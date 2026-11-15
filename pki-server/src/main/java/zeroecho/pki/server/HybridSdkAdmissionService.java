package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.api.hybrid.sdk.HybridSdkProofs;

/**
 * Private server-trusted dual-subject proof gate. No public carrier is installed here.
 * The default resolver rejects all production targets until C03.4 supplies the
 * authoritative issuer resolver. Consumed records and request references survive restart.
 */
final class HybridSdkAdmissionService {
    private static final int MAGIC = 0x48534931;
    private static final int MAX_BYTES = 524288;
    private static final int MAX_OPEN = 256;
    private final ServerControlStore control;
    private final Clock clock;
    private final String origin;
    private final Resolver resolver;
    private final AdministrativeRequestCoordinator coordinator;
    private final SecureRandom random = new SecureRandom();

    /** Trusted semantic/authorization seam; it is never populated from client JSON. */
    interface Resolver {
        /** Returns a fully authorized immutable admission and exact F7, or rejects unsupported targets. */
        Context resolve(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject);

        /**
         * Revalidates the exact target recovered from the private durable intent.
         * Implementations with time-sensitive policy must preserve its frozen absolute
         * validity; they must not rebase dates from the current clock. This argument
         * never originates in caller-supplied JSON or forwarded transport headers.
         */
        default Context revalidate(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope,
                ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
            return resolve(request,envelope,subject);
        }
    }

    /** Immutable, server-resolved semantic context; ordinary callers cannot submit this through HTTP. */
    record Context(ServerOperationGateway.Admission admission, HybridSdkFrame target) {
        Context { Objects.requireNonNull(admission); if (Objects.requireNonNull(target).kind() != 7) throw invalid(); }
    }

    /** Exact public challenge; contains no bearer capability or private material. */
    record Challenge(String intentId, HybridSdkFrame primary, HybridSdkFrame target) { }

    /** Private, defensively copied proof material recovered only from the consumed authoritative intent. */
    record Preparation(ParsedHybridSdkRequest subject, HybridSdkFrame primaryFrame, HybridSdkFrame target,
            byte[] primaryProof, byte[] alternativeProof, String proofCommitment, Instant acceptedAt) {
        Preparation { primaryProof=primaryProof.clone();alternativeProof=alternativeProof.clone(); }
        @Override public byte[] primaryProof() { return primaryProof.clone(); }
        @Override public byte[] alternativeProof() { return alternativeProof.clone(); }
    }

    /** Only this gate constructs a verified transaction input. */
    static final class Acceptance {
        private final Context context;
        private final AdministrativeRequest.SdkProof proof;
        private final ServerControlStore.ProtocolMutation consumption;
        private Acceptance(Context context, AdministrativeRequest.SdkProof proof, ServerControlStore.ProtocolMutation consumption) {
            this.context=context; this.proof=proof; this.consumption=consumption;
        }
        Context context() { return context; }
        AdministrativeRequest.SdkProof proof() { return proof; }
        ServerControlStore.ProtocolMutation consumption() { return consumption; }
    }

    HybridSdkAdmissionService(ServerControlStore control, Clock clock, AdministrativeRequestCoordinator coordinator,
            String origin, Resolver resolver) {
        this.control=Objects.requireNonNull(control); this.clock=Objects.requireNonNull(clock);
        this.coordinator=Objects.requireNonNull(coordinator); HybridSdkFrame.requireOrigin(origin);
        this.origin=origin; this.resolver=Objects.requireNonNull(resolver);
    }

    static Resolver unsupported() { return (request,envelope,subject) -> { throw new UnsupportedOperationException("SDK_ISSUER_CONTEXT_UNSUPPORTED"); }; }

    Challenge challenge(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope,
            byte[] originalDer, byte[] clientNonce) {
        if (clientNonce == null || clientNonce.length != 32) throw invalid();
        ParsedHybridSdkRequest parsed = parse(originalDer);
        Context context = resolve(request,envelope,parsed);
        HybridSdkFrame authentication = authentication(request);
        long issued=clock.instant().getEpochSecond();
        if (issued < 0 || issued > Long.MAX_VALUE-300) throw invalid();
        byte[] intent=randomBytes(), challenge=randomBytes(), nonce=randomBytes();
        Map<Integer,byte[]> fields=new TreeMap<>();
        fields.put(1,text("zeroecho-hybrid-sdk-v1"));fields.put(2,text(request.realmId().value()));
        fields.put(3,intent);fields.put(4,challenge);fields.put(5,nonce);fields.put(6,clientNonce.clone());
        fields.put(7,time(issued));fields.put(8,time(issued+300));fields.put(9,text(origin));fields.put(10,text("admin-http-v1"));
        fields.put(11,HybridSdkFrame.hash(originalDer));fields.put(12,HybridSdkFrame.hash(authentication.encode()));
        fields.put(13,HybridSdkFrame.hash(parsed.primary().publicKeyInfo().bytes()));
        fields.put(14,HybridSdkFrame.hash(parsed.alternativeSubjectPublicKeyInfo().bytes()));
        fields.put(15,HybridSdkFrame.primaryAlgorithm());fields.put(16,HybridSdkFrame.alternativeAlgorithm());
        fields.put(17,HybridSdkFrame.hash(context.target().encode()));
        HybridSdkFrame frame=new HybridSdkFrame(1,fields);
        Intent value=new Intent(frame,authentication,context.target(),originalDer.clone(),-1,Optional.empty(),Optional.empty(),new byte[0],new byte[0]);
        String id=hex(intent);
        synchronized(control) {
            if (control.openSdkIntentCount(Instant.ofEpochSecond(issued)) >= MAX_OPEN) throw new IllegalStateException("SDK_INTENT_CAPACITY");
            control.mutateProtocol(java.util.List.of(new ServerControlStore.ProtocolMutation(encode(id,value),Optional.empty())));
        }
        return new Challenge(id,frame,context.target());
    }

    /** Compares the repeated original request before existing acceptance or replay. */
    AdministrativeRequest accept(String intentId, String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration timeout, byte[] originalDer,
            byte[] primaryProof, byte[] alternativeProof) {
        synchronized (control) {
            var retained = control.protocolRecord(ServerControlStore.HYBRID_SDK_INTENT, intentId)
                    .orElseThrow(HybridSdkAdmissionService::invalid);
            if (!MessageDigest.isEqual(decode(retained).originalDer(), originalDer)) {
                throw new AdministrativeRequestCoordinator.Conflict();
            }
            return accept(intentId, requestId, request, envelope, timeout, primaryProof, alternativeProof);
        }
    }

    AdministrativeRequest accept(String intentId, String requestId, ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, Duration timeout, byte[] primaryProof, byte[] alternativeProof) {
        Permission.requireId(requestId,"administrative request");
        synchronized(control) {
            var previous=control.protocolRecord(ServerControlStore.HYBRID_SDK_INTENT,intentId).orElseThrow(HybridSdkAdmissionService::invalid);
            Intent intent=decode(previous);
            authentication(request);
            coordinator.requireSdkActor(request);
            if(!Arrays.equals(intent.frame().field(2),text(request.realmId().value())))throw invalid();
            if (intent.requestId().isPresent()) {
                if (!intent.requestId().orElseThrow().equals(requestId)
                        || !MessageDigest.isEqual(intent.primaryProof(),primaryProof)
                        || !MessageDigest.isEqual(intent.alternativeProof(),alternativeProof)) throw new AdministrativeRequestCoordinator.Conflict();
                var retained=coordinator.inspect(requestId,request.principalId());
                if(retained.executionTimeoutMillis()!=timeout.toMillis() || !retained.envelope().equals(envelope)) throw new AdministrativeRequestCoordinator.Conflict();
                validateIntegrity(retained);
                if (!Arrays.equals(intent.target().field(1), text(request.operation().name()))
                        || !retained.scope().realmId().equals(request.realmId())
                        || !retained.actor().principalId().equals(request.principalId())) throw new AdministrativeRequestCoordinator.Conflict();
                return retained;
            }
            ParsedHybridSdkRequest parsed=parse(intent.originalDer());
            Context context=resolve(request,envelope,parsed,Optional.of(intent.target()));
            requireContext(intent,authentication(request),context.target());
            Instant accepted=clock.instant();
            String commitment=HybridSdkProofs.verify(parsed,intent.frame(),primaryProof,alternativeProof,accepted);
            var proof=new AdministrativeRequest.SdkProof(intentId,commitment);
            var consumed=new Intent(intent.frame(),intent.authentication(),intent.target(),intent.originalDer(),accepted.getEpochSecond(),
                    Optional.of(requestId),Optional.of(commitment),primaryProof.clone(),alternativeProof.clone());
            var mutation=new ServerControlStore.ProtocolMutation(encode(intentId,consumed),Optional.of(previous.commitment()));
            return coordinator.submitSdk(requestId,request,envelope,timeout,new Acceptance(context,proof,mutation));
        }
    }

    Preparation preparation(AdministrativeRequest request, ServerOperationGateway.Request authenticated,
            PkiOperationValue.ObjectValue envelope) {
        validateRetained(request,authenticated,envelope);
        Intent intent=retainedIntent(request);
        return new Preparation(parse(intent.originalDer()),intent.frame(),intent.target(),intent.primaryProof(),
                intent.alternativeProof(),intent.proofCommitment().orElseThrow(),Instant.ofEpochSecond(intent.acceptedAt()));
    }

    /** Immutable receipt observation never depends on today's admission policy or credential mapping. */
    void validateIntegrity(AdministrativeRequest request) { retainedIntent(request); }

    void validateRetained(AdministrativeRequest request, ServerOperationGateway.Request authenticated,
            PkiOperationValue.ObjectValue envelope) {
        Intent intent=retainedIntent(request);
        Context current=resolve(authenticated,envelope,parse(intent.originalDer()),Optional.of(intent.target()));
        if(!request.operationCommitment().equals(current.admission().commitment())
                || !request.scope().equals(current.admission().request().resource().scope())
                || !request.policyCommitment().equals(current.admission().policy().map(ApprovalService.Policy::commitment))) throw new SecurityException("SDK_CONTEXT_CHANGED");
        requireContext(intent,authentication(authenticated),current.target());
    }

    private Intent retainedIntent(AdministrativeRequest request) {
        var proof=request.sdkProof().orElseThrow(HybridSdkAdmissionService::invalid);
        Intent intent=decode(control.protocolRecord(ServerControlStore.HYBRID_SDK_INTENT,proof.intentId()).orElseThrow(HybridSdkAdmissionService::invalid));
        if (!intent.requestId().equals(Optional.of(request.requestId())) || !intent.proofCommitment().equals(Optional.of(proof.proofCommitment()))
                || !Arrays.equals(intent.frame().field(2),text(request.scope().realmId().value()))
                || !Arrays.equals(intent.target().field(1),text(request.operation()))
                || !Arrays.equals(intent.target().field(3),text(request.actor().principalId()))
                || !Arrays.equals(intent.target().field(2),value(request.envelope().fields().get("arguments")).encode())
                || !Arrays.equals(intent.authentication().encode(),authentication(request.actor(),request.scope().realmId()).encode())) throw invalid();
        String verified=HybridSdkProofs.verify(parse(intent.originalDer()),intent.frame(),intent.primaryProof(),intent.alternativeProof(),Instant.ofEpochSecond(intent.acceptedAt()));
        if (!verified.equals(proof.proofCommitment())) throw invalid();
        return intent;
    }

    private Context resolve(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject) {
        return resolve(request,envelope,subject,Optional.empty());
    }
    private Context resolve(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope,
            ParsedHybridSdkRequest subject, Optional<HybridSdkFrame> retainedTarget) {
        authentication(request); // Missing validated certificate context cannot reach a fixture or production resolver.
        coordinator.requireSdkActor(request);
        if (!(request.operation() instanceof AdministrativeOperation.Signing)
                || request.operation().name().equals("ca.create")) throw new UnsupportedOperationException("SDK_ISSUANCE_TARGET_UNSUPPORTED");
        Context context=Objects.requireNonNull(retainedTarget.isPresent()
                ?resolver.revalidate(request,envelope,subject,retainedTarget.orElseThrow())
                :resolver.resolve(request,envelope,subject));
        var admission=context.admission(); var target=context.target();
        boolean admitted=admission.decision().allowed() || admission.decision().code()==AuthorizationEngine.Code.APPROVAL_REQUIRED
                && admission.policy().isPresent();
        if (!admitted || !admission.request().principalId().equals(request.principalId())
                || !admission.request().realmId().equals(request.realmId())
                || !admission.request().operation().equals(request.operation())
                || !Arrays.equals(authentication(admission.request()).encode(),authentication(request).encode())
                || !Arrays.equals(target.field(1),text(request.operation().name()))
                || !Arrays.equals(target.field(3),text(request.principalId()))
                || !admission.request().resource().scope().authorityId().map(id->Arrays.equals(target.field(4),text(id.value()))).orElse(false)
                || admission.request().resource().scope().issuerId().filter(id->!Arrays.equals(target.field(5),text(id.value()))).isPresent()
                || admission.request().resource().scope().profileId().filter(id->!Arrays.equals(target.field(10),text(id))).isPresent()
                || !Arrays.equals(target.field(2),value(envelope.fields().get("arguments")).encode())
                || !Arrays.equals(target.field(14),text("sha256:"+admission.policy().map(ApprovalService.Policy::commitment).orElseGet(()->ApprovalService.digest(""))))) throw invalid();
        return context;
    }

    private static void requireContext(Intent intent, HybridSdkFrame authentication, HybridSdkFrame target) {
        if (!MessageDigest.isEqual(intent.authentication().encode(),authentication.encode())
                || !MessageDigest.isEqual(intent.target().encode(),target.encode())) throw new SecurityException("SDK_CONTEXT_CHANGED");
    }

    static HybridSdkFrame authentication(ServerOperationGateway.Request request) {
        return authentication(new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence()),request.realmId());
    }
    private static HybridSdkFrame authentication(AdministrativeRequest.Actor actor,RealmId realm) {
        CertificateIdentityEvidence evidence=actor.evidence().orElseThrow(()->new SecurityException("SDK_AUTHENTICATION_EVIDENCE_REQUIRED"));
        if (!evidence.realmId().equals(realm)) throw invalid();
        Map<String,HybridSdkValue> values=Map.of("canonicalKeySha256",HybridSdkValue.text(evidence.canonicalKeySha256()),
                "issuerSerialSha256",HybridSdkValue.text(evidence.issuerSerialSha256()),
                "transportPrincipalId",HybridSdkValue.text(actor.transportPrincipalId().orElse("")));
        return new HybridSdkFrame(6,Map.of(1,text(actor.principalId()),2,text(actor.mode()==AdministrativeAuthenticationMode.DIRECT_MTLS?"direct-mtls-v1":"trusted-proxy-mtls-v1"),
                3,HybridSdkFrame.hash(text("sha256:"+evidence.certificateSha256())),4,text("admin-http-v1"),5,HybridSdkValue.object(values).encode()));
    }

    static HybridSdkValue value(PkiOperationValue value) {
        return switch(Objects.requireNonNull(value)) {
            case PkiOperationValue.Text v -> HybridSdkValue.text(v.value());
            case PkiOperationValue.IntegerValue v -> HybridSdkValue.integer(v.value());
            case PkiOperationValue.BooleanValue v -> HybridSdkValue.bool(v.value());
            case PkiOperationValue.ListValue v -> HybridSdkValue.list(v.values().stream().map(HybridSdkAdmissionService::value).toList());
            case PkiOperationValue.ObjectValue v -> { var fields=new TreeMap<String,HybridSdkValue>();v.fields().forEach((k,item)->fields.put(k,value(item)));yield HybridSdkValue.object(fields); }
        };
    }

    static void requireConsumption(ServerControlStore.ProtocolRecord previous, ServerControlStore.ProtocolRecord next, AdministrativeRequest request) {
        Intent before=decode(previous),after=decode(next);
        if (before.requestId().isPresent() || after.requestId().isEmpty() || !after.requestId().orElseThrow().equals(request.requestId())
                || !after.proofCommitment().equals(request.sdkProof().map(AdministrativeRequest.SdkProof::proofCommitment))
                || !Arrays.equals(before.frame().encode(),after.frame().encode()) || !Arrays.equals(before.target().encode(),after.target().encode())
                || !Arrays.equals(before.authentication().encode(),after.authentication().encode()) || !Arrays.equals(before.originalDer(),after.originalDer())) throw invalid();
    }

    private ParsedHybridSdkRequest parse(byte[] der) {
        return HybridSdkProofs.parse(der);
    }
    private byte[] randomBytes() { byte[] value=new byte[32];random.nextBytes(value);return value; }
    private static byte[] time(long seconds) { return ByteBuffer.allocate(8).putLong(seconds).array(); }
    private static long epoch(HybridSdkFrame frame,int field) { return ByteBuffer.wrap(frame.field(field)).getLong(); }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String hex(byte[] value) { return HexFormat.of().formatHex(value); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK_INTENT_INVALID"); }

    private record Intent(HybridSdkFrame frame, HybridSdkFrame authentication, HybridSdkFrame target, byte[] originalDer,
            long acceptedAt, Optional<String> requestId, Optional<String> proofCommitment, byte[] primaryProof, byte[] alternativeProof) { }

    private static ServerControlStore.ProtocolRecord encode(String id,Intent intent) {
        try {
            var bytes=new ByteArrayOutputStream();var out=new DataOutputStream(bytes);
            out.writeInt(MAGIC);out.writeInt(1);write(out,intent.frame().encode());write(out,intent.authentication().encode());
            write(out,intent.target().encode());write(out,intent.originalDer());out.writeLong(intent.acceptedAt());
            out.writeBoolean(intent.requestId().isPresent());
            if(intent.requestId().isPresent()) {out.writeUTF(intent.requestId().orElseThrow());out.writeUTF(intent.proofCommitment().orElseThrow());write(out,intent.primaryProof());write(out,intent.alternativeProof());}
            byte[] payload=bytes.toByteArray();if(payload.length>MAX_BYTES)throw new IllegalArgumentException("SDK_TOO_LARGE");
            return new ServerControlStore.ProtocolRecord(ServerControlStore.HYBRID_SDK_INTENT,id,ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(payload)),payload);
        } catch(IOException impossible) {throw new IllegalStateException(impossible);}
    }
    static boolean openAt(ServerControlStore.ProtocolRecord record, Instant now) {
        byte[] payload = record.payload();
        if (payload.length < 8) throw invalid();
        int magic = java.nio.ByteBuffer.wrap(payload).getInt();
        if (magic == zeroecho.pki.server.enrollment.EnrollmentSdkIntentCodec.MAGIC) {
            var intent = zeroecho.pki.server.enrollment.EnrollmentSdkIntentCodec.decode(record);
            return intent.state() == zeroecho.pki.server.enrollment.EnrollmentSdkIntent.State.OPEN && now.isBefore(intent.expiresAt());
        }
        if (magic != MAGIC) throw invalid();
        var intent = decode(record);
        return intent.requestId().isEmpty() && now.getEpochSecond() < epoch(intent.frame(), 8);
    }

    private static Intent decode(ServerControlStore.ProtocolRecord record) {
        byte[] payload=record.payload();
        if(!record.namespace().equals(ServerControlStore.HYBRID_SDK_INTENT)||!record.commitment().equals(ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(payload))))throw invalid();
        try(var in=new DataInputStream(new ByteArrayInputStream(payload))) {
            if(in.readInt()!=MAGIC||in.readInt()!=1)throw invalid();
            HybridSdkFrame frame=HybridSdkFrame.decode(read(in)),auth=HybridSdkFrame.decode(read(in)),target=HybridSdkFrame.decode(read(in));byte[] der=read(in);
            if(frame.kind()!=1||auth.kind()!=6||target.kind()!=7||!record.recordId().equals(hex(frame.field(3)))
                    ||!Arrays.equals(frame.field(11),HybridSdkFrame.hash(der))||!Arrays.equals(frame.field(12),HybridSdkFrame.hash(auth.encode()))
                    ||!Arrays.equals(frame.field(17),HybridSdkFrame.hash(target.encode())))throw invalid();
            long accepted=in.readLong();Optional<String> request=Optional.empty(),proof=Optional.empty();byte[] primary=new byte[0],alternative=new byte[0];
            if(in.readBoolean()) {request=Optional.of(in.readUTF());Permission.requireId(request.orElseThrow(),"administrative request");proof=Optional.of(in.readUTF());new AdministrativeRequest.SdkProof(record.recordId(),proof.orElseThrow());primary=read(in);alternative=read(in);
                if(accepted<epoch(frame,7)||accepted>=epoch(frame,8))throw invalid();
            } else if(accepted!=-1)throw invalid();
            if(in.available()!=0)throw invalid();return new Intent(frame,auth,target,der,accepted,request,proof,primary,alternative);
        } catch(IOException malformed) {throw invalid();}
    }
    private static void write(DataOutputStream out,byte[] value)throws IOException {if(value.length>MAX_BYTES)throw new IllegalArgumentException("SDK_TOO_LARGE");out.writeInt(value.length);out.write(value);}
    private static byte[] read(DataInputStream in)throws IOException {int size=in.readInt();if(size<0||size>MAX_BYTES||size>in.available())throw invalid();return in.readNBytes(size);}
}
