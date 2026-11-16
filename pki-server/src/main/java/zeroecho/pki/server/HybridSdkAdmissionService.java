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

    /**
     * Trusted semantic/authorization seam; it is never populated from client JSON.
     */
    interface Resolver {
        /**
         * Resolves authorized server-owned admission and its exact SDK target frame.
         *
         * @param request trusted authenticated administrative request
         * @param envelope strict decoded original administrative envelope
         * @param subject parsed original hybrid certificate request
         * @return fully authorized immutable admission and exact kind-seven target frame
         * @throws UnsupportedOperationException if the operation or issuer target is unsupported
         * @throws SecurityException if current authorization rejects the target
         */
        Context resolve(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject);

        /**
         * Revalidates the exact target recovered from a private durable intent.
         *
         * <p>Time-sensitive policies must preserve frozen absolute validity rather than
         * rebasing dates from the current clock. The retained target never originates in
         * caller-supplied JSON or forwarded headers.</p>
         *
         * @param request trusted authenticated administrative request
         * @param envelope strict decoded original administrative envelope
         * @param subject parsed original hybrid certificate request
         * @param retainedTarget exact target retained when the challenge was issued
         * @return revalidated authorized admission and unchanged semantic target
         * @throws UnsupportedOperationException if the operation or issuer target is unsupported
         * @throws SecurityException if current authorization rejects the target
         */
        default Context revalidate(ServerOperationGateway.Request request, PkiOperationValue.ObjectValue envelope,
                ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
            return resolve(request,envelope,subject);
        }
    }

    /**
     * Immutable server-resolved admission and target; not accepted from HTTP input.
     *
     * @param admission fully resolved authorization and approval context
     * @param target exact kind-seven semantic target frame
     */
    record Context(ServerOperationGateway.Admission admission, HybridSdkFrame target) {
        /**
         * Requires authorized context and the semantic target frame kind.
         *
         * @param admission server-resolved admission; must not be null
         * @param target kind-seven target frame; must not be null
         * @throws NullPointerException if either component is null
         * @throws IllegalArgumentException if the target frame has another kind
         */
        Context { Objects.requireNonNull(admission); if (Objects.requireNonNull(target).kind() != 7) throw invalid(); }
    }

    /**
     * Public challenge coordinates without bearer authority or private key material.
     *
     * @param intentId opaque retained challenge-intent identity
     * @param primary exact primary challenge frame
     * @param target exact server-resolved semantic target frame
     */
    record Challenge(String intentId, HybridSdkFrame primary, HybridSdkFrame target) { }

    /**
     * Proof material recovered only from a consumed authoritative SDK intent.
     *
     * @param subject parsed original hybrid certificate request
     * @param primaryFrame exact issued primary challenge frame
     * @param target exact retained semantic target
     * @param primaryProof accepted primary signature bytes; defensively copied
     * @param alternativeProof accepted alternative signature bytes; defensively copied
     * @param proofCommitment verified combined proof commitment
     * @param acceptedAt authoritative proof acceptance instant
     */
    record Preparation(ParsedHybridSdkRequest subject, HybridSdkFrame primaryFrame, HybridSdkFrame target,
            byte[] primaryProof, byte[] alternativeProof, String proofCommitment, Instant acceptedAt) {
        /**
         * Snapshots both accepted proof signatures for independent caller ownership.
         *
         * @param subject parsed original hybrid certificate request
         * @param primaryFrame exact issued primary challenge frame
         * @param target exact retained semantic target
         * @param primaryProof accepted primary signature bytes; copied
         * @param alternativeProof accepted alternative signature bytes; copied
         * @param proofCommitment verified combined proof commitment
         * @param acceptedAt authoritative proof acceptance instant
         * @throws NullPointerException if either proof byte array is null
         */
        Preparation { primaryProof=primaryProof.clone();alternativeProof=alternativeProof.clone(); }
        /**
         * Copies the accepted primary proof signature.
         *
         * @return caller-owned primary proof bytes
         */
        @Override public byte[] primaryProof() { return primaryProof.clone(); }
        /**
         * Copies the accepted alternative proof signature.
         *
         * @return caller-owned alternative proof bytes
         */
        @Override public byte[] alternativeProof() { return alternativeProof.clone(); }
    }

    /**
     * Only this gate constructs a verified transaction input.
     */
    static final class Acceptance {
        private final Context context;
        private final AdministrativeRequest.SdkProof proof;
        private final ServerControlStore.ProtocolMutation consumption;
        private Acceptance(Context context, AdministrativeRequest.SdkProof proof, ServerControlStore.ProtocolMutation consumption) {
            this.context=context; this.proof=proof; this.consumption=consumption;
        }
        /**
         * Returns the server-resolved admission context validated by this gate.
         *
         * @return exact authorized context associated with the verified proof
         */
        Context context() { return context; }
        /**
         * Returns the accepted SDK proof reference.
         *
         * @return retained intent identity and verified proof commitment
         */
        AdministrativeRequest.SdkProof proof() { return proof; }
        /**
         * Returns the compare-and-set mutation consuming the retained SDK intent.
         *
         * @return mutation that must be committed atomically with administrative admission
         */
        ServerControlStore.ProtocolMutation consumption() { return consumption; }
    }

    /**
     * Composes the durable SDK proof-admission gate for one canonical server origin.
     *
     * @param control realm-owned durable server-control store
     * @param clock authoritative challenge issue/acceptance time source
     * @param coordinator administrative request lifecycle coordinator
     * @param origin canonical public server origin
     * @param resolver trusted server-owned issuer and authorization resolver
     * @throws NullPointerException if a required collaborator is null
     * @throws IllegalArgumentException if origin is noncanonical
     */
    HybridSdkAdmissionService(ServerControlStore control, Clock clock, AdministrativeRequestCoordinator coordinator,
            String origin, Resolver resolver) {
        this.control=Objects.requireNonNull(control); this.clock=Objects.requireNonNull(clock);
        this.coordinator=Objects.requireNonNull(coordinator); HybridSdkFrame.requireOrigin(origin);
        this.origin=origin; this.resolver=Objects.requireNonNull(resolver);
    }

    /**
     * Creates a resolver that fails closed for every SDK issuer context.
     *
     * @return resolver that always throws {@link UnsupportedOperationException}
     */
    static Resolver unsupported() { return (request,envelope,subject) -> { throw new UnsupportedOperationException("SDK_ISSUER_CONTEXT_UNSUPPORTED"); }; }

    /**
     * Persists a fresh five-minute challenge bound to the authenticated actor and exact semantic target.
     *
     * @param request trusted authenticated administrative request
     * @param envelope strict original administrative envelope
     * @param originalDer original hybrid certificate request DER; copied into retained intent
     * @param clientNonce exactly 32 client nonce bytes; copied into the challenge
     * @return public challenge and durable intent identity
     * @throws IllegalArgumentException if the nonce, clock range, request or target binding is invalid
     * @throws IllegalStateException if the bounded open-intent capacity is exhausted
     * @throws SecurityException if actor authentication or authorization fails
     * @throws UnsupportedOperationException if the requested issuance target is unsupported
     */
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

    /**
     * Checks the repeated original DER before accepting or replaying dual-key proof admission.
     *
     * @param originalDer original hybrid certificate request DER, which must match the retained intent
     * @param intentId retained SDK challenge identity
     * @param requestId canonical administrative request identity
     * @param request trusted authenticated administrative request
     * @param envelope exact original administrative envelope
     * @param timeout bounded execution timeout
     * @param primaryProof primary challenge proof signature
     * @param alternativeProof alternative challenge proof signature
     * @return existing identical admission or newly retained administrative request
     * @throws AdministrativeRequestCoordinator.Conflict if a repeated admission changes its identity or inputs
     * @throws IllegalArgumentException if retained intent or proof binding is invalid
     * @throws SecurityException if actor, policy or target context changed
     */
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

    /**
     * Verifies dual-key proofs and atomically consumes the challenge with administrative admission.
     *
     * <p>An exact replay observes the existing request without submitting another operation.</p>
     *
     * @param intentId retained SDK challenge identity
     * @param requestId canonical administrative request identity
     * @param request trusted authenticated administrative request
     * @param envelope exact original administrative envelope
     * @param timeout bounded execution timeout
     * @param primaryProof primary challenge proof signature
     * @param alternativeProof alternative challenge proof signature
     * @return existing identical admission or newly retained administrative request
     * @throws AdministrativeRequestCoordinator.Conflict if a repeated admission changes its identity or inputs
     * @throws IllegalArgumentException if retained intent or proof binding is invalid
     * @throws SecurityException if actor, policy or target context changed
     */
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

    /**
     * Recovers verified proof material after revalidating the retained target and current authorization.
     *
     * @param request retained administrative SDK request
     * @param authenticated trusted current actor/request context
     * @param envelope exact administrative envelope
     * @return caller-owned proof preparation with copied signature arrays
     * @throws IllegalArgumentException if retained proof integrity is invalid
     * @throws SecurityException if actor, policy or target context changed
     */
    Preparation preparation(AdministrativeRequest request, ServerOperationGateway.Request authenticated,
            PkiOperationValue.ObjectValue envelope) {
        validateRetained(request,authenticated,envelope);
        Intent intent=retainedIntent(request);
        return new Preparation(parse(intent.originalDer()),intent.frame(),intent.target(),intent.primaryProof(),
                intent.alternativeProof(),intent.proofCommitment().orElseThrow(),Instant.ofEpochSecond(intent.acceptedAt()));
    }

    /**
     * Checks immutable retained proof integrity independently of current admission policy.
     *
     * @param request retained administrative SDK request and proof reference
     * @throws IllegalArgumentException if intent, actor, request coordinates or proof commitments are
     *         inconsistent
     */
    void validateIntegrity(AdministrativeRequest request) { retainedIntent(request); }

    /**
     * Checks retained proof integrity and revalidates its exact authorization and frozen target.
     *
     * @param request retained administrative SDK request
     * @param authenticated trusted current actor/request context
     * @param envelope exact administrative envelope
     * @throws IllegalArgumentException if retained proof integrity is invalid
     * @throws SecurityException if actor, authorization policy or semantic target changed
     */
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

    /**
     * Projects validated certificate-authentication evidence into its canonical SDK binding frame.
     *
     * @param request trusted authenticated request with realm-bound certificate evidence
     * @return kind-six authentication frame
     * @throws SecurityException if certificate-authentication evidence is absent
     * @throws IllegalArgumentException if evidence belongs to another realm
     */
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

    /**
     * Converts the closed administrative value model into canonical SDK values.
     *
     * @param value structured operation value; must not be null
     * @return equivalent SDK value with object keys in canonical order
     * @throws NullPointerException if value is null
     */
    static HybridSdkValue value(PkiOperationValue value) {
        return switch(Objects.requireNonNull(value)) {
            case PkiOperationValue.Text v -> HybridSdkValue.text(v.value());
            case PkiOperationValue.IntegerValue v -> HybridSdkValue.integer(v.value());
            case PkiOperationValue.BooleanValue v -> HybridSdkValue.bool(v.value());
            case PkiOperationValue.ListValue v -> HybridSdkValue.list(v.values().stream().map(HybridSdkAdmissionService::value).toList());
            case PkiOperationValue.ObjectValue v -> { var fields=new TreeMap<String,HybridSdkValue>();v.fields().forEach((k,item)->fields.put(k,value(item)));yield HybridSdkValue.object(fields); }
        };
    }

    /**
     * Checks that one unconsumed SDK intent is consumed by the exact administrative request.
     *
     * @param previous retained open intent record
     * @param next proposed consumed intent record
     * @param request administrative request committed in the same mutation
     * @throws IllegalArgumentException if identity, proof commitment or immutable challenge coordinates differ
     */
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
    /**
     * Checks whether a recognized SDK intent remains unconsumed and unexpired.
     *
     * @param record retained administrative or enrollment SDK intent record
     * @param now observation time
     * @return whether the intent is open strictly before its absolute expiry
     * @throws IllegalArgumentException if the record magic, encoding or commitment is invalid
     */
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
