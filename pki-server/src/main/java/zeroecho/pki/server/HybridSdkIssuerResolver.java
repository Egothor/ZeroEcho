package zeroecho.pki.server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Domain-backed SDK context resolver. It performs no signing, staging or request
 * mutation. The domain owns policy/key/issuer verification and the exact frozen
 * validity; this layer adds current gateway authorization and its approval policy.
 * Explicit internal composition supplies the canonical origin; no transport
 * header or listener binding is used to infer an externally published address.
 */
final class HybridSdkIssuerResolver implements HybridSdkAdmissionService.Resolver {
    private final ServerRealmContext realm;

    HybridSdkIssuerResolver(ServerRealmContext realm) { this.realm=java.util.Objects.requireNonNull(realm); }

    @Override public HybridSdkAdmissionService.Context resolve(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject) {
        return resolve(request,envelope,subject,Optional.empty());
    }

    @Override public HybridSdkAdmissionService.Context revalidate(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
        return resolve(request,envelope,subject,Optional.of(frozenValidity(retainedTarget)));
    }

    private HybridSdkAdmissionService.Context resolve(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject, Optional<Validity> frozenValidity) {
        var decoded=zeroecho.pki.server.http.HttpOperationCodec.decode(request.operation().name(),
                zeroecho.pki.server.http.StrictJson.encode(envelope),262144,request.realmId(),realm.gateway()::descriptor);
        if(!decoded.operation().equals(request.operation()))throw new IllegalArgumentException("SDK_OPERATION_ENVELOPE_DIFFERS");
        var admission=realm.gateway().assessAdministrativeRequest(request);
        var operation=issue(admission.request());
        // Importing client metadata through a second operation is unnecessary: the exact SDK CSR is proof-bound here.
        requireRequestId(operation,subject);
        var preview=realm.session().signingCommands().orElseThrow().previewSdk(operation,access(request),subject,
                frozenValidity,CancellationSignal.NONE);
        return new HybridSdkAdmissionService.Context(admission,target(admission,envelope,preview));
    }

    SdkIssuancePreview preview(ServerOperationGateway.Request request, ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
        var operation=issue(request);
        requireRequestId(operation,subject);
        return realm.session().signingCommands().orElseThrow().previewSdk(operation,access(request),subject,
                Optional.of(frozenValidity(retainedTarget)),CancellationSignal.NONE);
    }

    static PkiSigningOperation issue(ServerOperationGateway.Request request) {
        if(request.operation() instanceof AdministrativeOperation.Signing signing
                && (signing.operation() instanceof PkiSigningOperation.IssueCredential
                    || signing.operation() instanceof PkiSigningOperation.RenewCredential
                    || signing.operation() instanceof PkiSigningOperation.ReissueCredential
                    || signing.operation() instanceof PkiSigningOperation.ReplaceCredential)) return signing.operation();
        throw new UnsupportedOperationException("SDK_ISSUANCE_TARGET_UNSUPPORTED");
    }

    private static void requireRequestId(PkiSigningOperation operation, ParsedHybridSdkRequest subject) {
        var id=operation instanceof PkiSigningOperation.IssueCredential issue?Optional.of(issue.requestId()):
                operation instanceof PkiSigningOperation.ReplaceCredential replace?Optional.of(replace.requestId()):Optional.<zeroecho.pki.api.PkiId>empty();
        if(id.isPresent()&&!id.orElseThrow().equals(subject.primary().requestId()))throw new IllegalArgumentException("SDK_REQUEST_ID_DIFFERS");
    }

    static AccessContext access(ServerOperationGateway.Request request) {
        return new AccessContext(new Principal("ADMIN_PRINCIPAL",request.principalId()),new Purpose(request.operation().name()),Optional.empty(),Optional.empty());
    }

    private static HybridSdkFrame target(ServerOperationGateway.Admission admission,
            PkiOperationValue.ObjectValue envelope, SdkIssuancePreview preview) {
        var fields=new TreeMap<Integer,byte[]>();
        fields.put(1,text(admission.request().operation().name()));
        fields.put(2,HybridSdkAdmissionService.value(envelope.fields().get("arguments")).encode());
        fields.put(3,text(admission.request().principalId()));fields.put(4,text(preview.issuerCaId().value()));
        fields.put(5,text(preview.issuerId().value()));fields.put(6,text(preview.chainPathId().value()));
        fields.put(7,text("sha512:"+preview.issuerCertificateSha512()));
        fields.put(8,preview.primaryIssuerBindingFrame().encode());
        fields.put(9,preview.alternativeIssuerBindingFrame().map(HybridSdkFrame::encode).orElseGet(()->new byte[0]));
        fields.put(10,text(preview.profile().profileId()));
        fields.put(11,ByteBuffer.allocate(Long.BYTES).putLong(preview.profile().profileVersion()).array());
        fields.put(12,text("sha256:"+HexFormat.of().formatHex(preview.profile().canonicalSha256())));
        fields.put(13,text(preview.bindingSetCommitment()));
        fields.put(14,text("sha256:"+admission.policy().map(ApprovalService.Policy::commitment).orElseGet(()->ApprovalService.digest(""))));
        fields.put(15,preview.effectiveSubjectValue().encode());fields.put(16,preview.disclosurePolicy().encode());
        fields.put(17,preview.targetExtensionValue().encode());
        return new HybridSdkFrame(7,fields);
    }

    static Validity frozenValidity(HybridSdkFrame retainedTarget) {
        if(retainedTarget.kind()!=7)throw new IllegalArgumentException("SDK_TARGET_INVALID");
        var fields=HybridSdkValue.decode(retainedTarget.field(15)).objectFields();
        return new Validity(Instant.parse(fields.get("notBefore").textValue()),Instant.parse(fields.get("notAfter").textValue()));
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
