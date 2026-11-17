/*
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

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
    private static final int TARGET_FRAME_KIND = 7;

    private final ServerRealmContext realm;

    /**
     * Binds SDK issuer resolution to one borrowed authoritative realm context.
     *
     * @param realm realm-owned authorization and signing services
     * @throws NullPointerException if realm is null
     */
    /* default */ HybridSdkIssuerResolver(ServerRealmContext realm) { this.realm=java.util.Objects.requireNonNull(realm); }

    /**
     * {@inheritDoc}
     */
    @Override public HybridSdkAdmissionService.Context resolve(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject) {
        return resolve(request,envelope,subject,Optional.empty());
    }

    /**
     * {@inheritDoc}
     */
    @Override public HybridSdkAdmissionService.Context revalidate(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
        return resolve(request,envelope,subject,Optional.of(frozenValidity(retainedTarget)));
    }

    private HybridSdkAdmissionService.Context resolve(ServerOperationGateway.Request request,
            PkiOperationValue.ObjectValue envelope, ParsedHybridSdkRequest subject, Optional<Validity> frozenValidity) {
        zeroecho.pki.server.http.HttpOperationCodec.Decoded decoded=zeroecho.pki.server.http.HttpOperationCodec.decode(request.operation().name(),
                zeroecho.pki.server.http.StrictJson.encode(envelope),262_144,request.realmId(),realm.gateway()::descriptor);
        if(!decoded.operation().equals(request.operation())){ throw new IllegalArgumentException("SDK_OPERATION_ENVELOPE_DIFFERS"); }
        ServerOperationGateway.Admission admission=realm.gateway().assessAdministrativeRequest(request);
        PkiSigningOperation operation=issue(admission.request());
        // Importing client metadata through a second operation is unnecessary: the exact SDK CSR is proof-bound here.
        requireRequestId(operation,subject);
        SdkIssuancePreview preview=realm.session().signingCommands().orElseThrow().previewSdk(operation,access(request),subject,
                frozenValidity,CancellationSignal.NONE);
        return new HybridSdkAdmissionService.Context(admission,target(admission,envelope,preview));
    }

    /**
     * Recomputes the exact SDK issuance preview while preserving the retained absolute validity.
     *
     * @param request trusted authenticated issuance request
     * @param subject parsed original hybrid certificate request
     * @param retainedTarget exact retained kind-seven semantic target
     * @return authoritative issuance preview with frozen validity
     * @throws UnsupportedOperationException if the issuance operation is unsupported
     * @throws IllegalArgumentException if request identity or retained target validity is invalid
     */
    /* default */ SdkIssuancePreview preview(ServerOperationGateway.Request request, ParsedHybridSdkRequest subject, HybridSdkFrame retainedTarget) {
        PkiSigningOperation operation=issue(request);
        requireRequestId(operation,subject);
        return realm.session().signingCommands().orElseThrow().previewSdk(operation,access(request),subject,
                Optional.of(frozenValidity(retainedTarget)),CancellationSignal.NONE);
    }

    /**
     * Extracts only the supported end-entity issuance-family signing operation.
     *
     * @param request authenticated administrative signing request
     * @return issue, renew, reissue or replace operation
     * @throws UnsupportedOperationException if the operation is outside the SDK issuance family
     */
    /* default */ static PkiSigningOperation issue(ServerOperationGateway.Request request) {
        if(request.operation() instanceof AdministrativeOperation.Signing signing
                && (signing.operation() instanceof PkiSigningOperation.IssueCredential
                    || signing.operation() instanceof PkiSigningOperation.RenewCredential
                    || signing.operation() instanceof PkiSigningOperation.ReissueCredential
                    || signing.operation() instanceof PkiSigningOperation.ReplaceCredential)) { return signing.operation(); }
        throw new UnsupportedOperationException("SDK_ISSUANCE_TARGET_UNSUPPORTED");
    }

    private static void requireRequestId(PkiSigningOperation operation, ParsedHybridSdkRequest subject) {
        Optional<zeroecho.pki.api.PkiId> id=operation instanceof PkiSigningOperation.IssueCredential issue?Optional.of(issue.requestId()):
                operation instanceof PkiSigningOperation.ReplaceCredential replace?Optional.of(replace.requestId()):Optional.<zeroecho.pki.api.PkiId>empty();
        if(id.isPresent()&&!id.orElseThrow().equals(subject.primary().requestId())){ throw new IllegalArgumentException("SDK_REQUEST_ID_DIFFERS"); }
    }

    /**
     * Projects the trusted administrative principal and operation into domain access coordinates.
     *
     * @param request authenticated administrative request
     * @return access context with the exact operation name as purpose
     */
    /* default */ static AccessContext access(ServerOperationGateway.Request request) {
        return new AccessContext(new Principal("ADMIN_PRINCIPAL",request.principalId()),new Purpose(request.operation().name()),Optional.empty(),Optional.empty());
    }

    private static HybridSdkFrame target(ServerOperationGateway.Admission admission,
            PkiOperationValue.ObjectValue envelope, SdkIssuancePreview preview) {
        Map<Integer,byte[]> fields=new TreeMap<>();
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

    /**
     * Recovers the exact absolute validity encoded into a retained semantic target.
     *
     * @param retainedTarget exact kind-seven SDK target frame
     * @return retained not-before and not-after instants without rebasing to the current clock
     * @throws IllegalArgumentException if frame kind, subject value or timestamp syntax is invalid
     */
    /* default */ static Validity frozenValidity(HybridSdkFrame retainedTarget) {
        if(retainedTarget.kind()!=TARGET_FRAME_KIND){ throw new IllegalArgumentException("SDK_TARGET_INVALID"); }
        Map<String,HybridSdkValue> fields=HybridSdkValue.decode(retainedTarget.field(15)).objectFields();
        return new Validity(Instant.parse(fields.get("notBefore").textValue()),Instant.parse(fields.get("notAfter").textValue()));
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
