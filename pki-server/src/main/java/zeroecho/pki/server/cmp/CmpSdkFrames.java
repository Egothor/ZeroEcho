/* *****************************************************************************
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
package zeroecho.pki.server.cmp;

import java.util.Optional;

import java.util.HashMap;
import java.util.HexFormat;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.enrollment.CmpTransaction;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pkix.cmp.CmpProtectedMessage;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;

/**
 * Encodes frozen CMP SDK authentication and target frames without performing authorization.
 */
final class CmpSdkFrames {
    private static final int CMP_REPLACEMENT_BODY = 7;
    private CmpSdkFrames() { }
    /**
     * Encodes the exact native authentication transcript.
     */
    /* default */ static zeroecho.pki.api.hybrid.sdk.HybridSdkFrame authentication(CmpEndpoint endpoint, CmpProtectedMessage request,
            byte[] wire, CmpTransaction.Frozen frozen) {
        EnrollmentTransaction.Requester requester = frozen.requester();
        String credentialId = requester.type() == IssuanceExecutionEvidence.ActorType.CMP_PBM ? requester.actorId() : requester.certificate().orElseThrow().certificateSha256();
        zeroecho.pki.api.hybrid.sdk.HybridSdkValue anchor = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.of(
                "credentialId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(credentialId),
                "credentialRevision", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.integer(0),
                "endpointCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(frozen.source().commitment())));
        java.util.Map<String,zeroecho.pki.api.hybrid.sdk.HybridSdkValue> fields = new HashMap<>();
        fields.put("endpointId", sdkValue(endpoint.label())); fields.put("endpointCommitment", sdkValue(frozen.source().commitment()));
        fields.put("authenticationPolicyCommitment", sdkValue(frozen.source().commitment()));
        fields.put("manifestCommitment", sdkValue("sha256:" + CmpTransaction.unreserved(frozen).commitment()));
        fields.put("transactionIdSha256", sdkValue(frozen.transactionSha256())); fields.put("certReqId", sdkValue(request.requestId().toString()));
        fields.put("bodyType", sdkValue(Integer.toString(request.bodyType()))); fields.put("originalWireSha512", sdkValue("sha512:" + HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(wire))));
        fields.put("senderNonceSha256", sdkValue(CmpService.hash(request.senderNonce()))); fields.put("recipientNonceSha256", sdkValue(request.recipientNonce().map(CmpService::hash).orElse("")));
        fields.put("authenticationCredentialId", sdkValue(credentialId)); fields.put("authenticationCredentialRevision", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.integer(0)); fields.put("requestKind", sdkValue("CRMF"));
        byte[] authAnchor = requester.type() == IssuanceExecutionEvidence.ActorType.CMP_PBM ? anchor.encode() : ("sha256:" + credentialId).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        zeroecho.pki.api.hybrid.sdk.HybridSdkFrame auth = new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(6, java.util.Map.of(1,sdkBytes(requester.actorId()),2,sdkBytes(request.isPbm()?"cmp-pbm-v1":"cmp-signature-v1"),
                3,zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(authAnchor),4,sdkBytes("cmp-v1"),5,zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(fields).encode()));
        return auth;
    }
    /**
     * Encodes the exact policy target after caller-owned authentication.
     */
    /* default */ static zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget target(CmpEndpoint endpoint, CmpProtectedMessage request,
            zeroecho.pki.api.hybrid.sdk.HybridSdkFrame auth, CmpTransaction.Frozen frozen,
            EnrollmentEndpointRegistry.Snapshot snapshot, EnrollmentProfileService profiles) {
        zeroecho.pki.server.enrollment.EnrollmentProfile policy = profiles.find(endpoint.enrollmentProfileId()).orElseThrow();
        zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget target = new zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget(1,"CMP",endpoint.label(),snapshot.revision(),snapshot.commitment(),endpoint.enrollmentProfileId(),
                profiles.revision(endpoint.enrollmentProfileId()),EnrollmentProfileService.commitment(policy),request.bodyType()==CMP_REPLACEMENT_BODY?"REPLACE":"ISSUE",X509EnrollmentPayload.Kind.CRMF,frozen.transactionSha256(),
                "sha512:"+HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(auth.encode())));
        return target;
    }
    private static zeroecho.pki.api.hybrid.sdk.HybridSdkValue sdkValue(String value) { return zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(value); }
    private static byte[] sdkBytes(String value) { return value.getBytes(java.nio.charset.StandardCharsets.UTF_8); }

    /**
     * Reports request-owned SDK frame support without granting protocol admission.
     */
    /* default */ static boolean available(CmpEndpoint endpoint, zeroecho.pki.server.ServerRealmContext realm) {

        Optional<zeroecho.pki.server.enrollment.EnrollmentProfile> policy = realm.enrollmentProfiles().find(endpoint.enrollmentProfileId());
        if (policy.isEmpty() || policy.orElseThrow().state() != zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE || policy.orElseThrow().sdkProfile().isEmpty() || realm.enrollmentRuntime().isEmpty()
                || realm.enrollmentCoordinator().isEmpty() || realm.session().semanticSigning().isEmpty()) { return false; }
        return realm.session().profiles().requireActiveProfile(endpoint.profileId()).definition().hybridMode()
                instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature mode
                && mode.subjectKeySource() == zeroecho.pki.api.hybrid.HybridCertificateMode.AlternativeSubjectKeySource.REQUEST;
        }

}
