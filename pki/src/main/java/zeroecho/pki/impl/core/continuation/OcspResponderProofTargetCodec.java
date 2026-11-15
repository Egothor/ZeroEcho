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

package zeroecho.pki.impl.core.continuation;

import java.util.Base64;
import java.util.HexFormat;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.signing.ManagedOcspResponderProofTarget;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore.SubjectKeyRole;

/** Canonical private version-one prefix codecs for pre-certificate responder proof coordinates. */
public final class OcspResponderProofTargetCodec {
    private static final String TARGET = "OCSP_RESPONDER_PROOF_TARGET_V1";
    private static final String PROFILE = "OCSP_RESPONDER_PROOF_PROFILE_V1";
    private OcspResponderProofTargetCodec() { }
    /** @param target exact candidate context @return canonical unpadded base64url private encoding */
    public static String encode(ManagedOcspResponderProofTarget target) {
        return encoded(TARGET, target.parentOperationId().value(), target.parentIntentCommitment(), target.frozenTargetCommitment(), target.role().name());
    }
    /** @param value canonical private encoding @return exact bounded target @throws IllegalArgumentException if malformed */
    public static ManagedOcspResponderProofTarget decode(String value) {
        var decoded = decoded(value, TARGET, 4);
        var target = new ManagedOcspResponderProofTarget(new PkiId(decoded.field(0)), decoded.field(1), decoded.field(2), SubjectKeyRole.valueOf(decoded.field(3)));
        if (!encode(target).equals(value)) throw invalid(); return target;
    }
    /** @param profile immutable profile reference @return canonical unpadded base64url encoding */
    public static String profile(CertificateProfileRef profile) {
        return encoded(PROFILE, profile.profileId(), Long.toString(profile.profileVersion()), HexFormat.of().formatHex(profile.canonicalSha256()));
    }
    /** @param value exact profile encoding @return immutable reference @throws IllegalArgumentException if malformed */
    public static CertificateProfileRef profile(String value) {
        var decoded = decoded(value, PROFILE, 3);
        if (!decoded.field(1).matches("[1-9][0-9]{0,18}") || !decoded.field(2).matches("[0-9a-f]{64}")) throw invalid();
        var profile = new CertificateProfileRef(decoded.field(0), Long.parseLong(decoded.field(1)), HexFormat.of().parseHex(decoded.field(2)));
        if (!profile(profile).equals(value)) throw invalid(); return profile;
    }
    private static String encoded(String operation, String... fields) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(DomainCommandEncoding.template(
                DomainContinuationStore.Kind.KEY_PROOF, operation, fields).command().bytes());
    }
    private static DomainCommandEncoding.Decoded decoded(String value, String operation, int fields) {
        if (value == null || value.length() > 32_768 || !value.matches("[A-Za-z0-9_-]+")) throw invalid();
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) throw invalid();
        var decoded = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes)).requireFields(fields);
        if (!decoded.operation().equals(operation)) throw invalid(); return decoded;
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Responder proof prefix invalid"); }
}
