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

/**
 * Encodes canonical internal version-one prefixes for managed responder proof targets and profiles.
 *
 * <p>The descriptors contain public coordinates, not private keys or authority
 * capabilities. Target and profile prefixes use different operation discriminators;
 * decoders require exact canonical unpadded Base64url and reject unknown shapes.
 * Encoding does not resolve a provider, authenticate a caller or admit a proof.
 */
public final class OcspResponderProofTargetCodec {
    private static final String TARGET = "OCSP_RESPONDER_PROOF_TARGET_V1";
    private static final String PROFILE = "OCSP_RESPONDER_PROOF_PROFILE_V1";
    private OcspResponderProofTargetCodec() {
    }
    /**
     * Encodes the exact parent intent, frozen candidate commitment and subject role.
     *
     * @param target validated immutable pre-certificate proof context; must not be null
     * @return canonical unpadded Base64url target-prefix encoding
     * @throws NullPointerException if the target is null
     * @throws IllegalArgumentException if the domain command exceeds its framing bounds
     */
    public static String encode(ManagedOcspResponderProofTarget target) {
        return encoded(TARGET, target.parentOperationId().value(), target.parentIntentCommitment(),
                target.frozenTargetCommitment(), target.role().name());
    }
    /**
     * Decodes and reconstructs the exact bounded responder proof-target coordinates.
     *
     * <p>The descriptor must have four fields and reproduce the same bytes when
     * re-encoded. Structural validation does not establish the actual parent/child
     * relationship or authorize the selected subject role.
     *
     * @param value canonical target encoding, at most 32,768 characters
     * @return independently constructed immutable proof target
     * @throws IllegalArgumentException if input is null, oversized, noncanonical or malformed
     */
    public static ManagedOcspResponderProofTarget decode(String value) {
        DomainCommandEncoding.Decoded decoded = decoded(value, TARGET, 4);
        ManagedOcspResponderProofTarget target = new ManagedOcspResponderProofTarget(new PkiId(decoded.field(0)),
                decoded.field(1), decoded.field(2), SubjectKeyRole.valueOf(decoded.field(3)));
        if (!encode(target).equals(value)) {
            throw invalid();
        }
        return target;
    }
    /**
     * Encodes an exact profile identifier, positive version and canonical SHA-256 digest.
     *
     * <p>No active-profile lookup occurs and no profile permission is implied.
     * The descriptor preserves the supplied version rather than following a mutable pointer.
     *
     * @param profile immutable retained profile reference; must not be null
     * @return canonical unpadded Base64url profile-prefix encoding
     * @throws NullPointerException if the profile is null
     * @throws IllegalArgumentException if the domain command exceeds its framing bounds
     */
    public static String profile(CertificateProfileRef profile) {
        return encoded(PROFILE, profile.profileId(), Long.toString(profile.profileVersion()),
                HexFormat.of().formatHex(profile.canonicalSha256()));
    }
    /**
     * Decodes an exact profile reference without consulting the profile store.
     *
     * <p>Three fields, positive canonical decimal version, lowercase digest and
     * byte-exact re-encoding are required. The result does not prove that the
     * referenced profile is installed, active or authorized for a request.
     *
     * @param value canonical profile encoding, at most 32,768 characters
     * @return independently constructed immutable profile reference
     * @throws IllegalArgumentException if input is null, oversized, noncanonical or malformed
     */
    public static CertificateProfileRef profile(String value) {
        DomainCommandEncoding.Decoded decoded = decoded(value, PROFILE, 3);
        if (!decoded.field(1).matches("[1-9][0-9]{0,18}") || !decoded.field(2).matches("[0-9a-f]{64}")) {
            throw invalid();
        }
        CertificateProfileRef profile = new CertificateProfileRef(decoded.field(0), Long.parseLong(decoded.field(1)),
                HexFormat.of().parseHex(decoded.field(2)));
        if (!profile(profile).equals(value)) {
            throw invalid();
        }
        return profile;
    }
    private static String encoded(String operation, String... fields) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(DomainCommandEncoding.template(
                DomainContinuationStore.Kind.KEY_PROOF, operation, fields).command().bytes());
    }
    private static DomainCommandEncoding.Decoded decoded(String value, String operation, int fields) {
        if (value == null || value.length() > 32_768 || !value.matches("[A-Za-z0-9_-]+")) {
            throw invalid();
        }
        byte[] bytes = Base64.getUrlDecoder().decode(value);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) {
            throw invalid();
        }
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes))
                .requireFields(fields);
        if (!decoded.operation().equals(operation)) {
            throw invalid();
        }
        return decoded;
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Responder proof prefix invalid");
    }
}
