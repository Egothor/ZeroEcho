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
package zeroecho.pki.api.ca;

import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Immutable generation-specific signing authority and retained certificate evidence.
 * The certificate baseline describes this generation's own certificate, never the
 * baseline of certificates it will issue. Incoming certificate signatures belong
 * to the parent and do not determine either outgoing key binding.
 *
 * <p>Construction checks identity and representation consistency, not live managed
 * key availability, possession or signature validity. Retaining this public evidence
 * does not grant permission to sign. A certificate-baseline marker is not a store
 * migration procedure; the supported deployment baseline remains a fresh empty store.
 *
 * @param version binding model version, currently one
 * @param issuerId immutable generation identity
 * @param authorityId logical authority identity
 * @param credentialId exact retained CA credential
 * @param formatId credential format
 * @param primary outgoing primary managed signing key
 * @param alternative complete outgoing alternative managed signing key, if hybrid
 * @param certificateSha256 exact retained certificate digest
 * @param profile exact creation profile reference
 * @param bindingSetCommitment exact X.509 algorithm binding-set digest
 * @param certificateHybridBaseline encoding baseline of the retained certificate
 * @param evidenceSha256 verified creation evidence digest
 */
public record IssuerCryptographicBinding(int version, PkiId issuerId, PkiId authorityId,
        PkiId credentialId, String formatId, IssuerKeyBinding primary,
        Optional<IssuerKeyBinding> alternative, String certificateSha256,
        CertificateProfileRef profile, String bindingSetCommitment,
        HybridSignatureBaseline certificateHybridBaseline, String evidenceSha256) {
    /**
     * Identifies the encoding recipe of this CA's own retained certificate.
     *
     * <p>The marker describes retained representation. It neither selects an outgoing
     * issuer algorithm nor proves that the certificate or any historical store is valid.
     */
    public enum HybridSignatureBaseline {
        /**
         * Identifies a retained certificate without an alternative signature.
         */
        NONE,
        /**
         * Identifies the Cor3 SIGNED wrapper with native inner and outer AlgorithmIdentifiers.
         */
        COR3_SIGNED_WRAPPER,
        /**
         * Identifies the historical pre-TBS recipe; it is not selected for new certificates
         * and does not imply an implemented old-store migration path.
         */
        LEGACY_PRE_TBS
    }
    /**
     * Validates the complete generation-specific public binding without algorithm inference.
     *
     * <p>The issuer identity must derive from the exact authority and credential.
     * Alternative-role presence must agree with the retained certificate baseline,
     * and all digest coordinates must be lowercase SHA-256 hexadecimal. The
     * constructor does not open a store, resolve keys or verify certificate signatures.
     *
     * @throws NullPointerException if a required identity, role, profile, optional or baseline is null
     * @throws IllegalArgumentException if the version, format bound, generation identity,
     *         alternative/baseline relationship or a digest representation is invalid
     * @param version binding model version, currently one
     * @param issuerId immutable generation identity
     * @param authorityId logical authority identity
     * @param credentialId exact retained CA credential
     * @param formatId credential format
     * @param primary outgoing primary managed signing key
     * @param alternative complete outgoing alternative managed signing key, if hybrid
     * @param certificateSha256 exact retained certificate digest
     * @param profile exact creation profile reference
     * @param bindingSetCommitment exact X.509 algorithm binding-set digest
     * @param certificateHybridBaseline encoding baseline of the retained certificate
     * @param evidenceSha256 verified creation evidence digest
     */
    public IssuerCryptographicBinding {
        Objects.requireNonNull(issuerId, "issuerId");
        Objects.requireNonNull(authorityId, "authorityId");
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(primary, "primary");
        Objects.requireNonNull(alternative, "alternative");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(certificateHybridBaseline, "certificateHybridBaseline");
        if (version != 1 || formatId == null || formatId.isBlank() || formatId.length() > 256
                || !issuerId.equals(IssuerGeneration.idFor(authorityId, credentialId))
                || alternative.isPresent() != (certificateHybridBaseline != HybridSignatureBaseline.NONE)) {
            throw new IllegalArgumentException("Invalid issuer cryptographic binding");
        }
        requireDigest(certificateSha256, "certificateSha256");
        requireDigest(bindingSetCommitment, "bindingSetCommitment");
        requireDigest(evidenceSha256, "evidenceSha256");
    }

    /**
     * Commits all binding fields using the canonical versioned public-evidence encoding.
     *
     * <p>The codec's ZICB magic, version and ordered framing supply domain separation.
     * Hashing does not validate a managed key or prove that evidence was authorized.
     *
     * @return the SHA-256 commitment as 64 lowercase hexadecimal characters
     * @throws IllegalArgumentException if the complete binding cannot fit the codec's bounds
     * @throws IllegalStateException if the required SHA-256 implementation is unavailable
     */
    public String commitment() {
        try {
            return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                    .digest(IssuerCryptographicBindingCodec.encode(this)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    /**
     * Checks the canonical lowercase hexadecimal representation of a SHA-256 digest.
     *
     * @param value candidate digest text
     * @param field trusted field label included in the validation failure
     * @throws IllegalArgumentException if the value is null or is not exactly 64 lowercase hexadecimal characters
     */
    static void requireDigest(String value, String field) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException(field + " must be lowercase SHA-256 hexadecimal");
        }
    }
}
