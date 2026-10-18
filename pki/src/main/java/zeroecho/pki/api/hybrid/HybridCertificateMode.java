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
package zeroecho.pki.api.hybrid;

/**
 * Discriminates the hybrid certificate mode for a certificate profile.
 *
 * <p>
 * Hybrid modes allow a certificate to carry both a primary (classical) and an
 * alternative (post-quantum) signature or key, enabling a smooth migration path
 * while both types of verifiers are deployed. {@link AltSignature} and
 * {@link TwinCertificate} are implemented; {@link Composite} is a reserved stub
 * not accepted by the profile validator.
 * </p>
 *
 * @since 1.0
 */
public sealed interface HybridCertificateMode
        permits HybridCertificateMode.None, HybridCertificateMode.AltSignature,
                HybridCertificateMode.TwinCertificate, HybridCertificateMode.Composite {

    /**
     * No hybrid mode — the certificate carries only a primary signature.
     * This is the default for all profiles that do not declare hybrid support.
     */
    record None() implements HybridCertificateMode {
        /** Singleton instance. */
        public static final None INSTANCE = new None();
    }

    /**
     * X.509 2019 Amendment 2 alternative-signature extension mode.
     *
     * <p>
     * SubjectAltPublicKeyInfo (OID 2.5.29.72), AltSignatureAlgorithm (OID 2.5.29.73),
     * and AltSignatureValue (OID 2.5.29.74) extensions are added to the certificate.
     * The alternative key signs the pre-TBS structure omitting both AltSignatureValue
     * and the TBSCertificate signature field;
     * the primary key signs the complete TBS that contains the real alternative signature.
     * Only root creation, rollover and primary-key rotation support this mode.
     * Alternative-key rotation and AltSignature descendant profiles are unsupported.
     * CRLs retain the primary signature only.
     * </p>
     *
     * @param altSignatureAlgorithmId canonical algorithm identifier for the alternative signature
     * @param altKeyRef               key reference for the alternative private key in the keyring
     */
    record AltSignature(String altSignatureAlgorithmId, String altKeyRef)
            implements HybridCertificateMode {
        /**
         * Creates an AltSignature mode descriptor.
         *
         * @throws IllegalArgumentException if either value is null or blank
         */
        public AltSignature {
            if (altSignatureAlgorithmId == null || altSignatureAlgorithmId.isBlank()) {
                throw new IllegalArgumentException("altSignatureAlgorithmId must not be null or blank");
            }
            if (altKeyRef == null || altKeyRef.isBlank()) {
                throw new IllegalArgumentException("altKeyRef must not be null or blank");
            }
        }
    }

    /**
     * Twin-certificate mode: two parallel CA hierarchies, one classical and one
     * post-quantum, are maintained and cross-referenced at the deployment level.
     *
     * <p>Each individual certificate in the hierarchy is a standard single-algorithm
     * X.509 certificate; the twin relationship is a deployment-level configuration,
     * not a per-certificate property. Profiles using this mode carry no additional
     * extensions beyond the primary algorithm fields. The mode is a semantic marker
     * in the profile that tooling can use to coordinate twin deployments.</p>
     */
    record TwinCertificate() implements HybridCertificateMode {
        /** Singleton instance. */
        public static final TwinCertificate INSTANCE = new TwinCertificate();
    }

    /**
     * Composite-signature mode per draft-ounsworth-pq-composite-sigs (stub; not yet implemented).
     *
     * <p>Reserved for future use. Profiles using this mode are rejected by the validator.</p>
     */
    record Composite() implements HybridCertificateMode {
        /** Singleton instance. */
        public static final Composite INSTANCE = new Composite();
    }
}
