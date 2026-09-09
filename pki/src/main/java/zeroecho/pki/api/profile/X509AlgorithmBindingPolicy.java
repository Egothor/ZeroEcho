/*******************************************************************************
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
package zeroecho.pki.api.profile;

import java.util.Objects;
import java.util.Optional;

/**
 * Immutable explicit X.509 representation policy persisted with a certificate
 * profile.
 *
 * <p>Standard mode never falls back to a private OID. Explicit mode pins stable
 * binding identifiers and their immutable semantic commitments. Raw OIDs and DER
 * parameters are deliberately absent from this model.</p>
 *
 * @param mode standard-only or explicit binding selection
 * @param subjectPublicKey optional SPKI binding
 * @param csrSignature optional CSR-signature binding
 * @param certificateSignature optional certificate-signature binding
 * @param crlSignature optional CRL-signature binding
 */
public record X509AlgorithmBindingPolicy(Mode mode, Optional<BindingReference> subjectPublicKey,
        Optional<BindingReference> csrSignature, Optional<BindingReference> certificateSignature,
        Optional<BindingReference> crlSignature) {

    /** Selection mode. */
    public enum Mode {
        /** Only sealed official bindings may be selected. */
        STANDARD_ONLY,
        /** Every custom representation is selected by stable binding identity. */
        EXPLICIT
    }

    /**
     * Stable reference to one immutable binding contract.
     *
     * @param bindingId stable binding identity
     * @param semanticCommitment exact contract commitment
     */
    public record BindingReference(String bindingId, String semanticCommitment) {
        /** Validates one binding reference. */
        public BindingReference {
            if (bindingId == null || bindingId.isBlank() || semanticCommitment == null
                    || semanticCommitment.isBlank() || semanticCommitment.length() > 1024) {
                throw new IllegalArgumentException("X.509 binding reference is invalid");
            }
        }
    }

    /** Validates and snapshots the policy. */
    public X509AlgorithmBindingPolicy {
        Objects.requireNonNull(mode, "mode");
        subjectPublicKey = Objects.requireNonNull(subjectPublicKey, "subjectPublicKey");
        csrSignature = Objects.requireNonNull(csrSignature, "csrSignature");
        certificateSignature = Objects.requireNonNull(certificateSignature, "certificateSignature");
        crlSignature = Objects.requireNonNull(crlSignature, "crlSignature");
        boolean selected = subjectPublicKey.isPresent() || csrSignature.isPresent()
                || certificateSignature.isPresent() || crlSignature.isPresent();
        if (mode == Mode.STANDARD_ONLY == selected) {
            throw new IllegalArgumentException("X.509 binding mode and selections disagree");
        }
    }

    /**
     * Creates a standard-only policy with no private fallback.
     *
     * @return standard-only policy with no private fallback
     */
    public static X509AlgorithmBindingPolicy standardOnly() {
        return new X509AlgorithmBindingPolicy(Mode.STANDARD_ONLY, Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty());
    }
}
