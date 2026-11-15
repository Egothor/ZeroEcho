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
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;

/**
 * Exact public evidence for one issuer's outgoing managed signing key.
 * @param keyRef stable managed key reference; never private key bytes
 * @param publicKeyAlgorithm exact subject public-key identity
 * @param signatureAlgorithm exact outgoing signature identity
 * @param signatureAlgorithmIdentifier canonical DER outgoing AlgorithmIdentifier
 * @param subjectSpkiSha256 lowercase SHA-256 of canonical subject SPKI
 */
public record IssuerKeyBinding(KeyRef keyRef, AlgorithmIdentity publicKeyAlgorithm,
        AlgorithmIdentity signatureAlgorithm, EncodedObject signatureAlgorithmIdentifier,
        String subjectSpkiSha256) {
    /** Creates a complete immutable public signing-key binding. */
    public IssuerKeyBinding {
        Objects.requireNonNull(keyRef, "keyRef");
        Objects.requireNonNull(publicKeyAlgorithm, "publicKeyAlgorithm");
        Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        Objects.requireNonNull(signatureAlgorithmIdentifier, "signatureAlgorithmIdentifier");
        if (publicKeyAlgorithm.kind() != AlgorithmIdentity.Kind.PUBLIC_KEY
                || signatureAlgorithm.kind() != AlgorithmIdentity.Kind.SIGNATURE
                || signatureAlgorithmIdentifier.encoding() != Encoding.DER
                || signatureAlgorithmIdentifier.byteLength() > 4096) {
            throw new IllegalArgumentException("Invalid issuer algorithm binding");
        }
        byte[] encoded = signatureAlgorithmIdentifier.bytes();
        if (!java.util.Arrays.equals(encoded, zeroecho.pkix.Pkix.encodeAlgorithmIdentifier(
                zeroecho.pkix.Pkix.parseAlgorithmIdentifier(encoded)))) {
            throw new IllegalArgumentException("Noncanonical issuer AlgorithmIdentifier");
        }
        IssuerCryptographicBinding.requireDigest(subjectSpkiSha256, "subjectSpkiSha256");
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof IssuerKeyBinding value && keyRef.equals(value.keyRef)
                && publicKeyAlgorithm.equals(value.publicKeyAlgorithm) && signatureAlgorithm.equals(value.signatureAlgorithm)
                && java.util.Arrays.equals(signatureAlgorithmIdentifier.bytes(), value.signatureAlgorithmIdentifier.bytes())
                && subjectSpkiSha256.equals(value.subjectSpkiSha256);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyRef, publicKeyAlgorithm, signatureAlgorithm,
                java.util.Arrays.hashCode(signatureAlgorithmIdentifier.bytes()), subjectSpkiSha256);
    }
}
