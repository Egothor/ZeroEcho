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
package zeroecho.pkix.bc;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.sign.ContentVerifier;

/**
 * A {@link ContentVerifier} backed by a {@link PublicKey} via
 * {@link java.security.Signature}.
 */
final class JcaContentVerifier implements ContentVerifier {

    private final Signature signature;
    private final OutputStream stream;

    /* default */ JcaContentVerifier(PublicKey publicKey, AlgorithmIdentifier algorithm) {
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(algorithm, "algorithm");
        try {
            this.signature = Signature.getInstance(BcAlgorithmIdentifiers.jcaName(algorithm));
            this.signature.initVerify(publicKey);
        } catch (GeneralSecurityException failure) {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm.oid(), failure);
        }
        this.stream = new SignatureUpdateOutputStream(signature);
    }

    @Override
    public OutputStream contentStream() {
        return stream;
    }

    @Override
    public boolean verify(byte[] expectedSignature) {
        try {
            return signature.verify(expectedSignature);
        } catch (SignatureException failure) {
            return false;
        }
    }
}
