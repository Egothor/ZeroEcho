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
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.sign.ContentSigner;

/**
 * A {@link ContentSigner} backed by a local {@link PrivateKey} via
 * {@link java.security.Signature}. Used for tooling, tests, and native CSR
 * generation; production authority signing is supplied by the PKI layer's own
 * bus-backed signer.
 */
final class JcaContentSigner implements ContentSigner {

    private final AlgorithmIdentifier algorithm;
    private final Signature signature;
    private final OutputStream stream;

    /* default */ JcaContentSigner(PrivateKey privateKey, AlgorithmIdentifier algorithm) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(privateKey, "privateKey");
        zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(algorithm.oid(), privateKey);
        try {
            this.signature = Signature.getInstance(BcAlgorithmIdentifiers.jcaName(algorithm));
            this.signature.initSign(privateKey);
        } catch (GeneralSecurityException failure) {
            throw new IllegalArgumentException("Unsupported signature algorithm: " + algorithm.oid(), failure);
        }
        this.stream = new SignatureUpdateOutputStream(signature);
    }

    @Override
    public AlgorithmIdentifier algorithm() {
        return algorithm;
    }

    @Override
    public OutputStream contentStream() {
        return stream;
    }

    @Override
    public byte[] signature() {
        try {
            return signature.sign();
        } catch (SignatureException failure) {
            throw new IllegalStateException("Signature generation failed", failure);
        }
    }
}
