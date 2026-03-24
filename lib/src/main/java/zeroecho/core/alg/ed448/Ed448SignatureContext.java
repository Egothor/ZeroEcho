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
package zeroecho.core.alg.ed448;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.eddsa.CommonEdDSASignatureContext;
import zeroecho.core.context.SignatureContext;

/**
 * Signature context for Ed448 with a fixed 114-byte tag length.
 *
 * <p>
 * This class binds the Ed448 algorithm to {@link SignatureContext} via
 * {@link CommonEdDSASignatureContext}. Internally it configures a JCA
 * {@code Signature} with the name {@code "Ed448"} and delegates all streaming
 * and verification behavior to the common adapter.
 * </p>
 *
 * <h2>Algorithm characteristics</h2>
 * <ul>
 * <li>JCA signature name: {@code "Ed448"}.</li>
 * <li>Fixed signature length: 114 bytes (reported by
 * {@link #tagLength()}).</li>
 * <li>Edwards-curve Digital Signature Algorithm as specified in RFC 8032.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <h3>One-shot API</h3> <pre>
 * {@code
 * // Sign
 * PrivateKey priv = ...;
 * SignatureContext signer =
 *     new Ed448SignatureContext(CryptoAlgorithms.require("Ed448"), priv);
 * signer.update(message);
 * byte[] sig = signer.sign();
 *
 * // Verify
 * PublicKey pub = ...;
 * SignatureContext verifier =
 *     new Ed448SignatureContext(CryptoAlgorithms.require("Ed448"), pub);
 * verifier.update(message);
 * boolean ok = verifier.verify(sig);
 * }
 * </pre>
 *
 * <h3>Streaming pipeline (wrap)</h3> <pre>
 * {@code
 * // SIGN mode: body bytes followed by 114-byte signature trailer
 * try (SignatureContext ctx =
 *          new Ed448SignatureContext(CryptoAlgorithms.require("Ed448"), priv);
 *      InputStream in = ctx.wrap(upstream)) {
 *     in.transferTo(out);
 * }
 *
 * // VERIFY mode: supply expected signature; verification occurs at EOF
 * try (SignatureContext ctx =
 *          new Ed448SignatureContext(CryptoAlgorithms.require("Ed448"), pub)) {
 *     ctx.setExpectedTag(expectedSig);
 *     try (InputStream in = ctx.wrap(bodyWithoutTrailer)) {
 *         in.transferTo(java.io.OutputStream.nullOutputStream());
 *     }
 * }
 * }
 * </pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful and not thread-safe. Use one context per signing or
 * verification operation, and call {@code wrap(...)} at most once per instance.
 * </p>
 *
 * @since 1.0
 */
public final class Ed448SignatureContext extends CommonEdDSASignatureContext {
    private static final String SIG_NAME = "Ed448";
    private static final int TAG_LEN = 114;

    /**
     * Constructs a signing context bound to the given private key.
     *
     * @param algorithm  parent algorithm descriptor; must not be {@code null}
     * @param privateKey Ed448 private key; must not be {@code null}
     * @throws GeneralSecurityException if the underlying JCA engine cannot be
     *                                  initialized
     * @throws NullPointerException     if any argument is {@code null}
     */
    public Ed448SignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey)
            throws GeneralSecurityException {
        super(algorithm, privateKey, SIG_NAME, TAG_LEN);
    }

    /**
     * Constructs a verification context bound to the given public key.
     *
     * @param algorithm parent algorithm descriptor; must not be {@code null}
     * @param publicKey Ed448 public key; must not be {@code null}
     * @throws GeneralSecurityException if the underlying JCA engine cannot be
     *                                  initialized
     * @throws NullPointerException     if any argument is {@code null}
     */
    public Ed448SignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey)
            throws GeneralSecurityException {
        super(algorithm, publicKey, SIG_NAME, TAG_LEN);
    }
}
