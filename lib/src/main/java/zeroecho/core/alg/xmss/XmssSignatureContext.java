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
package zeroecho.core.alg.xmss;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Streaming signature context for XMSS (eXtended Merkle Signature Scheme).
 *
 * <p>
 * XMSS is a stateful hash-based signature scheme standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8391">RFC 8391</a>. Unlike
 * SLH-DSA/SPHINCS+, XMSS maintains a leaf index in the private key and each
 * signing operation advances that index <strong>irreversibly</strong>.
 * </p>
 *
 * <p>This generic context cannot sign; freshly enrolled keys may use
 * {@link zeroecho.core.storage.StatefulSigner}. Private-key construction fails before provider initialization or
 * signature-size discovery and never consumes a leaf. Verification remains available.</p>
 *
 * <h2>Usage — verification</h2><pre>
 * {@code
 * XmssSignatureContext vctx = new XmssSignatureContext(alg, publicKey);
 * vctx.setExpectedTag(signature);
 * try (InputStream in = vctx.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(OutputStream.nullOutputStream());
 * }
 * }
 * </pre>
 *
 * <h2>Signature length formula</h2>
 * <p>
 * For a digest output length of n bytes and tree height h:
 * </p>
 * <ul>
 * <li>n = 32 (SHA-256 / SHAKE-128): {@code sig_len = 4 + 32 * (68 + h)}</li>
 * <li>n = 64 (SHA-512 / SHAKE-256): {@code sig_len = 4 + 64 * (132 + h)}</li>
 * </ul>
 * <p>
 * The values 68 = 1 + 67 (index + WOTS+ p) and 132 = 1 + 131 reflect the
 * Winternitz parameter counts p for w = 16 (the value used in the BC
 * implementation for these parameter sets).
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful and not thread-safe. Use one instance per signing or
 * verification operation.
 * </p>
 *
 * @since 1.0
 */
public final class XmssSignatureContext implements SignatureContext {

    private static final String ALG = "XMSS";
    private static final String PROVIDER = "BCPQC";

    private final GenericJcaSignatureContext delegate;

    /**
     * Rejects XMSS signing without using or changing the private key.
     *
     * @param algorithm owning algorithm descriptor
     * @param privateKey private key
     * @throws zeroecho.core.err.UnsupportedRoleException always; use the explicit durable capability
     * @throws GeneralSecurityException retained for source compatibility
     */
    public XmssSignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey)
            throws GeneralSecurityException {
        throw new zeroecho.core.err.UnsupportedRoleException("XMSS signing requires an explicit durable StatefulSigner");
    }

    /**
     * Creates an XMSS verification context bound to the given public key.
     *
     * <p>
     * The expected signature length is derived from key parameters without any
     * signing operation.
     * </p>
     *
     * @param algorithm owning algorithm descriptor; must not be {@code null}
     * @param publicKey an XMSS public key ({@link XMSSKey}); must not be
     *                  {@code null}
     * @throws GeneralSecurityException if the key type is unrecognized or the
     *                                  JCA engine cannot be initialized
     */
    public XmssSignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, publicKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER),
                XmssSignatureContext::sigLenFromPublicKey);
    }

    private static int sigLenFromPublicKey(PublicKey pk) throws GeneralSecurityException {
        if (!(pk instanceof XMSSKey xk)) {
            throw new GeneralSecurityException("Expected an XMSS public key (XMSSKey)");
        }
        return xmssSigLen(xk);
    }

    /**
     * Computes the XMSS signature length from key parameters.
     *
     * <p>
     * Uses {@link XMSSKey#getHeight()} and {@link XMSSKey#getTreeDigest()} to
     * determine h and n, then applies the formula {@code 4 + n * (1 + p + h)}
     * where p = 67 for n = 32 (w = 16, SHA-256 or SHAKE-128) and p = 131 for
     * n = 64 (w = 16, SHA-512 or SHAKE-256).
     * </p>
     *
     * @param xk XMSS key (public or private)
     * @return signature length in bytes
     * @throws GeneralSecurityException if the digest is not recognized
     */
    /* default */ static int xmssSigLen(XMSSKey xk) throws GeneralSecurityException {
        String digest = xk.getTreeDigest();
        if (digest == null) {
            throw new GeneralSecurityException("XMSS key has no tree digest");
        }
        int h = xk.getHeight();
        if (h < 2 || h > 30) {
            throw new GeneralSecurityException("Unsupported XMSS tree height");
        }
        int n = switch (digest) {
            case "SHA256", "SHAKE128", "SHAKE256/256" -> 32;
            case "SHA512", "SHAKE256" -> 64;
            case "SHA256/192", "SHAKE256/192" -> 24;
            default -> throw new GeneralSecurityException("Unsupported XMSS tree digest");
        };
        int p = 2 * n + 3;
        return 4 + n * (1 + p + h);
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return delegate.algorithm();
    }

    @Override
    public Key key() {
        return delegate.key();
    }

    @Override
    public void close() {
        delegate.close();
    }

    @Override
    public InputStream wrap(InputStream upstream) throws IOException {
        return delegate.wrap(upstream);
    }

    @Override
    public int tagLength() {
        return delegate.tagLength();
    }

    @Override
    public void setExpectedTag(byte[] expected) {
        delegate.setExpectedTag(expected);
    }

    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        delegate.setVerificationApproach(strategy);
    }

    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return delegate.getVerificationCore();
    }
}
