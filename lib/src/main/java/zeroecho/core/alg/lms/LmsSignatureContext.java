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
package zeroecho.core.alg.lms;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Streaming signature context for LMS (Leighton–Micali Signatures).
 *
 * <p>
 * LMS is a stateful hash-based one-time signature scheme standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8554">RFC 8554</a>. Each
 * LMS private key is a Merkle tree of Winternitz OTS (LMOTS) keys; every
 * signing operation consumes one leaf and is therefore <strong>irreversible</strong>.
 * </p>
 *
 * <p>This generic context cannot sign; freshly enrolled keys may use
 * {@link zeroecho.core.storage.StatefulSigner}. Private-key construction fails before provider initialization or
 * signature-size discovery and never consumes a leaf. Verification remains available.</p>
 *
 * <h2>Usage — verification</h2><pre>
 * {@code
 * LmsSignatureContext vctx = new LmsSignatureContext(alg, publicKey);
 * vctx.setExpectedTag(signature);
 * try (InputStream in = vctx.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(OutputStream.nullOutputStream());
 * }
 * }
 * </pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are stateful and not thread-safe. Use one instance per signing or
 * verification operation.
 * </p>
 *
 * @since 1.0
 */
public final class LmsSignatureContext implements SignatureContext {
    private static final int TYPE_HEADER_BYTES = 12;
    private static final int SUPPORTED_LEVELS = 1;

    private static final String ALG = "LMS";
    private static final String PROVIDER = "BCPQC";

    private final GenericJcaSignatureContext delegate;

    /**
     * Rejects LMS signing without using or changing the private key.
     *
     * @param algorithm owning algorithm descriptor
     * @param privateKey private key
     * @throws zeroecho.core.err.UnsupportedRoleException always; use the explicit durable capability
     * @throws GeneralSecurityException retained for source compatibility
     */
    public LmsSignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey)
            throws GeneralSecurityException {
        throw new zeroecho.core.err.UnsupportedRoleException("LMS signing requires an explicit durable StatefulSigner");
    }

    /**
     * Creates an LMS verification context bound to the given public key.
     *
     * <p>
     * The expected signature length is derived from the LMS/LMOTS parameter set
     * encoded in the public key, without any signing operation.
     * </p>
     *
     * @param algorithm owning algorithm descriptor; must not be {@code null}
     * @param publicKey an LMS public key; must not be {@code null}
     * @throws GeneralSecurityException if the key is invalid or the signature
     *                                  length cannot be determined
     */
    public LmsSignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, publicKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER),
                LmsSignatureContext::sigLenFromPublicKey);
    }

    /**
     * Derives the LMS signature length (bytes) from the LMS public key.
     *
     * <p>
     * Parses the X.509 SubjectPublicKeyInfo encoding. BC encodes single-tree LMS
     * keys in HSS/LMS format: {@code u32str(L) || LMS-pub}, so the LMS type code
     * starts at byte offset&nbsp;4 (after the 4-byte HSS level count). The LMOTS
     * type code is at offset&nbsp;8.
     * </p>
     * <p>
     * Signature length formula — BC JCA "LMS" produces HSS format (RFC&nbsp;8554 §6.3)
     * even for a single-level (L=1) key, so the output is:
     * </p>
     * <pre>
     * HSS_SIG_LENGTH = 4                       // u32str(Nspk=0)
     *                + 4                       // u32str(q)
     *                + 4 + n + n*p             // LMOTS signature incl. type
     *                + 4                       // u32str(lms_type)
     *                + H * m                   // auth path
     * </pre>
     *
     * @param pk an LMS public key
     * @return the signature length in bytes
     * @throws GeneralSecurityException if the public key cannot be parsed or
     *                                  contains unknown type codes
     */
    /* default */ static int sigLenFromPublicKey(PublicKey pk) throws GeneralSecurityException {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pk.getEncoded());
            byte[] raw = spki.getPublicKeyData().getBytes();
            // BC encodes LMS keys in HSS/LMS format: u32str(L) || LMS-pub.
            // A single-tree LMS key has L=1; the LMS type starts at offset 4.
            if (raw.length < TYPE_HEADER_BYTES) {
                throw new GeneralSecurityException("LMS public key encoding too short: " + raw.length);
            }
            if (readInt(raw, 0) != SUPPORTED_LEVELS) {
                throw new GeneralSecurityException("Only single-level LMS metadata is supported");
            }
            int lmsType = readInt(raw, 4);
            int otsType = readInt(raw, 8);
            LMSigParameters sigParams = LMSigParameters.getParametersForType(lmsType);
            LMOtsParameters otsParams = LMOtsParameters.getParametersForType(otsType);
            if (sigParams == null) {
                throw new GeneralSecurityException("Unknown LMS type code: " + lmsType);
            }
            if (otsParams == null) {
                throw new GeneralSecurityException("Unknown LMOTS type code: " + otsType);
            }
            if (raw.length != 4 + 4 + 4 + 16 + sigParams.getM() || sigParams.getM() != otsParams.getN()) {
                throw new GeneralSecurityException("Invalid LMS public key structure");
            }
            // BC JCA "LMS" produces an HSS-format signature (RFC 8554 §6.3) even for
            // single-level keys: u32str(Nspk=0) || LMS_signature.
            // LMS_sig = u32str(q) + LMOTS_sig + u32str(lms_type) + path(H*m)
            // LMOTS_sig = u32str(type) + C(n) + y[0..p-1](n*p) = 4 + n*(1+p)
            int n = otsParams.getN();
            int p = otsParams.getP();
            return 4 + 4 + 4 + n * (1 + p) + 4 + sigParams.getH() * sigParams.getM();
        } catch (GeneralSecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityException("Cannot determine LMS signature length", e);
        }
    }

    private static int readInt(byte[] b, int offset) {
        return ((b[offset] & 0xFF) << 24)
                | ((b[offset + 1] & 0xFF) << 16)
                | ((b[offset + 2] & 0xFF) << 8)
                | (b[offset + 3] & 0xFF);
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return delegate.algorithm();
    }

    @Override
    public java.security.Key key() {
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
