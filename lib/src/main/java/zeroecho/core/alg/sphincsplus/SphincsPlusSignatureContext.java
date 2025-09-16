/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.sphincsplus;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusPublicKey;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * SPHINCS+ signature context that adapts a JCA engine for streaming sign and
 * verify.
 *
 * <p>
 * This context uses the Bouncy Castle PQC provider to obtain a JCA
 * {@code Signature} instance for the "SPHINCSPlus" algorithm and exposes it via
 * the {@link SignatureContext} and {@link TagEngine} contracts. In produce
 * (SIGN) mode, the wrapped stream emits the original data followed by a
 * detached signature trailer. In verify (VERIFY) mode, the wrapped stream emits
 * only the body and compares the computed signature at EOF against a
 * caller-supplied expected value.
 * </p>
 *
 * <h2>Delegation</h2>
 * <p>
 * The implementation delegates to {@link GenericJcaSignatureContext} for the
 * streaming mechanics and JCA interaction, including trailer handling and
 * verification strategy configuration.
 * </p>
 *
 * <h2>Signature length</h2>
 * <p>
 * SPHINCS+ signatures have fixed byte lengths that depend on the parameter set
 * attached to the key. When constructed with a public key, this context
 * resolves the expected signature length from
 * {@link org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec} on the key.
 * </p>
 *
 * <h3>Canonical sizes (bytes)</h3>
 * <ul>
 * <li>128s: 7856, 128f: 17088</li>
 * <li>192s: 16224, 192f: 35664</li>
 * <li>256s: 29792, 256f: 49856</li>
 * </ul>
 *
 * <h2>Examples</h2>
 * <h3>Signing pipeline</h3> <pre>
 * {@code
 * TagEngine<java.security.Signature> eng =
 *     new SphincsPlusSignatureContext(alg, privateKey);
 *
 * try (java.io.InputStream in = eng.wrap(upstream)) {
 *     in.transferTo(out); // body, then SPHINCS+ signature trailer
 * }
 * }
 * </pre>
 *
 * <h3>Verification pipeline (detached)</h3> <pre>
 * {@code
 * byte[] expectedSig = ...; // obtained via a trusted channel
 *
 * TagEngine<java.security.Signature> eng =
 *     new SphincsPlusSignatureContext(alg, publicKey);
 *
 * // Optional: throw on mismatch at EOF
 * eng.setVerificationApproach(eng.getVerificationCore().getThrowOnMismatch());
 * eng.setExpectedTag(expectedSig);
 *
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream());
 * }
 * }
 * </pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe and are single-use within a pipeline. Use one
 * instance per signing or verification stream.
 * </p>
 *
 * @since 1.0
 */
public final class SphincsPlusSignatureContext implements SignatureContext {
    private static final String ALG = "SPHINCSPlus";
    private static final String PROVIDER = "BCPQC";

    private final GenericJcaSignatureContext delegate;

    /**
     * Creates a SPHINCS+ signing context bound to a private key.
     *
     * <p>
     * The JCA engine is obtained from the "BCPQC" provider using the "SPHINCSPlus"
     * algorithm name. The signature length resolver probes the JCA engine to
     * determine the produced signature size.
     * </p>
     *
     * @param algorithm  the parent cryptographic algorithm abstraction; must not be
     *                   {@code null}
     * @param privateKey a SPHINCS+ private key; must not be {@code null}
     * @throws GeneralSecurityException if the JCA signature engine cannot be
     *                                  initialized
     */
    public SphincsPlusSignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, privateKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER),
                GenericJcaSignatureContext.SignLengthResolver.probeWith(ALG, PROVIDER));
    }

    /**
     * Creates a SPHINCS+ verification context bound to a public key.
     *
     * <p>
     * The expected signature length is derived from the public key's
     * {@link org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec}.
     * </p>
     *
     * @param algorithm the parent cryptographic algorithm abstraction; must not be
     *                  {@code null}
     * @param publicKey a SPHINCS+ public key; must not be {@code null}
     * @throws GeneralSecurityException if the key is invalid or the signature
     *                                  length cannot be determined
     */
    public SphincsPlusSignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, publicKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER), SphincsPlusSignatureContext::sigLenFromPublicKey);
    }

    /**
     * Resolves the canonical signature length from the SPHINCS+ parameter set on a
     * public key.
     *
     * <p>
     * Expected key type is Bouncy Castle's
     * {@link org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusPublicKey}.
     * Supported parameter names match the pattern
     * {@code <hash>-<level><variant>(-robust|-simple)?}, for example
     * {@code shake-256s-robust}, {@code sha2-192f-simple}, or {@code haraka-128s}.
     * </p>
     *
     * @param pk a SPHINCS+ public key carrying a parameter spec
     * @return the canonical signature length in bytes
     * @throws GeneralSecurityException if the key type or parameter spec is missing
     *                                  or unrecognized
     */
    private static int sigLenFromPublicKey(PublicKey pk) throws GeneralSecurityException {
        if (!(pk instanceof SPHINCSPlusPublicKey spk)) {
            throw new GeneralSecurityException("Expected a BouncyCastle SPHINCS+ public key (BCPQC)");
        }
        final SPHINCSPlusParameterSpec ps = spk.getParameterSpec();
        if (ps == null) {
            throw new GeneralSecurityException("Missing SPHINCS+ parameter spec on public key");
        }
        final String name = ps.getName(); // e.g. "shake-256s-robust", "sha2-192f-simple", "haraka-128s"
        if (name == null || name.isEmpty()) {
            throw new GeneralSecurityException("Unknown SPHINCS+ parameter (no name)");
        }

        // Pattern: <hash>-<level><variant>(-robust|-simple)?
        // Examples: shake-256s-robust, sha2-192f-simple, haraka-128s
        final java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("^[a-z0-9]+-(128|192|256)([sf])(?:-(robust|simple))?$").matcher(name);
        if (!m.matches()) {
            throw new GeneralSecurityException("Cannot parse SPHINCS+ security level/variant from: " + name);
        }
        final int level = Integer.parseInt(m.group(1));
        final char var = m.group(2).charAt(0); // 's' or 'f'
        final boolean isSmall = var == 's';

        // Canonical signature sizes (bytes) for SPHINCS+ per spec:
        // 128s: 7856, 128f: 17088
        // 192s: 16224, 192f: 35664
        // 256s: 29792, 256f: 49856
        return switch (level) {
            case 128 -> isSmall ? 7_856 : 17_088;
            case 192 -> isSmall ? 16_224 : 35_664;
            case 256 -> isSmall ? 29_792 : 49_856;
            default -> throw new GeneralSecurityException("Unsupported SPHINCS+ level: " + level);
        };
    }

    /**
     * Returns the algorithm associated with this context.
     *
     * @return the parent {@link CryptoAlgorithm}
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return delegate.algorithm();
    }

    /**
     * Returns the key bound to this context.
     *
     * @return the signing {@link PrivateKey} or verification {@link PublicKey}
     */
    @Override
    public java.security.Key key() {
        return delegate.key();
    }

    /**
     * Closes this context and releases underlying resources.
     *
     * <p>
     * Once closed, the context should not be reused. If auditing is enabled,
     * closing may also trigger key destruction attempts.
     * </p>
     */
    @Override
    public void close() {
        delegate.close();
    }

    /**
     * Wraps an input stream to produce or verify a SPHINCS+ signature as data is
     * consumed.
     *
     * <p>
     * For SIGN mode this feeds bytes into the signing engine and appends the
     * signature at EOF. For VERIFY mode this feeds bytes into the verification
     * engine and compares the computed signature at EOF against the expected value
     * (supplied via {@link #setExpectedTag(byte[])}).
     * </p>
     *
     * @param upstream the input stream providing raw data; must not be {@code null}
     * @return a wrapped input stream that updates the signature engine
     * @throws IOException if wrapping fails
     */
    @Override
    public InputStream wrap(InputStream upstream) throws IOException {
        return delegate.wrap(upstream);
    }

    /**
     * Returns the length of the signature (tag) produced or expected.
     *
     * @return signature length in bytes
     */
    @Override
    public int tagLength() {
        return delegate.tagLength();
    }

    /**
     * Supplies the expected signature for verification mode.
     *
     * @param expected the expected signature bytes; implementations may defensively
     *                 copy the array
     */
    @Override
    public void setExpectedTag(byte[] expected) {
        delegate.setExpectedTag(expected);
    }

    /**
     * Sets the verification approach to compare computed and expected signatures.
     *
     * @param strategy verification predicate; must not be {@code null}
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        delegate.setVerificationApproach(strategy);
    }

    /**
     * Returns the core verification predicate in use.
     *
     * @return the verification predicate
     */
    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return delegate.getVerificationCore();
    }

}
