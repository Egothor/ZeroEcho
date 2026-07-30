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
package zeroecho.core.alg.slhdsa;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Streaming signature context for SLH-DSA (FIPS 205).
 *
 * <p>
 * {@code SlhDsaSignatureContext} adapts a JCA {@link Signature} engine for use
 * within the ZeroEcho streaming signature infrastructure. It supports both
 * signing and verification and delegates the low-level mechanics to
 * {@link GenericJcaSignatureContext}.
 * </p>
 *
 * <h2>Provider and algorithm</h2>
 * <ul>
 * <li>JCA algorithm: {@code "SLH-DSA"}.</li>
 * <li>Provider: {@code "BC"} (Bouncy Castle core provider).</li>
 * </ul>
 *
 * <h2>Streaming contract</h2>
 * <ul>
 * <li><b>SIGN</b>: the wrapped stream emits the message body and appends a
 * detached signature trailer at EOF.</li>
 * <li><b>VERIFY</b>: the wrapped stream emits the body only; verification is
 * performed at EOF against a caller-supplied expected tag.</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>
 * This class never logs secrets, key material, plaintext, or signature bytes.
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaSignatureContext implements SignatureContext {

    private static final String ALG = "SLH-DSA";
    private static final String PROVIDER = "BC";

    private static final Pattern PARAM_PATTERN = Pattern
            .compile("^slh-dsa-(sha2|shake)-(128|192|256)([fs])(?:-with-[a-z0-9]+)?$");

    private final GenericJcaSignatureContext delegate;

    /**
     * Creates a signing context bound to a private key.
     *
     * <p>
     * The produced signature length is resolved by probing the JCA engine via
     * {@link GenericJcaSignatureContext.SignLengthResolver#probeWith(String, String)}.
     * </p>
     *
     * @param algorithm  the parent algorithm instance; must not be {@code null}
     * @param privateKey SLH-DSA private key; must not be {@code null}
     * @throws GeneralSecurityException if the JCA signature engine cannot be
     *                                  initialized
     */
    public SlhDsaSignatureContext(final CryptoAlgorithm algorithm, final PrivateKey privateKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, privateKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER),
                GenericJcaSignatureContext.SignLengthResolver.probeWith(ALG, PROVIDER));
    }

    /**
     * Creates a verification context bound to a public key.
     *
     * <p>
     * The expected signature length is derived from the public key parameter set
     * via {@link SLHDSAParameterSpec#getName()} and the canonical SLH-DSA sizes.
     * </p>
     *
     * @param algorithm the parent algorithm instance; must not be {@code null}
     * @param publicKey SLH-DSA public key; must not be {@code null}
     * @throws GeneralSecurityException if the key is invalid or the parameter set
     *                                  is unsupported
     */
    public SlhDsaSignatureContext(final CryptoAlgorithm algorithm, final PublicKey publicKey)
            throws GeneralSecurityException {
        this.delegate = new GenericJcaSignatureContext(algorithm, publicKey,
                GenericJcaSignatureContext.jcaFactory(ALG, PROVIDER), SlhDsaSignatureContext::sigLenFromPublicKey);
    }

    /**
     * Resolves the canonical SLH-DSA signature length (bytes) from a public key.
     *
     * <p>
     * The Bouncy Castle public key exposes an {@link SLHDSAParameterSpec} whose
     * {@linkplain SLHDSAParameterSpec#getName() name} encodes the family
     * (SHA2/SHAKE), security level (128/192/256) and variant (s/f). The resolver
     * normalizes the returned name to lowercase and replaces underscores with
     * hyphens to tolerate provider naming differences.
     * </p>
     *
     * @param pk SLH-DSA public key
     * @return signature length in bytes for the key's parameter set
     * @throws GeneralSecurityException if the key type or parameter specification
     *                                  is missing or unrecognized
     */
    private static int sigLenFromPublicKey(PublicKey pk) throws GeneralSecurityException {
        if (!(pk instanceof SLHDSAPublicKey slhPk)) {
            throw new GeneralSecurityException("Expected a BouncyCastle SLH-DSA public key (BC)");
        }
        SLHDSAParameterSpec ps = slhPk.getParameterSpec();
        if (ps == null) {
            throw new GeneralSecurityException("Missing SLH-DSA parameter spec on public key");
        }
        String name = ps.getName();
        if (name == null || name.isEmpty()) {
            throw new GeneralSecurityException("Unknown SLH-DSA parameter (no name)");
        }

        String normalized = name.toLowerCase(Locale.ROOT).replace('_', '-');

        Matcher m = PARAM_PATTERN.matcher(normalized);
        if (!m.matches()) {
            throw new GeneralSecurityException("Cannot parse SLH-DSA parameter from: " + name);
        }

        int level = Integer.parseInt(m.group(2));
        char var = m.group(3).charAt(0);
        boolean isSmall = var == 's';

        return switch (level) {
            case 128 -> isSmall ? 7_856 : 17_088;
            case 192 -> isSmall ? 16_224 : 35_664;
            case 256 -> isSmall ? 29_792 : 49_856;
            default -> throw new GeneralSecurityException("Unsupported SLH-DSA level: " + level);
        };
    }

    /**
     * Returns the parent {@link CryptoAlgorithm} associated with this context.
     *
     * @return the algorithm instance
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return delegate.algorithm();
    }

    /**
     * Returns the key bound to this context.
     *
     * @return signing {@link PrivateKey} or verification {@link PublicKey}
     */
    @Override
    public java.security.Key key() {
        return delegate.key();
    }

    /**
     * Closes this context and releases any underlying resources.
     *
     * <p>
     * Once closed, the context must not be reused.
     * </p>
     */
    @Override
    public void close() {
        delegate.close();
    }

    /**
     * Wraps an input stream such that bytes read from the returned stream update
     * the underlying signature engine.
     *
     * <p>
     * In SIGN mode, the wrapper appends the signature trailer at EOF. In VERIFY
     * mode, the wrapper compares the computed signature at EOF against the expected
     * tag configured via {@link #setExpectedTag(byte[])}.
     * </p>
     *
     * @param upstream input stream providing message bytes; must not be
     *                 {@code null}
     * @return wrapped stream that performs signing or verification as bytes are
     *         read
     * @throws IOException if wrapping fails
     */
    @Override
    public InputStream wrap(InputStream upstream) throws IOException {
        return delegate.wrap(upstream);
    }

    /**
     * Returns the signature (tag) length in bytes for the parameter set in use.
     *
     * @return signature length in bytes
     */
    @Override
    public int tagLength() {
        return delegate.tagLength();
    }

    /**
     * Supplies the expected signature (tag) for VERIFY mode.
     *
     * <p>
     * Implementations may defensively copy the provided array. Callers should treat
     * this value as sensitive and avoid logging or persisting it unless explicitly
     * required by the application.
     * </p>
     *
     * @param expected expected signature bytes; must not be {@code null}
     */
    @Override
    public void setExpectedTag(byte[] expected) {
        delegate.setExpectedTag(expected);
    }

    /**
     * Sets the verification approach used at EOF to compare the computed and
     * expected signatures.
     *
     * @param strategy verification predicate; must not be {@code null}
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<Signature> strategy) {
        delegate.setVerificationApproach(strategy);
    }

    /**
     * Returns the verification predicate core that can be used to select a
     * particular mismatch handling strategy (e.g., throw on mismatch).
     *
     * @return the verification predicate core
     */
    @Override
    public VerificationBiPredicate<Signature> getVerificationCore() {
        return delegate.getVerificationCore();
    }
}
