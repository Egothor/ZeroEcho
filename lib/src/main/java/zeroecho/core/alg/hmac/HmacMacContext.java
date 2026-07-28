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
package zeroecho.core.alg.hmac;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.MacContext;
import zeroecho.core.tag.ByteVerificationStrategy;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Streaming HMAC context backed by the JCA {@link javax.crypto.Mac} API.
 *
 * <p>
 * {@code HmacMacContext} implements {@link MacContext} and integrates with the
 * {@link TagEngine} contract to support both production and verification in a
 * pull-based streaming pipeline. One instance is intended for one wrapped
 * stream.
 * </p>
 *
 * <h2>TagEngine contract</h2>
 * <ul>
 * <li><b>Produce mode</b> (no expected tag set): {@link #wrap(InputStream)}
 * returns a pass-through stream that emits the full body followed by the
 * computed MAC as a trailer.</li>
 * <li><b>Verify mode</b> (expected tag set): the stream emits only the body. At
 * EOF, the computed MAC is compared with the expected tag using the configured
 * verification approach set via
 * {@link #setVerificationApproach(VerificationBiPredicate)}. Decorators such as
 * {@link VerificationBiPredicate#getThrowOnMismatch()} or
 * {@link VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}
 * may be used to control error signaling.</li>
 * </ul>
 *
 * <h2>CryptoContext contract</h2>
 * <ul>
 * <li>{@link #algorithm()} returns the owning {@link CryptoAlgorithm}.</li>
 * <li>{@link #key()} returns the {@link javax.crypto.SecretKey} used for the
 * MAC.</li>
 * <li>{@link #close()} closes the active wrapped stream (idempotent).</li>
 * </ul>
 *
 * <h2>Verification approach</h2>
 * <p>
 * The core comparison strategy is provided by {@link #getVerificationCore()},
 * which by default returns a constant-time byte-array comparator
 * ({@link ByteVerificationStrategy}). If no explicit strategy is set,
 * {@link #wrap(InputStream)} applies that core strategy decorated with
 * {@code getThrowOnMismatch()} so that mismatches raise an exception at EOF.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This context is stateful and not thread-safe. After
 * {@link #wrap(InputStream)} has been called once, further calls are rejected.
 * </p>
 *
 * <h2>Usage example</h2>
 * <h3>Produce HMAC-SHA256 trailer</h3> <pre>
 * {@code
 * SecretKey key = session.keyBuilders().symmetric().generate("HMAC", HmacKeyGenSpec.sha256(256));
 * HmacMacContext ctx = new HmacMacContext(CryptoAlgorithms.require("HMAC"), key, "HmacSHA256");
 * try (InputStream in = ctx.wrap(new FileInputStream("data.bin"))) {
 *     in.transferTo(OutputStream.nullOutputStream()); // body then MAC trailer
 * }
 * }
 * </pre>
 *
 * <h3>Verify with explicit strategy</h3> <pre>
 * {@code
 * HmacMacContext ctx = new HmacMacContext(CryptoAlgorithms.require("HMAC"), key, "HmacSHA256");
 * ctx.setVerificationApproach(ctx.getVerificationCore().getThrowOnMismatch());
 * ctx.setExpectedTag(expectedTag);
 * try (InputStream in = ctx.wrap(new FileInputStream("body.bin"))) {
 *     in.transferTo(OutputStream.nullOutputStream()); // throws on mismatch at EOF
 * }
 * }
 * </pre>
 *
 * @since 1.0
 */
public final class HmacMacContext implements MacContext {
    private static final Logger LOG = Logger.getLogger(HmacMacContext.class.getName());

    private final CryptoAlgorithm algorithm;
    private final SecretKey key;
    private final String macName;
    private final int macLen; // length of MAC/tag in bytes

    // verification configuration (used when expectedTag is set)
    private byte[] expectedTag;
    private VerificationBiPredicate<byte[]> verificationStrategy;

    // lifecycle
    private boolean wrapped; // = false;
    private HmacStream activeStream;
    private boolean autoCloseActiveStream;

    /**
     * Constructs an HMAC context for the given algorithm and key.
     *
     * <p>
     * The constructor probes the MAC length by initializing a JCA {@link Mac}
     * instance with the given key.
     * </p>
     *
     * @param algorithm owning algorithm descriptor
     * @param key       JCA secret key for HMAC
     * @param macName   canonical MAC algorithm name (e.g., {@code "HmacSHA256"})
     * @throws NullPointerException     if any argument is {@code null}
     * @throws GeneralSecurityException if the algorithm cannot be initialized with
     *                                  the given key
     */
    public HmacMacContext(final CryptoAlgorithm algorithm, final SecretKey key, final String macName)
            throws GeneralSecurityException {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(key, "key");
        this.macName = Objects.requireNonNull(macName, "macName");
        Mac probe = Mac.getInstance(macName);
        probe.init(key);
        this.macLen = probe.getMacLength();
    }

    /**
     * Returns the algorithm descriptor associated with this context.
     *
     * @return owning algorithm
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key used for HMAC operations.
     *
     * @return JCA secret key
     */
    @Override
    public java.security.Key key() {
        return key;
    }

    /**
     * Closes the active wrapped stream, if any.
     *
     * <p>
     * Idempotent: multiple calls are safe. Any underlying I/O exceptions are
     * suppressed.
     * </p>
     */
    @Override
    public void close() {
        LOG.log(Level.INFO, "close");

        if (autoCloseActiveStream) {
            try {
                if (activeStream != null) {
                    activeStream.close();
                }
            } catch (IOException ignore) {
                LOG.log(Level.INFO, "exception ignored on close", ignore);
            }
        }
    }

    /**
     * Wraps an upstream input stream with HMAC computation.
     *
     * <p>
     * In produce mode, the returned stream emits the body followed by the computed
     * tag. In verify mode, it emits the body only and validates at EOF using the
     * configured verification approach (default: throw on mismatch).
     * </p>
     *
     * @param upstream input stream to wrap; must not be {@code null}
     * @return wrapped input stream
     * @throws IOException           if initialization fails
     * @throws IllegalStateException if this context has already been used
     * @throws NullPointerException  if {@code upstream} is {@code null}
     */
    @Override
    public InputStream wrap(final InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream");
        if (wrapped) {
            throw new IllegalStateException(
                    "This HmacMacContext instance was already used; create a new one per stream.");
        }
        wrapped = true;

        final Mac mac;
        try {
            mac = Mac.getInstance(macName);
            mac.init(key);
        } catch (GeneralSecurityException e) {
            throw new IOException("HMAC init failed for " + macName, e);
        }

        HmacStream s = new HmacStream(upstream, mac, macName, expectedTag, verifier());
        this.activeStream = s;
        return s;
    }

    /**
     * Returns the MAC tag length in bytes.
     *
     * @return tag length
     */
    @Override
    public int tagLength() {
        return macLen;
    }

    /**
     * Sets the expected tag for verification mode.
     *
     * <p>
     * Passing {@code null} clears verification and reverts to produce mode. The
     * value is copied defensively. If a wrapped stream is already active, the
     * expected tag of the underlying stream is updated as well.
     * </p>
     *
     * @param expected expected tag, or {@code null} to disable verification
     */
    @Override
    public void setExpectedTag(final byte[] expected) {
        this.expectedTag = (expected == null) ? null : Arrays.copyOf(expected, expected.length);

        if (activeStream != null) {
            activeStream.setExpectedTag(expected);
        }
    }

    /**
     * Sets the verification approach used in verify mode to compare the expected
     * and computed tags.
     *
     * <p>
     * If no strategy is set explicitly, the context will use
     * {@link #getVerificationCore()} decorated with
     * {@link VerificationBiPredicate#getThrowOnMismatch()} so that mismatches raise
     * an exception at EOF.
     * </p>
     *
     * @param strategy verification predicate; may be {@code null} to keep the
     *                 default
     */
    @Override
    public void setVerificationApproach(VerificationBiPredicate<byte[]> strategy) {
        verificationStrategy = strategy;
    }

    /**
     * Returns the core verification predicate for HMAC tags.
     *
     * <p>
     * The default core is a constant-time byte-array comparison implemented by
     * {@link ByteVerificationStrategy}. Callers may decorate it with
     * {@link VerificationBiPredicate#getThrowOnMismatch()} or
     * {@link VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}
     * depending on the desired reporting behavior.
     * </p>
     *
     * @return the base verification predicate (never {@code null})
     */
    @Override
    public VerificationBiPredicate<byte[]> getVerificationCore() {
        return new ByteVerificationStrategy();
    }

    /**
     * Selects the effective verification predicate: the user-supplied strategy if
     * present, otherwise the default core with throw-on-mismatch decoration.
     *
     * @return effective verification predicate
     */
    private VerificationBiPredicate<byte[]> verifier() {
        return verificationStrategy == null ? getVerificationCore().getThrowOnMismatch() : verificationStrategy;
    }
}
