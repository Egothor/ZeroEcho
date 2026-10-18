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
package zeroecho.sdk.builders.alg;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKey;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.hmac.HmacKeyGenSpec;
import zeroecho.core.alg.hmac.HmacKeyImportSpec;
import zeroecho.core.alg.hmac.HmacSpec;
import zeroecho.core.context.MacContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * HmacDataContentBuilder constructs streaming pipelines that compute or verify
 * HMAC tags while an InputStream is consumed.
 *
 * <h2>Overview</h2> The builder produces
 * {@link zeroecho.sdk.content.api.PlainContent} that either passes the original
 * bytes through while computing or verifying an HMAC trailer, or emits only the
 * tag or a boolean verification result. The HMAC variant is selected via
 * {@link #spec(HmacSpec)} or convenience methods such as {@link #sha256()}.
 *
 * <h2>Modes and outputs</h2>
 * <ul>
 * <li>MAC mode: compute an HMAC over the incoming stream and either pass the
 * body through with the trailer stripped or emit the finalized tag in raw, hex,
 * or Base64 form.</li>
 * <li>VERIFY mode: verify an expected HMAC. The expected tag can be provided
 * directly or taken from the input trailer. The output can be pass-through of
 * the body or a textual boolean.</li>
 * </ul>
 *
 * <h2>Key handling</h2> Keys may be supplied directly, generated for the
 * configured MAC name, or imported from raw, hex, or Base64 text. If no key
 * material is provided, a default key suitable for the selected MAC is
 * generated.
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.MacContext
 * @see HmacSpec
 */
public final class HmacDataContentBuilder implements DataContentBuilder<PlainContent> {
    private static final String ALGORITHM_ID = "HMAC";
    private final ZeroEchoSession session;

    /**
     * Mode selects whether the pipeline computes an HMAC tag or verifies one.
     *
     * <p>
     * The active mode is set by {@link #mac()} or {@link #verify()} and governs how
     * the builder interprets the selected output. In {@code MAC} mode, the pipeline
     * produces or strips an HMAC trailer computed over the input. In {@code VERIFY}
     * mode, the pipeline checks an expected tag supplied explicitly or taken from
     * the input trailer.
     * </p>
     *
     * <h2>Typical flows</h2> <pre>{@code
     * // Compute HMAC and emit hex tag:
     * PlainContent c1 = HmacDataContentBuilder.builder()
     *     .mac()
     *     .sha256()
     *     .emitHexTag()
     *     .build(true);
     *
     * // Verify HMAC carried as input trailer and pass the body through:
     * PlainContent c2 = HmacDataContentBuilder.builder()
     *     .verify()
     *     .sha256()
     *     .passThrough()
     *     .build(true);
     * }</pre>
     *
     * @since 1.0
     */
    public enum Mode {
        /**
         * Compute an HMAC tag over the input stream.
         *
         * <p>
         * Use with {@link #passThrough()} to output the body while stripping the tag,
         * or with one of {@link #emitRawTag()}, {@link #emitHexTag()}, or
         * {@link #emitBase64Tag()} to output only the finalized tag.
         * </p>
         */
        MAC,
        /**
         * Verify an expected HMAC tag against the input stream.
         *
         * <p>
         * The expected tag can be provided via {@link #expectedTag(byte[])},
         * {@link #expectedTagHex(String)}, or {@link #expectedTagBase64(String)}. If no
         * expected tag is supplied, the pipeline reads it from the input trailer. Use
         * {@link #passThrough()} to output the body and throw on mismatch, or
         * {@link #emitVerificationBoolean()} to output a textual {@code "true"} or
         * {@code "false"} result.
         * </p>
         */
        VERIFY
    }

    /**
     * Out selects the concrete output representation produced by the pipeline.
     *
     * <p>
     * In {@link Mode#MAC} the {@code TAG_*} outputs emit only the computed tag and
     * {@link #PASSTHROUGH} emits the original body with the trailer stripped. In
     * {@link Mode#VERIFY}, {@link #VERIFY_BOOL} emits a textual boolean and
     * {@link #PASSTHROUGH} emits the body, throwing on mismatch. Any other
     * mode/output combination is rejected at build time.
     * </p>
     *
     * <h2>Mapping from builder methods</h2>
     * <ul>
     * <li>{@link #passThrough()} -&gt; {@code PASSTHROUGH}</li>
     * <li>{@link #emitRawTag()} -&gt; {@code TAG_RAW}</li>
     * <li>{@link #emitHexTag()} -&gt; {@code TAG_HEX}</li>
     * <li>{@link #emitBase64Tag()} -&gt; {@code TAG_BASE64}</li>
     * <li>{@link #emitVerificationBoolean()} -&gt; {@code VERIFY_BOOL}</li>
     * </ul>
     *
     * @since 1.0
     */
    private enum Out {
        /**
         * Pass-through body output.
         *
         * <p>
         * In {@link Mode#MAC}, the HMAC trailer produced by the engine is stripped and
         * the body is forwarded unchanged. In {@link Mode#VERIFY}, the body is
         * forwarded and verification is performed; a mismatch results in an exception
         * at EOF.
         * </p>
         */
        PASSTHROUGH,
        /**
         * Emit the finalized HMAC tag as raw bytes.
         *
         * <p>
         * Valid only with {@link Mode#MAC}.
         * </p>
         */
        TAG_RAW,
        /**
         * Emit the finalized HMAC tag as lowercase hexadecimal text.
         *
         * <p>
         * Valid only with {@link Mode#MAC}.
         * </p>
         */
        TAG_HEX,
        /**
         * Emit the finalized HMAC tag as Base64 text.
         *
         * <p>
         * Valid only with {@link Mode#MAC}.
         * </p>
         */
        TAG_BASE64,
        /**
         * Emit a textual boolean representing verification success.
         *
         * <p>
         * Outputs {@code "true"} when verification succeeds and {@code "false"} on
         * failure. Valid only with {@link Mode#VERIFY}.
         * </p>
         */
        VERIFY_BOOL
    }

    private static final int IO_BUF = 8192;

    private Mode mode = Mode.MAC;

    private HmacSpec spec = HmacSpec.sha256(); // default
    private SecretKey key;
    private Integer genKeyBits; // if set, generate for this spec.macName()

    private byte[] importRaw;
    private String importHex;
    private String importBase64;

    private byte[] expectedTag; // raw bytes
    private String expectedTagHex;
    private String expectedTagBase64;

    private Out out = Out.PASSTHROUGH;

    private HmacDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Creates a new builder for constructing HMAC computing or verifying pipelines.
     *
     * <h4>Example</h4> <pre>{@code
     * PlainContent pc = HmacDataContentBuilder.builder()
     *     .sha256()
     *     .emitHexTag()
     *     .build(true);
     * }</pre>
     *
     * @param session active session used to create cryptographic contexts
     * @return a new {@code HmacDataContentBuilder} instance
     */
    public static HmacDataContentBuilder builder(ZeroEchoSession session) {
        return new HmacDataContentBuilder(session);
    }

    /**
     * Returns the currently configured HMAC specification.
     *
     * <p>
     * This accessor is intentionally read-only and exists to support safe
     * integrations (for example hybrid-derived key injection) without duplicating
     * the HMAC variant configuration outside of this builder.
     * </p>
     *
     * @return current HMAC spec (never null)
     * @since 1.0
     */
    public HmacSpec spec() {
        return this.spec;
    }

    /**
     * Returns a recommended HMAC key size (in bits) for the currently configured
     * {@link #spec()}.
     *
     * <p>
     * This is a convenience forwarding method to
     * {@link HmacSpec#recommendedKeyBits()} and is intended as the default choice
     * for derived-key integrations. Callers that intentionally need a non-default
     * size may override it explicitly.
     * </p>
     *
     * @return recommended key size in bits (positive, multiple of 8)
     * @since 1.0
     */
    public int recommendedKeyBits() {
        return this.spec.recommendedKeyBits();
    }

    /**
     * Switches the builder to MAC mode.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder mac() {
        this.mode = Mode.MAC;
        return this;
    }

    /**
     * Switches the builder to VERIFY mode.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder verify() {
        this.mode = Mode.VERIFY;
        return this;
    }

    /**
     * Sets the HMAC specification to use for this pipeline.
     *
     * @param s the HMAC spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code s} is null
     */
    public HmacDataContentBuilder spec(HmacSpec s) {
        this.spec = Objects.requireNonNull(s);
        return this;
    }

    /**
     * Selects HmacSHA256.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder sha256() {
        return spec(HmacSpec.sha256());
    }

    /**
     * Selects HmacSHA384.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder sha384() {
        return spec(HmacSpec.sha384());
    }

    /**
     * Selects HmacSHA512.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder sha512() {
        return spec(HmacSpec.sha512());
    }

    /**
     * Supplies an explicit secret key for the HMAC operation.
     *
     * <p>
     * Calling this clears any prior key generation or import configuration.
     * </p>
     *
     * @param k the secret key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public HmacDataContentBuilder withKey(SecretKey k) {
        this.key = Objects.requireNonNull(k);
        this.genKeyBits = null;
        this.importRaw = null;
        this.importHex = null;
        this.importBase64 = null;
        return this;
    }

    /**
     * Requests generation of a new secret key sized for the configured MAC.
     *
     * <p>
     * The key is generated for the MAC name returned by {@link HmacSpec#macName()}.
     * </p>
     *
     * @param bits desired key length in bits
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder generateKey(int bits) {
        this.genKeyBits = bits;
        this.key = null;
        this.importRaw = null;
        this.importHex = null;
        this.importBase64 = null;
        return this;
    }

    /**
     * Imports a secret key from raw bytes.
     *
     * <p>
     * Calling this clears any prior explicit key or generation request.
     * </p>
     *
     * @param raw the raw key bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code raw} is null
     */
    public HmacDataContentBuilder importKeyRaw(byte[] raw) {
        this.importRaw = Objects.requireNonNull(raw).clone();
        this.key = null;
        this.genKeyBits = null;
        return this;
    }

    /**
     * Imports a secret key from a hexadecimal string.
     *
     * <p>
     * Calling this clears any prior explicit key or generation request.
     * </p>
     *
     * @param hex hex-encoded key text; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if {@code hex} is not valid hexadecimal
     */
    public HmacDataContentBuilder importKeyHex(String hex) {
        this.importHex = Objects.requireNonNull(hex);
        this.key = null;
        this.genKeyBits = null;
        return this;
    }

    /**
     * Imports a secret key from a Base64 string.
     *
     * <p>
     * Calling this clears any prior explicit key or generation request.
     * </p>
     *
     * @param b64 Base64-encoded key text; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if {@code b64} is not valid Base64
     */
    public HmacDataContentBuilder importKeyBase64(String b64) {
        this.importBase64 = Objects.requireNonNull(b64);
        this.key = null;
        this.genKeyBits = null;
        return this;
    }

    /**
     * Configures the pipeline to pass the input body through unchanged and strip
     * the engine's trailer.
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder passThrough() {
        this.out = Out.PASSTHROUGH;
        return this;
    }

    /**
     * Configures the pipeline to emit the finalized HMAC tag as raw bytes.
     *
     * <p>
     * Switches the mode to {@link Mode#MAC}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder emitRawTag() {
        this.mode = Mode.MAC;
        this.out = Out.TAG_RAW;
        return this;
    }

    /**
     * Configures the pipeline to emit the finalized HMAC tag as lowercase
     * hexadecimal text.
     *
     * <p>
     * Switches the mode to {@link Mode#MAC}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder emitHexTag() {
        this.mode = Mode.MAC;
        this.out = Out.TAG_HEX;
        return this;
    }

    /**
     * Configures the pipeline to emit the finalized HMAC tag as Base64 text.
     *
     * <p>
     * Switches the mode to {@link Mode#MAC}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder emitBase64Tag() {
        this.mode = Mode.MAC;
        this.out = Out.TAG_BASE64;
        return this;
    }

    /**
     * Configures the pipeline to verify and emit a textual boolean result.
     *
     * <p>
     * Switches the mode to {@link Mode#VERIFY}.
     * </p>
     *
     * @return {@code this} builder for chaining
     */
    public HmacDataContentBuilder emitVerificationBoolean() {
        this.mode = Mode.VERIFY;
        this.out = Out.VERIFY_BOOL;
        return this;
    }

    /**
     * Supplies the expected HMAC tag as raw bytes for verification.
     *
     * <p>
     * Providing a value here clears any prior hex or Base64 expected tag.
     * </p>
     *
     * @param raw the expected tag bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code raw} is null
     */
    public HmacDataContentBuilder expectedTag(byte[] raw) {
        this.expectedTag = Objects.requireNonNull(raw).clone();
        this.expectedTagHex = null;
        this.expectedTagBase64 = null;
        return this;
    }

    /**
     * Supplies the expected HMAC tag as a hexadecimal string for verification.
     *
     * <p>
     * Providing a value here clears any prior raw or Base64 expected tag.
     * </p>
     *
     * @param hex the expected tag in hexadecimal; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if {@code hex} is not valid hexadecimal
     */
    public HmacDataContentBuilder expectedTagHex(String hex) {
        this.expectedTagHex = Objects.requireNonNull(hex);
        this.expectedTag = null;
        this.expectedTagBase64 = null;
        return this;
    }

    /**
     * Supplies the expected HMAC tag as a Base64 string for verification.
     *
     * <p>
     * Providing a value here clears any prior raw or hex expected tag.
     * </p>
     *
     * @param b64 the expected tag in Base64; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if {@code b64} is not valid Base64
     */
    public HmacDataContentBuilder expectedTagBase64(String b64) {
        this.expectedTagBase64 = Objects.requireNonNull(b64);
        this.expectedTag = null;
        this.expectedTagHex = null;
        return this;
    }

    /**
     * Builds a digesting or verifying {@link PlainContent} pipeline according to
     * the current configuration.
     *
     * <p>
     * The boolean parameter is ignored and exists only to satisfy the
     * {@link zeroecho.sdk.builders.core.DataContentBuilder} interface. The actual
     * behavior is controlled by {@link #mac()} or {@link #verify()} and the
     * selected output.
     * </p>
     *
     * <h4>Result</h4>
     * <ul>
     * <li>MAC mode: returns a pass-through content or a tag-emitting content based
     * on {@link #passThrough()}, {@link #emitRawTag()}, {@link #emitHexTag()}, or
     * {@link #emitBase64Tag()}.</li>
     * <li>VERIFY mode: returns a pass-through content that throws on mismatch or an
     * emitter of "true"/"false" based on {@link #emitVerificationBoolean()}.</li>
     * </ul>
     *
     * @param ignoredEncryptFlag unused parameter from the interface
     * @return a {@link PlainContent} pipeline performing the configured HMAC
     *         operation
     * @throws IllegalStateException if an invalid mode/output combination is
     *                               selected or key construction fails
     */
    @Override
    public PlainContent build(boolean ignoredEncryptFlag) {
        final SecretKey secret = resolveKey();

        return switch (mode) {
            case MAC -> switch (out) {
                case PASSTHROUGH -> new MacPassThrough(secret, spec);
                case TAG_RAW, TAG_HEX, TAG_BASE64 -> new MacEmit(secret, spec, out);
                default -> throw new IllegalStateException("Invalid output for MAC: " + out);
            };
            case VERIFY -> switch (out) {
                case PASSTHROUGH ->
                    new VerifyPassThrough(secret, spec, decodeExpected(expectedTag, expectedTagHex, expectedTagBase64));
                case VERIFY_BOOL ->
                    new VerifyEmit(secret, spec, decodeExpected(expectedTag, expectedTagHex, expectedTagBase64));
                default -> throw new IllegalStateException("Invalid output for VERIFY: " + out);
            };
        };
    }

    private SecretKey resolveKey() {
        if (key != null) {
            return key;
        }
        final String mac = spec.macName(); // e.g., "HmacSHA256"
        try {
            if (genKeyBits != null) {
                return session.keyBuilders().symmetric().generate(ALGORITHM_ID, new HmacKeyGenSpec(mac, genKeyBits));
            }
            if (importRaw != null || importHex != null || importBase64 != null) {
                HmacKeyImportSpec ispec;
                if (importRaw != null) {
                    ispec = HmacKeyImportSpec.fromRaw(mac, importRaw);
                } else if (importHex != null) {
                    ispec = HmacKeyImportSpec.fromHex(mac, importHex);
                } else {
                    ispec = HmacKeyImportSpec.fromBase64(mac, importBase64);
                }
                return session.keyBuilders().symmetric().importKey(ALGORITHM_ID, ispec);
            }
            // default keygen if nothing provided
            return session.keyBuilders().symmetric().generate(ALGORITHM_ID, HmacKeyGenSpec.sha256(256));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC key construction failed", e);
        }
    }

    private static byte[] decodeExpected(byte[] raw, String hex, String b64) {
        if (raw != null) {
            return raw.clone();
        }
        if (hex != null) {
            return java.util.HexFormat.of().parseHex(hex);
        }
        if (b64 != null) {
            return Base64.getDecoder().decode(b64);
        }
        return null; // NOPMD means: expect the tag to be present as a trailer in the input stream
    }

    /**
     * MAC + pass-through: return body only (trailer stripped).
     */
    private final class MacPassThrough implements PlainContent {
        private final SecretKey key;
        private final HmacSpec spec;

        private DataContent upstream;

        private MacPassThrough(SecretKey key, HmacSpec spec) {
            this.key = key;
            this.spec = spec;
        }

        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "mac: missing input");
            final MacContext m = session.createContext(ALGORITHM_ID, KeyUsage.MAC, key, spec); // HmacMacContext
            final InputStream produced = m.wrap(upstream.getStream()); // emits [body][tag]
            final int tagLen = m.tagLength();
            return withContextClose(new TailStrippingInputStream(produced, tagLen, IO_BUF) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    /* drop */ }
            }, m);
        }
    }

    /**
     * MAC + emit tag (raw/hex/base64).
     */
    private final class MacEmit implements PlainContent {
        private final SecretKey key;
        private final HmacSpec spec;
        private final Out out;
        private DataContent upstream;

        private MacEmit(SecretKey key, HmacSpec spec, Out out) {
            if (out != Out.TAG_RAW && out != Out.TAG_HEX && out != Out.TAG_BASE64) {
                throw new IllegalArgumentException("MacEmit requires TAG_* output");
            }
            this.key = key;
            this.spec = spec;
            this.out = out;
        }

        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "mac: missing input");

            final byte[][] holder = new byte[1][];
            try (MacContext m = session.createContext(ALGORITHM_ID, KeyUsage.MAC, key, spec)) {
                final int tagLen = m.tagLength();
                try (InputStream in = new TailStrippingInputStream(m.wrap(upstream.getStream()), tagLen, IO_BUF) {
                    @Override
                    protected void processTail(byte[] tail) throws IOException {
                        holder[0] = (tail == null ? null : tail.clone());
                    }
                }) {
                    byte[] buf = new byte[8192];
                    while (true) {
                        int n = in.read(buf);
                        if (n < 0) {
                            break;
                        }
                    }
                }
            }

            byte[] tag = holder[0];
            if (tag == null) {
                tag = new byte[0];
            }

            byte[] outBytes;
            switch (out) {
                case TAG_RAW:
                    outBytes = tag;
                    break;
                case TAG_HEX:
                    outBytes = java.util.HexFormat.of().formatHex(tag).getBytes(StandardCharsets.UTF_8);
                    break;
                case TAG_BASE64:
                    outBytes = Base64.getEncoder().encode(tag);
                    break;
                default:
                    throw new IllegalStateException("Unexpected TAG output: " + out);
            }
            return new ByteArrayInputStream(outBytes);
        }
    }

    /**
     * VERIFY + pass-through: - If expected tag provided: verify against it. - Else:
     * read expected from the input trailer (and strip it). Returns body only;
     * throws on mismatch.
     */
    private final class VerifyPassThrough implements PlainContent {
        private final SecretKey key;
        private final HmacSpec spec;
        private final byte[] expectedOrNull;

        private DataContent upstream;

        private VerifyPassThrough(SecretKey key, HmacSpec spec, byte[] expectedOrNull) {
            this.key = key;
            this.spec = spec;
            this.expectedOrNull = (expectedOrNull == null) ? null : expectedOrNull.clone();
        }

        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "verify: missing input");

            final MacContext m = session.createContext(ALGORITHM_ID, KeyUsage.MAC, key, spec);

            final InputStream body;
            if (expectedOrNull != null) {
                // expected supplied by caller; body is the upstream as-is
                m.setExpectedTag(expectedOrNull);
                body = m.wrap(upstream.getStream());
            } else {
                // expected is the input trailer; strip it and feed body to the engine
                final int tagLen = m.tagLength();
                InputStream bodyOnly = new TailStrippingInputStream(upstream.getStream(), tagLen, IO_BUF) { // NOPMD
                    @Override
                    protected void processTail(byte[] tail) throws IOException {
                        m.setExpectedTag(tail == null ? null : tail.clone());
                    }
                };
                body = m.wrap(bodyOnly);
            }

            // Engine will throw on mismatch at EOF (THROW_ON_MISMATCH by default).
            return withContextClose(body, m);
        }
    }

    /**
     * VERIFY + emit boolean ("true"/"false").
     */
    private final class VerifyEmit implements PlainContent {
        private final SecretKey key;
        private final HmacSpec spec;
        private final byte[] expectedOrNull;

        private DataContent upstream;

        private VerifyEmit(SecretKey key, HmacSpec spec, byte[] expectedOrNull) {
            this.key = key;
            this.spec = spec;
            this.expectedOrNull = (expectedOrNull == null) ? null : expectedOrNull.clone();
        }

        @Override
        public void setInput(DataContent input) {
            this.upstream = Objects.requireNonNull(input);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "verify: missing input");

            boolean ok;
            try (MacContext m = session.createContext(ALGORITHM_ID, KeyUsage.MAC, key, spec)) {
                if (expectedOrNull != null) {
                    m.setExpectedTag(expectedOrNull);
                    try (InputStream in = m.wrap(upstream.getStream())) {
                        byte[] buf = new byte[8192];
                        while (true) {
                            int n = in.read(buf);
                            if (n < 0) {
                                break;
                            }
                        }
                    }
                } else {
                    final int tagLen = m.tagLength();
                    try (InputStream in = m.wrap(new TailStrippingInputStream(upstream.getStream(), tagLen, IO_BUF) {
                        @Override
                        protected void processTail(byte[] tail) throws IOException {
                            m.setExpectedTag(tail == null ? null : tail.clone());
                        }
                    })) {
                        byte[] buf = new byte[8192];
                        while (true) {
                            int n = in.read(buf);
                            if (n < 0) {
                                break;
                            }
                        }
                    }
                }
                ok = true; // no exception thrown by engine → verified OK
            } catch (IOException fail) {
                ok = false;
            }

            byte[] out = ok ? "true".getBytes(StandardCharsets.UTF_8) : "false".getBytes(StandardCharsets.UTF_8);
            return new ByteArrayInputStream(out);
        }
    }

    private static InputStream withContextClose(final InputStream in, final MacContext ctx) {
        return new FilterInputStream(in) {
            @Override
            public void close() throws IOException {
                try (ctx) {
                    super.close();
                }
            }
        };
    }
}
