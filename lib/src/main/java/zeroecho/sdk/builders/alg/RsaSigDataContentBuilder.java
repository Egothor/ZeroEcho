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
package zeroecho.sdk.builders.alg;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Consumer;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.alg.rsa.RsaSigSpec;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * RsaSigDataContentBuilder builds streaming RSA signature pipelines that sign
 * or verify as an InputStream is consumed.
 *
 * <h2>Overview</h2> The builder produces
 * {@link zeroecho.sdk.content.api.PlainContent} that either passes the original
 * bytes through while appending or checking a detached signature trailer, or
 * emits only the signature or a boolean verification result. The signature
 * variant (PKCS#1 v1.5 or PSS) is configured via {@link #spec(RsaSigSpec)},
 * {@link #pkcs1v15(RsaSigSpec.Hash)}, or {@link #pss(RsaSigSpec.Hash, int)}.
 * Keys may be supplied, generated, or imported from standard encodings.
 *
 * <h2>Usage examples</h2> <pre>{@code
 * // Sign while passing the body through; capture signature via callback:
 * PlainContent sign = RsaSigDataContentBuilder.builder()
 *     .pss(RsaSigSpec.Hash.SHA256, 32)
 *     .withPrivateKey(priv)
 *     .onSignature(sig -> System.out.println(sig.length))
 *     .passThrough()
 *     .sign()
 *     .build(true);
 *
 * // Emit a Base64 detached signature:
 * PlainContent sigOnly = RsaSigDataContentBuilder.builder()
 *     .pkcs1v15(RsaSigSpec.Hash.SHA512)
 *     .withPrivateKey(priv)
 *     .emitBase64Signature()
 *     .build(true);
 *
 * // Verify against an expected signature and emit "true"/"false":
 * PlainContent verdict = RsaSigDataContentBuilder.builder()
 *     .withPublicKey(pub)
 *     .pss(RsaSigSpec.Hash.SHA256, 32)
 *     .expectedSignatureBase64(b64)
 *     .emitVerificationBoolean()
 *     .build(true);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are mutable and not thread-safe. Configure
 * and use each builder instance from a single thread.
 *
 * @see zeroecho.sdk.builders.core.DataContentBuilder
 * @see zeroecho.core.CryptoAlgorithms
 * @see zeroecho.core.context.SignatureContext
 * @see RsaSigSpec
 * @see RsaKeyGenSpec
 */
public final class RsaSigDataContentBuilder implements DataContentBuilder<PlainContent> {
    private static final String ALGORITHM_ID = "RSA";
    private final ZeroEchoSession session;

    /**
     * Mode selects whether the builder signs or verifies.
     */
    public enum Mode {
        /**
         * Sign mode produces an RSA signature over the input stream.
         */
        SIGN,
        /**
         * Verify mode checks an RSA signature against the input stream.
         */
        VERIFY
    }

    /**
     * Output selector controlling what the pipeline produces after processing the
     * body.
     *
     * <h2>Semantics</h2>
     * <ul>
     * <li>{@link #PASSTHROUGH}: return only the input body; in sign mode the
     * signature is consumed as a trailer (optionally delivered via callback); in
     * verify mode the expected signature is checked and a mismatch throws.</li>
     * <li>{@link #SIG_RAW}/{@link #SIG_HEX}/{@link #SIG_BASE64}: sign mode only;
     * return the finalized signature bytes encoded as specified. The input body is
     * consumed but not returned.</li>
     * <li>{@link #VERIFY_BOOL}: verify mode only; return either {@code "true"} or
     * {@code "false"} after consuming the input body, without throwing on
     * mismatch.</li>
     * </ul>
     *
     * <p>
     * Selecting a signature-emitting option implicitly sets {@link Mode#SIGN}.
     * Selecting {@link #VERIFY_BOOL} implicitly sets {@link Mode#VERIFY}.
     * </p>
     */
    private enum Out {
        /**
         * Return only the input body. Sign: the signature trailer is stripped; Verify:
         * throws on mismatch.
         */
        PASSTHROUGH,
        /**
         * Emit the computed signature as raw bytes (sign mode only).
         */
        SIG_RAW,
        /**
         * Emit the computed signature as lowercase hexadecimal text (sign mode only).
         */
        SIG_HEX,
        /**
         * Emit the computed signature as Base64 text (sign mode only).
         */
        SIG_BASE64,
        /**
         * Emit a textual boolean result: {@code "true"} on success, {@code "false"} on
         * failure (verify mode only).
         */
        VERIFY_BOOL
    }

    private static final int IO_BUF = 8192;

    private Mode mode = Mode.SIGN;
    private RsaSigSpec spec = RsaSigSpec.pss(RsaSigSpec.Hash.SHA256, 32); // default (PSS, salt 32)

    private PrivateKey privateKey;
    private PublicKey publicKey;

    private boolean genKeyPair;
    private RsaKeyGenSpec keyGen = RsaKeyGenSpec.rsa2048();
    private byte[] importPrivatePkcs8;
    private byte[] importPublicX509;

    private byte[] expected; // verify input (raw)
    private Out out = Out.PASSTHROUGH;

    private Consumer<byte[]> onSignature;
    private Consumer<Boolean> onVerified;

    private RsaSigDataContentBuilder(ZeroEchoSession session) {
        this.session = Objects.requireNonNull(session, "session must not be null");
    }

    /**
     * Creates a new builder for constructing RSA signing or verification pipelines.
     *
     * <pre>{@code
     * RsaSigDataContentBuilder b = RsaSigDataContentBuilder.builder();
     * }</pre>
     *
     * @param session active session used to create cryptographic contexts
     * @return a new {@code RsaSigDataContentBuilder} instance
     */
    public static RsaSigDataContentBuilder builder(ZeroEchoSession session) {
        return new RsaSigDataContentBuilder(session);
    }

    /**
     * Switches the builder to sign mode.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder sign() {
        this.mode = Mode.SIGN;
        return this;
    }

    /**
     * Switches the builder to verify mode.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder verify() {
        this.mode = Mode.VERIFY;
        return this;
    }

    /**
     * Configures the pipeline to pass the input body through unchanged while
     * appending or checking a trailer.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder passThrough() {
        this.out = Out.PASSTHROUGH;
        return this;
    }

    /**
     * Configures sign mode to emit the finalized signature as raw bytes.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder emitRawSignature() {
        this.mode = Mode.SIGN;
        this.out = Out.SIG_RAW;
        return this;
    }

    /**
     * Configures sign mode to emit the finalized signature as lowercase hexadecimal
     * text.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder emitHexSignature() {
        this.mode = Mode.SIGN;
        this.out = Out.SIG_HEX;
        return this;
    }

    /**
     * Configures sign mode to emit the finalized signature as Base64 text.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder emitBase64Signature() {
        this.mode = Mode.SIGN;
        this.out = Out.SIG_BASE64;
        return this;
    }

    /**
     * Configures verify mode to emit a textual boolean result.
     *
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder emitVerificationBoolean() {
        this.mode = Mode.VERIFY;
        this.out = Out.VERIFY_BOOL;
        return this;
    }

    /**
     * Sets the RSA signature specification, including padding mode and hash
     * options.
     *
     * @param s the RSA signature spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code s} is null
     */
    public RsaSigDataContentBuilder spec(RsaSigSpec s) {
        this.spec = Objects.requireNonNull(s);
        return this;
    }

    /**
     * Selects the PKCS#1 v1.5 signature scheme with the given hash function.
     *
     * @param h the hash function to use
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code h} is null
     */
    public RsaSigDataContentBuilder pkcs1v15(RsaSigSpec.Hash h) {
        this.spec = RsaSigSpec.pkcs1v15(h);
        return this;
    }

    /**
     * Selects the RSASSA-PSS signature scheme with the given hash function and salt
     * length.
     *
     * @param h       the hash function to use for both message hash and MGF1
     * @param saltLen the salt length in bytes
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder pss(RsaSigSpec.Hash h, int saltLen) {
        this.spec = RsaSigSpec.pss(h, saltLen);
        return this;
    }

    /**
     * Supplies the private key to use for signing.
     *
     * @param k the private key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public RsaSigDataContentBuilder withPrivateKey(PrivateKey k) {
        this.privateKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Supplies the public key to use for verification.
     *
     * @param k the public key; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code k} is null
     */
    public RsaSigDataContentBuilder withPublicKey(PublicKey k) {
        this.publicKey = Objects.requireNonNull(k);
        return this;
    }

    /**
     * Requests generation of a fresh RSA key pair with the provided key generation
     * specification.
     *
     * @param spec the RSA key generation spec; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code spec} is null
     */
    public RsaSigDataContentBuilder generateKeyPair(RsaKeyGenSpec spec) {
        this.genKeyPair = true;
        this.keyGen = Objects.requireNonNull(spec);
        return this;
    }

    /**
     * Imports a private key from PKCS#8-encoded bytes.
     *
     * @param pkcs8 PKCS#8 PrivateKeyInfo bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code pkcs8} is null
     */
    public RsaSigDataContentBuilder importPrivatePkcs8(byte[] pkcs8) {
        this.importPrivatePkcs8 = Objects.requireNonNull(pkcs8).clone();
        return this;
    }

    /**
     * Imports a public key from X.509 SubjectPublicKeyInfo bytes.
     *
     * @param x509 X.509 public key bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code x509} is null
     */
    public RsaSigDataContentBuilder importPublicX509(byte[] x509) {
        this.importPublicX509 = Objects.requireNonNull(x509).clone();
        return this;
    }

    /**
     * Supplies the expected signature as raw bytes for verification.
     *
     * @param raw the expected signature bytes; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException if {@code raw} is null
     */
    public RsaSigDataContentBuilder expectedSignature(byte[] raw) {
        this.expected = Objects.requireNonNull(raw).clone();
        return this;
    }

    /**
     * Supplies the expected signature as a hexadecimal string for verification.
     *
     * @param hex the expected signature in hexadecimal; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if {@code hex} is not valid hexadecimal
     */
    public RsaSigDataContentBuilder expectedSignatureHex(String hex) {
        this.expected = java.util.HexFormat.of().parseHex(Objects.requireNonNull(hex));
        return this;
    }

    /**
     * Supplies the expected signature as a Base64 string for verification.
     *
     * @param b64 the expected signature in Base64; must not be null
     * @return {@code this} builder for chaining
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if {@code b64} is not valid Base64
     */
    public RsaSigDataContentBuilder expectedSignatureBase64(String b64) {
        this.expected = Base64.getDecoder().decode(Objects.requireNonNull(b64));
        return this;
    }

    /**
     * Registers a callback that receives a defensive copy of the finalized
     * signature bytes in sign mode.
     *
     * @param cb the callback to invoke; may be null to clear
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder onSignature(Consumer<byte[]> cb) {
        this.onSignature = cb;
        return this;
    }

    /**
     * Registers a callback that receives the verification result in verify mode.
     *
     * @param cb the callback to invoke with {@code true} on success and
     *           {@code false} on failure; may be null to clear
     * @return {@code this} builder for chaining
     */
    public RsaSigDataContentBuilder onVerified(Consumer<Boolean> cb) {
        this.onVerified = cb;
        return this;
    }

    /**
     * Builds a streaming signing or verification pipeline according to the current
     * configuration.
     *
     * <p>
     * The boolean parameter is ignored and exists only to satisfy the
     * {@link zeroecho.sdk.builders.core.DataContentBuilder} interface; behavior is
     * determined by {@link #sign()} or {@link #verify()} and the selected output.
     * </p>
     *
     * <h4>Result</h4>
     * <ul>
     * <li>Sign mode: returns pass-through content that strips the trailer and
     * optionally invokes {@link #onSignature(Consumer)} or an emitter of the
     * signature in raw, hex, or Base64.</li>
     * <li>Verify mode: returns pass-through content that throws on mismatch and can
     * invoke {@link #onVerified(Consumer)}, or an emitter of "true"/"false".</li>
     * </ul>
     *
     * @param ignored ignored parameter from the interface
     * @return a {@link zeroecho.sdk.content.api.PlainContent} pipeline performing
     *         the configured RSA signature operation
     * @throws IllegalStateException if required key material is missing or key
     *                               setup fails
     */
    @Override
    public PlainContent build(boolean ignored) {
        try {
            resolveKeys();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("RSA key setup failed", e);
        }
        switch (mode) {
            case SIGN:
                if (privateKey == null) {
                    throw new IllegalStateException("SIGN requires a PrivateKey");
                }
                return (out == Out.PASSTHROUGH) ? new SignPass(privateKey, spec, onSignature)
                        : new SignEmit(privateKey, spec, out);
            case VERIFY:
                if (publicKey == null) {
                    throw new IllegalStateException("VERIFY requires a PublicKey");
                }
                return (out == Out.VERIFY_BOOL) ? new VerifyEmit(publicKey, spec, expected, onVerified)
                        : new VerifyPass(publicKey, spec, expected, onVerified);
        }
        throw new IllegalStateException("Unsupported mode: " + mode);
    }

    private void resolveKeys() throws GeneralSecurityException {
        if (genKeyPair) {
            KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair(ALGORITHM_ID, keyGen);
            this.privateKey = kp.getPrivate();
            this.publicKey = kp.getPublic();
        }
        if (importPrivatePkcs8 != null) {
            this.privateKey = session.keyBuilders().asymmetric().importPrivate(ALGORITHM_ID,
                    new RsaPrivateKeySpec(importPrivatePkcs8));
        }
        if (importPublicX509 != null) {
            this.publicKey = session.keyBuilders().asymmetric().importPublic(ALGORITHM_ID,
                    new RsaPublicKeySpec(importPublicX509));
        }
    }

    /**
     * SIGN + pass-through: return body only; capture signature from trailer.
     */
    private final class SignPass implements PlainContent {
        private final PrivateKey key;
        private final RsaSigSpec spec;
        private final Consumer<byte[]> cb;
        private DataContent upstream;

        private SignPass(PrivateKey k, RsaSigSpec s, Consumer<byte[]> cb) {
            this.key = k;
            this.spec = s;
            this.cb = cb;
        }

        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "rsa sign: upstream not set");

            SignatureContext sc = session.createContext(ALGORITHM_ID, KeyUsage.SIGN, key, spec);
            final InputStream produced = sc.wrap(upstream.getStream()); // NOPMD emits [body][signature]
            final int sigLen = sc.tagLength();

            InputStream stripped = new TailStrippingInputStream(produced, sigLen, IO_BUF) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    if (cb != null && tail != null) {
                        try {
                            cb.accept(tail.clone());
                        } catch (RuntimeException ignore) { // NOPMD

                        }
                    }
                }
            };
            return withContextClose(stripped, sc);
        }
    }

    /**
     * SIGN + emit-only (raw/hex/base64).
     */
    private final class SignEmit implements PlainContent {
        private final PrivateKey key;
        private final RsaSigSpec spec;
        private final Out out;
        private DataContent upstream;

        private SignEmit(PrivateKey k, RsaSigSpec s, Out o) {
            if (o == Out.PASSTHROUGH || o == Out.VERIFY_BOOL) {
                throw new IllegalArgumentException("Emit mode requires SIG_* output");
            }
            this.key = k;
            this.spec = s;
            this.out = o;
        }

        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "rsa sign: upstream not set");

            final byte[][] sigHolder = new byte[1][];
            try (SignatureContext sc = session.createContext(ALGORITHM_ID, KeyUsage.SIGN, key, spec)) {
                final int sigLen = sc.tagLength();

                try (InputStream in = new TailStrippingInputStream(sc.wrap(upstream.getStream()), sigLen, IO_BUF) {
                    @Override
                    protected void processTail(byte[] tail) throws IOException {
                        sigHolder[0] = (tail == null ? null : tail.clone());
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

            byte[] sig = sigHolder[0];
            if (sig == null) {
                sig = new byte[0];
            }

            byte[] outBytes = switch (out) {
                case SIG_RAW -> sig;
                case SIG_HEX -> java.util.HexFormat.of().formatHex(sig).getBytes(StandardCharsets.UTF_8);
                case SIG_BASE64 -> Base64.getEncoder().encode(sig);
                default -> throw new IllegalStateException("Unexpected output: " + out);
            };
            return new ByteArrayInputStream(outBytes);
        }
    }

    /**
     * VERIFY + pass-through: verify against expected; return body (throws on
     * mismatch).
     */
    private final class VerifyPass implements PlainContent {
        private final PublicKey key;
        private final RsaSigSpec spec;
        private final byte[] expected;
        private final Consumer<Boolean> cb;
        private DataContent upstream;

        private VerifyPass(PublicKey k, RsaSigSpec s, byte[] exp, Consumer<Boolean> cb) {
            this.key = k;
            this.spec = s;
            this.expected = (exp == null ? null : exp.clone());
            this.cb = cb;
        }

        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "rsa verify: upstream not set");
            if (expected == null) {
                throw new IllegalStateException("VERIFY requires expectedSignature(...)");
            }
            SignatureContext sc = session.createContext(ALGORITHM_ID, KeyUsage.VERIFY, key, spec);
            sc.setExpectedTag(expected);
            InputStream body = sc.wrap(upstream.getStream()); // throws at EOF on mismatch

            if (cb != null) {
                body = new EofCallbackInputStream(body, new Runnable() {
                    @Override
                    public void run() {
                        try {
                            cb.accept(Boolean.TRUE);
                        } catch (RuntimeException ignore) { // NOPMD
                        }
                    }
                });
            }
            return withContextClose(body, sc);
        }
    }

    /**
     * VERIFY + emit boolean ("true"/"false").
     */
    private final class VerifyEmit implements PlainContent {
        private final PublicKey key;
        private final RsaSigSpec spec;
        private final byte[] expected;
        private final Consumer<Boolean> cb;
        private DataContent upstream;

        private VerifyEmit(PublicKey k, RsaSigSpec s, byte[] exp, Consumer<Boolean> cb) {
            this.key = k;
            this.spec = s;
            this.expected = (exp == null ? null : exp.clone());
            this.cb = cb;
        }

        @Override
        public void setInput(DataContent in) {
            this.upstream = Objects.requireNonNull(in);
        }

        @Override
        public InputStream getStream() throws IOException {
            Objects.requireNonNull(upstream, "rsa verify: upstream not set");
            if (expected == null) {
                throw new IllegalStateException("VERIFY requires expectedSignature(...)");
            }

            boolean ok;
            try (SignatureContext sc = session.createContext(ALGORITHM_ID, KeyUsage.VERIFY, key, spec)) {
                sc.setExpectedTag(expected);

                try (InputStream in = sc.wrap(upstream.getStream())) {
                    byte[] buf = new byte[8192];
                    while (true) {
                        int n = in.read(buf);
                        if (n < 0) {
                            break;
                        }
                    }
                    ok = true; // no exception => verified
                } catch (IOException fail) {
                    ok = false;
                }
            }

            if (cb != null) {
                try {
                    cb.accept(ok);
                } catch (RuntimeException ignore) { // NOPMD
                }
            }

            byte[] outBytes = ok ? "true".getBytes(StandardCharsets.UTF_8) : "false".getBytes(StandardCharsets.UTF_8);
            return new ByteArrayInputStream(outBytes);
        }
    }

    /**
     * Ensure the SignatureContext is closed when the stream is closed.
     */
    private static InputStream withContextClose(final InputStream in, final SignatureContext sc) {
        return new FilterInputStream(in) {
            @Override
            public void close() throws IOException {
                try (sc) {
                    super.close();
                }
            }
        };
    }

    /**
     * Run a callback exactly once at EOF of the underlying stream.
     */
    private static final class EofCallbackInputStream extends FilterInputStream {
        private final Runnable onEof;
        private boolean done;

        private EofCallbackInputStream(InputStream in, Runnable onEof) {
            super(in);
            this.onEof = onEof;
        }

        @Override
        public int read() throws IOException {
            int r = super.read();
            if (r == -1) {
                runOnce();
            }
            return r;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n == -1) {
                runOnce();
            }
            return n;
        }

        @Override
        public void close() throws IOException {
            try { // NOPMD
                transferTo(OutputStream.nullOutputStream());
                runOnce();
            } finally {
                super.close();
            }
        }

        private void runOnce() {
            if (!done) {
                done = true;
                onEof.run();
            }
        }
    }
}
