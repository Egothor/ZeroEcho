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
package zeroecho.core.audit;

import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * AuditListener implementation that emits structured Java Util Logging records.
 *
 * <p>
 * The listener produces parameterized JUL messages in a stable key=value format
 * suitable for ingestion by log processors. It never logs secret material: keys
 * are represented only by short, non-reversible fingerprints and specification
 * objects are summarized by simple type names.
 * </p>
 *
 * <h2>Configuration</h2>
 * <p>
 * Instances are created via {@link #builder()}. The builder allows selecting
 * the target {@code Logger}, individual levels for informational, warning, and
 * progress messages, and whether stack traces are included for failures.
 * </p>
 *
 * <h2>Logging format</h2>
 * <p>
 * Each callback logs a single structured line. Examples:
 * </p>
 * <pre>{@code
 * // Context created:
 * CTX_CREATED algo=AES/GCM provider=ZeroEcho role=ENCRYPTION keyFp=AES:1a2b3c4d spec=EncryptSpec
 *
 * // Progress tick:
 * PROGRESS ctxId=abc-123 body=4096 trailer=16
 *
 * // Failure with stack trace when enabled:
 * FAILURE ctxId=abc-123 stage=read op=wrap error=IOException message=stream closed
 * }</pre>
 *
 * <p>
 * This implementation checks {@code Logger#isLoggable(Level)} before formatting
 * and uses parameterized {@code Logger#log(Level, String, Object[])} to defer
 * formatting cost when messages are disabled at the chosen level.
 * </p>
 */
public final class JulAuditListenerStd implements AuditListener {
    /**
     * Underlying JUL logger used to emit audit records.
     */
    private final Logger log;
    /**
     * Log level used for informational events such as creation, tag produced, and
     * closure metadata.
     */
    private final Level infoLevel;

    /**
     * Log level used for warnings and verification failures.
     */
    private final Level warnLevel;
    /**
     * Log level used for frequent progress-style events such as header I/O, KDF
     * summaries, and byte counters.
     */
    private final Level progressLevel;
    /**
     * Whether failure callbacks include stack traces in addition to a structured
     * summary line.
     */
    private final boolean includeStackTraces;

    /**
     * Creates a listener configured by the supplied builder.
     *
     * @param b the configuration builder; must not be null
     */
    private JulAuditListenerStd(Builder b) {
        this.log = (b.logger != null ? b.logger : Logger.getLogger("zeroecho.audit"));
        this.infoLevel = b.infoLevel;
        this.warnLevel = b.warnLevel;
        this.progressLevel = b.progressLevel;
        this.includeStackTraces = b.includeStackTraces;
    }

    /**
     * Fluent factory for {@code JulAuditListenerStd}.
     *
     * <p>
     * The builder defaults are:
     * <ul>
     * <li>{@code logger}: {@code Logger.getLogger("zeroecho.audit")}</li>
     * <li>{@code infoLevel}: {@code Level.INFO}</li>
     * <li>{@code warnLevel}: {@code Level.WARNING}</li>
     * <li>{@code progressLevel}: {@code Level.FINE}</li>
     * <li>{@code includeStackTraces}: {@code true}</li>
     * </ul>
     *
     * <h2>Example</h2> <pre>{@code
     * JulAuditListenerStd listener = JulAuditListenerStd.builder()
     *     .logger(Logger.getLogger("audit"))
     *     .infoLevel(Level.INFO)
     *     .warnLevel(Level.WARNING)
     *     .progressLevel(Level.FINER)
     *     .includeStackTraces(false)
     *     .build();
     * }</pre>
     */
    public static final class Builder {
        private Logger logger;
        private Level infoLevel = Level.INFO;
        private Level warnLevel = Level.WARNING;
        private Level progressLevel = Level.FINE;
        private boolean includeStackTraces = true;

        /**
         * Sets the JUL logger that will receive audit messages.
         *
         * @param logger the target logger; must not be null
         * @return this builder for chaining
         */
        public Builder logger(Logger logger) {
            this.logger = Objects.requireNonNull(logger);
            return this;
        }

        /**
         * Sets the level for informational events.
         *
         * @param level the level to use for info events; must not be null
         * @return this builder for chaining
         */
        public Builder infoLevel(Level level) {
            this.infoLevel = Objects.requireNonNull(level);
            return this;
        }

        /**
         * Sets the level for warnings and verification failures.
         *
         * @param level the level to use for warnings; must not be null
         * @return this builder for chaining
         */
        public Builder warnLevel(Level level) {
            this.warnLevel = Objects.requireNonNull(level);
            return this;
        }

        /**
         * Sets the level for progress-style, high-frequency events.
         *
         * @param level the level to use for progress events; must not be null
         * @return this builder for chaining
         */
        public Builder progressLevel(Level level) {
            this.progressLevel = Objects.requireNonNull(level);
            return this;
        }

        /**
         * Controls whether {@link #onFailure(String, String, String, Throwable)}
         * appends a stack trace in addition to the structured summary.
         *
         * @param include true to include stack traces, false to omit them
         * @return this builder for chaining
         */
        public Builder includeStackTraces(boolean include) {
            this.includeStackTraces = include;
            return this;
        }

        /**
         * Builds a new {@code JulAuditListenerStd} instance with the current settings.
         *
         * @return a configured listener
         */
        public JulAuditListenerStd build() {
            return new JulAuditListenerStd(this);
        }
    }

    /**
     * Creates a new builder with sensible defaults.
     *
     * @return a fresh builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Logs a structured context creation event.
     *
     * @param <S>      context specification type
     * @param <K>      key type
     * @param id       algorithm or implementation identifier
     * @param provider provider or vendor label
     * @param role     key usage role for the context
     * @param key      associated key, if any
     * @param spec     context specification, if any
     */
    @Override
    public <S extends ContextSpec, K extends Key> void onContextCreated(String id, String provider, KeyUsage role,
            K key, S spec) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "CTX_CREATED algo={0} provider={1} role={2} keyFp={3} spec={4}",
                new Object[] { id, provider, role, fingerprint(key), specName(spec) });
    }

    /**
     * Logs a structured context closure event in generic form.
     *
     * @param id       algorithm or implementation identifier
     * @param provider provider or vendor label
     * @param role     key usage role for the context
     * @param key      associated key, if any
     */
    @Override
    public void onContextClosed(String id, String provider, KeyUsage role, Key key) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "CTX_CLOSED algo={0} provider={1} role={2} keyFp={3}",
                new Object[] { id, provider, role, fingerprint(key) });
    }

    /**
     * Logs key pair generation with non-secret metadata.
     *
     * @param id       algorithm or implementation identifier
     * @param provider provider or vendor label
     * @param spec     algorithm key specification used for generation
     * @param kp       generated key pair
     */
    @Override
    public void onKeyGenerated(String id, String provider, AlgorithmKeySpec spec, KeyPair kp) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "KEY_GENERATED algo={0} provider={1} spec={2} publicFp={3} privateType={4}",
                new Object[] { id, provider, specType(spec), fingerprint(kp == null ? null : kp.getPublic()),
                        keyType(kp == null ? null : kp.getPrivate()) });
    }

    /**
     * Logs key construction or import.
     *
     * @param id       algorithm or implementation identifier
     * @param provider provider or vendor label
     * @param spec     algorithm key specification used to build the key
     * @param key      constructed or imported key
     */
    @Override
    public void onKeyBuilt(String id, String provider, AlgorithmKeySpec spec, Key key) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "KEY_BUILT algo={0} provider={1} spec={2} keyFp={3}",
                new Object[] { id, provider, specType(spec), fingerprint(key) });
    }

    /**
     * Logs best-effort key destruction.
     *
     * @param id       algorithm or implementation identifier
     * @param provider provider or vendor label
     * @param key      key being destroyed
     */
    @Override
    public void onKeyDestroyed(String id, String provider, Key key) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "KEY_DESTROYED algo={0} provider={1} keyFp={2}",
                new Object[] { id, provider, fingerprint(key) });
    }

    /**
     * Logs creation metadata with correlation id and non-secret spec attributes.
     *
     * @param ctxId          correlation id for the wrapped context
     * @param algoId         algorithm or implementation identifier
     * @param provider       provider or vendor label
     * @param role           key usage role for the context
     * @param keyFingerprint short, non-reversible key fingerprint or "n/a"
     * @param specMeta       best-effort non-secret attributes map
     */
    @Override
    public void onContextCreatedMeta(String ctxId, String algoId, String provider, KeyUsage role, String keyFingerprint, // NOPMD
            Map<String, Object> specMeta) {
        if (!log.isLoggable(infoLevel)) {
            return;
        }
        log.log(infoLevel, "CTX_CREATED_META ctxId={0} algo={1} provider={2} role={3} keyFp={4} specMeta={5}",
                new Object[] { ctxId, algoId, provider, role, keyFingerprint, specMeta });
    }

    /**
     * Logs streaming progress for the given context id.
     *
     * @param ctxId        correlation id
     * @param bodyBytes    cumulative body bytes
     * @param trailerBytes cumulative trailer bytes
     */
    @Override
    public void onProgress(String ctxId, long bodyBytes, long trailerBytes) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "PROGRESS ctxId={0} body={1} trailer={2}",
                    new Object[] { ctxId, bodyBytes, trailerBytes });
        }
    }

    /**
     * Logs that a tag or signature was produced.
     *
     * @param ctxId     correlation id
     * @param tagLength produced tag length in bytes
     * @param policy    verification or emission policy label
     */
    @Override
    public void onTagProduced(String ctxId, int tagLength, String policy) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "TAG_PRODUCED ctxId={0} tagLen={1} policy={2}",
                    new Object[] { ctxId, tagLength, policy });
        }
    }

    /**
     * Logs verification outcome for verify mode.
     *
     * @param ctxId          correlation id
     * @param ok             true if verification succeeded
     * @param policy         verification policy label
     * @param expectedSource expected tag provenance label
     * @param tagLength      expected tag length in bytes
     */
    @Override
    public void onVerifyResult(String ctxId, boolean ok, String policy, String expectedSource, int tagLength) {
        final Level lvl = ok ? infoLevel : warnLevel;
        if (log.isLoggable(lvl)) {
            log.log(lvl, "VERIFY_RESULT ctxId={0} ok={1} policy={2} expected={3} tagLen={4}",
                    new Object[] { ctxId, ok, policy, expectedSource, tagLength });
        }
    }

    /**
     * Logs that a header was written to a stream.
     *
     * @param ctxId     correlation id
     * @param codecId   header codec identifier
     * @param headerLen total header length in bytes
     * @param ivLen     IV length in bytes
     * @param saltLen   salt length in bytes
     * @param aadLen    AAD length in bytes
     */
    @Override
    public void onHeaderWritten(String ctxId, String codecId, int headerLen, int ivLen, int saltLen, int aadLen) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "HEADER_WRITTEN ctxId={0} codec={1} len={2} ivLen={3} saltLen={4} aadLen={5}",
                    new Object[] { ctxId, codecId, headerLen, ivLen, saltLen, aadLen });
        }
    }

    /**
     * Logs that a header was read from a stream.
     *
     * @param ctxId     correlation id
     * @param codecId   header codec identifier
     * @param headerLen total header length in bytes
     * @param ivLen     IV length in bytes
     * @param saltLen   salt length in bytes
     * @param aadLen    AAD length in bytes
     */
    @Override
    public void onHeaderRead(String ctxId, String codecId, int headerLen, int ivLen, int saltLen, int aadLen) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "HEADER_READ ctxId={0} codec={1} len={2} ivLen={3} saltLen={4} aadLen={5}",
                    new Object[] { ctxId, codecId, headerLen, ivLen, saltLen, aadLen });
        }
    }

    /**
     * Logs random material generation such as IVs, salts, nonces, or key bytes.
     *
     * @param ctxId  correlation id
     * @param kind   material kind label
     * @param rng    random source label
     * @param length number of bytes generated
     */
    @Override
    public void onRandomMaterial(String ctxId, String kind, String rng, int length) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "RANDOM ctxId={0} kind={1} rng={2} len={3}",
                    new Object[] { ctxId, kind, rng, length });
        }
    }

    /**
     * Logs a KDF usage summary.
     *
     * @param ctxId      correlation id
     * @param kdf        KDF identifier
     * @param saltLen    salt length in bytes
     * @param infoLen    info length in bytes
     * @param outLen     derived output length in bytes
     * @param iterations iteration count, or null if not applicable
     */
    @Override
    public void onKdfUsed(String ctxId, String kdf, int saltLen, int infoLen, int outLen, Integer iterations) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "KDF ctxId={0} kdf={1} saltLen={2} infoLen={3} outLen={4} iters={5}",
                    new Object[] { ctxId, kdf, saltLen, infoLen, outLen, (iterations == null ? "n/a" : iterations) });
        }
    }

    /**
     * Logs a failure with a structured summary and optional stack trace.
     *
     * @param ctxId correlation id
     * @param stage coarse-grained stage label such as "read" or "invoke"
     * @param op    fine-grained operation label
     * @param cause the exception that caused the failure; may be null
     */
    @Override
    public void onFailure(String ctxId, String stage, String op, Throwable cause) {
        if (!log.isLoggable(warnLevel)) {
            return;
        }
        String msg = "FAILURE ctxId={0} stage={1} op={2} error={3} message={4}";
        Object[] params = { ctxId, stage, op, (cause == null ? "unknown" : cause.getClass().getSimpleName()),
                (cause == null ? "" : safeMessage(cause.getMessage())) };
        if (includeStackTraces && cause != null) {
            log.log(warnLevel, msg, params);
            log.log(warnLevel, "STACKTRACE", cause);
        } else {
            log.log(warnLevel, msg, params);
        }
    }

    /**
     * Logs closure totals and elapsed time for the correlation id.
     *
     * @param ctxId          correlation id
     * @param bodyBytes      total body bytes processed
     * @param trailerBytes   total trailer bytes processed
     * @param durationMillis processing time in milliseconds
     */
    @Override
    public void onContextClosed(String ctxId, long bodyBytes, long trailerBytes, long durationMillis) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "CTX_CLOSED_META ctxId={0} body={1} trailer={2} durationMs={3}",
                    new Object[] { ctxId, bodyBytes, trailerBytes, durationMillis });
        }
    }

    /**
     * Logs that a peer message was provided to a message agreement context.
     *
     * @param ctxId  correlation id
     * @param msgLen provided message length in bytes
     */
    @Override
    public void onAgreementPeerMessageSet(String ctxId, int msgLen) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "AGREE_MSG_SET ctxId={0} msgLen={1}", new Object[] { ctxId, msgLen });
        }
    }

    /**
     * Logs that a peer message was retrieved from a message agreement context.
     *
     * @param ctxId  correlation id
     * @param msgLen retrieved message length in bytes
     */
    @Override
    public void onAgreementPeerMessageGet(String ctxId, int msgLen) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "AGREE_MSG_GET ctxId={0} msgLen={1}", new Object[] { ctxId, msgLen });
        }
    }

    /**
     * Logs the legacy single-argument creation callback with the context type.
     *
     * @param ctx the wrapped context
     */
    @Override
    public void onContextCreated(CryptoContext ctx) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "CTX_CREATED_LEGACY type={0}",
                    new Object[] { (ctx == null ? "null" : ctx.getClass().getSimpleName()) });
        }
    }

    /**
     * Logs the legacy cumulative byte counter.
     *
     * @param role  key usage role
     * @param count cumulative bytes observed
     */
    @Override
    public void onBytes(KeyUsage role, long count) {
        if (log.isLoggable(progressLevel)) {
            log.log(progressLevel, "BYTES role={0} count={1}", new Object[] { role, count });
        }
    }

    /**
     * Logs legacy KEM encapsulation lengths.
     *
     * @param cipherLength       ciphertext length in bytes, or -1 if unknown
     * @param sharedSecretLength shared secret length in bytes, or -1 if unknown
     */
    @Override
    public void onKemEncapsulated(int cipherLength, int sharedSecretLength) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "KEM_ENCAPSULATED ctLen={0} ssLen={1}",
                    new Object[] { cipherLength, sharedSecretLength });
        }
    }

    /**
     * Logs legacy KEM decapsulation length.
     *
     * @param sharedSecretLength shared secret length in bytes, or -1 if unknown
     */
    @Override
    public void onKemDecapsulated(int sharedSecretLength) {
        log.log(infoLevel, "KEM_DECAPSULATED ssLen={0}", sharedSecretLength);
    }

    /**
     * Logs that a peer public key was provided to an agreement context.
     *
     * @param ctxId           correlation id
     * @param peerFingerprint short, non-reversible peer key fingerprint
     */
    @Override
    public void onAgreementPeerSet(String ctxId, String peerFingerprint) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "AGREE_PEER_SET ctxId={0} peerFp={1}", new Object[] { ctxId, peerFingerprint });
        }
    }

    /**
     * Logs that an agreement secret was derived with the reported length only.
     *
     * @param ctxId        correlation id
     * @param secretLength derived secret length in bytes, or -1 if unknown
     */
    @Override
    public void onAgreementDerived(String ctxId, int secretLength) {
        if (log.isLoggable(infoLevel)) {
            log.log(infoLevel, "AGREE_DERIVED ctxId={0} secretLen={1}", new Object[] { ctxId, secretLength });
        }
    }

    /**
     * Returns the simple name of the provided specification or "null".
     *
     * @param spec a context specification, possibly null
     * @return simple class name or "null"
     */
    private static String specName(ContextSpec spec) {
        return spec == null ? "null" : spec.getClass().getSimpleName();
    }

    /**
     * Returns the simple name of the provided key specification or "null".
     *
     * @param spec an algorithm key specification, possibly null
     * @return simple class name or "null"
     */
    private static String specType(AlgorithmKeySpec spec) {
        return spec == null ? "null" : spec.getClass().getSimpleName();
    }

    /**
     * Returns an algorithm/type descriptor for the given key or "null".
     *
     * @param k a key, possibly null
     * @return algorithm and type descriptor or "null"
     */
    private static String keyType(Key k) {
        return k == null ? "null" : k.getAlgorithm() + "/" + k.getClass().getSimpleName();
    }

    /**
     * Computes a short, non-reversible fingerprint for the key without logging raw
     * key bytes. Non-extractable keys fall back to algorithm and type.
     *
     * @param key the key to summarize; may be null
     * @return a fingerprint string or "n/a" if the key is null
     */
    private static String fingerprint(Key key) {
        if (key == null) {
            return "n/a";
        }
        try {
            byte[] enc = key.getEncoded();
            if (enc == null) {
                return key.getAlgorithm() + ":" + key.getClass().getSimpleName();
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(enc);
            StringBuilder sb = new StringBuilder(key.getAlgorithm()).append(':');
            for (int i = 0; i < Math.min(8, d.length); i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return key.getAlgorithm() + ":fp-error";
        }
    }

    /**
     * Returns a non-null message string for logging.
     *
     * @param s a message, possibly null
     * @return the message or an empty string if null
     */
    private static String safeMessage(String s) {
        return s == null ? "" : s;
    }
}
