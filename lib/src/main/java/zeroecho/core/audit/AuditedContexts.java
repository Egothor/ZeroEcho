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
package zeroecho.core.audit;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.KemContext.KemResult;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Lightweight dynamic proxy that audits crypto contexts without changing their
 * behavior.
 *
 * <p>
 * This utility wraps an existing context instance and transparently intercepts
 * selected operations in order to emit audit events. The wrapper delegates all
 * calls to the underlying context and does not alter the functional results.
 * </p>
 *
 * <h2>What is audited</h2>
 * <ul>
 * <li><strong>attach(InputStream)</strong>: classic byte counting over the
 * processed body.</li>
 * <li><strong>wrap(InputStream)</strong> on TagEngine-style contexts
 * (SIGN/VERIFY, MAC, DIGEST): trailer-aware accounting that distinguishes body
 * bytes from the authentication tag trailer; verification success or failure is
 * inferred at EOF when possible.</li>
 * <li><strong>KEM</strong>: {@code encapsulate()} and
 * {@code decapsulate(byte[])} are observed to report ciphertext and
 * shared-secret lengths.</li>
 * <li><strong>Agreement</strong>: peer material assignment and secret
 * derivation are captured with non-reversible fingerprints and byte sizes.</li>
 * </ul>
 *
 * <h2>Events and correlation</h2>
 * <p>
 * Creation, progress, failure, and closure events are emitted. Each wrapped
 * instance is associated with a generated correlation id that is included with
 * progress and failure notifications. When available, algorithm id, provider
 * label, key fingerprint, and a best-effort summary of the context
 * specification are recorded at creation time.
 * </p>
 *
 * <h2>Behavioral guarantees</h2>
 * <ul>
 * <li>The proxy preserves the original semantics and exceptions of the wrapped
 * context. Any failure reported to the listener mirrors the underlying
 * failure.</li>
 * <li>Counting is performed by decorating the returned {@code InputStream}s; no
 * buffering beyond normal {@code FilterInputStream} forwarding is
 * introduced.</li>
 * <li>Idempotent wrapping: contexts that are already JDK proxies will be
 * returned unchanged.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * AuditListener listener = ...;
 * KeyUsage role = KeyUsage.ENCRYPTION;
 * CryptoContext original = ...; // e.g., an EncryptionContext
 *
 * CryptoContext audited = AuditedContexts.wrap(original, listener, role);
 * try (InputStream in = audited.attach(sourceStream)) {
 *     in.transferTo(sink);
 * }
 * }</pre>
 */
public final class AuditedContexts {
    private static final String UNKNOWN = "unknown";

    /**
     * Prevents instantiation.
     */
    private AuditedContexts() {
    }

    /**
     * Wraps a crypto context with an auditing proxy that emits lifecycle, progress,
     * and error events while preserving the original behavior.
     *
     * <p>
     * If {@code ctx} is {@code null}, this method returns {@code null}. If
     * {@code ctx} is already a JDK dynamic proxy, the instance is returned as-is to
     * keep wrapping idempotent.
     * </p>
     *
     * <p>
     * The returned proxy implements the same set of interfaces as the original
     * object. It observes:
     * <ul>
     * <li>{@code attach(InputStream)} for classic cumulative byte counts,</li>
     * <li>{@code wrap(InputStream)} for TagEngine-style contexts to account for
     * body vs. authentication tag trailer and to report tag production or verify
     * results at EOF when the tag length is known,</li>
     * <li>{@code encapsulate()} and {@code decapsulate(byte[])} on KEM contexts to
     * report ciphertext and secret lengths,</li>
     * <li>agreement operations (peer material assignment and secret derivation)
     * with non-reversible key fingerprints and derived sizes.</li>
     * </ul>
     * Creation metadata includes a generated correlation id, algorithm id, provider
     * label, key fingerprint (if extractable), and a best-effort, non-secret spec
     * summary when available.
     *
     * <p>
     * This call does not invoke any context operations other than the minimal,
     * best-effort introspection used to produce creation metadata. Functional
     * results and exceptions from the wrapped object are forwarded unchanged.
     * </p>
     *
     * <p>
     * <strong>Thread-safety:</strong> the proxy does not introduce additional
     * synchronization. It is safe only to the extent the wrapped {@code ctx} is
     * safe.
     * </p>
     *
     * @param ctx   the context to wrap; may be {@code null}
     * @param audit the listener that will receive audit events; must not be
     *              {@code null}
     * @param role  the usage role associated with the context (for example,
     *              ENCRYPTION, DECRYPTION, SIGNING); must not be {@code null}
     * @return the auditing proxy for {@code ctx}, the original {@code ctx} if it is
     *         already a proxy, or {@code null} if {@code ctx} is {@code null}
     */
    public static CryptoContext wrap(final CryptoContext ctx, final AuditListener audit, final KeyUsage role) {
        if (ctx == null) {
            return null;
        }
        if (Proxy.isProxyClass(ctx.getClass())) {
            return ctx; // idempotent
        }
        // IMPORTANT: do not call any other wrap(...) here — avoid recursion.
        return replaceWithProxy(ctx, audit, role);
    }

    @SuppressWarnings("unchecked")
    private static <T> T replaceWithProxy(final T ctx, final AuditListener audit, final KeyUsage role) { // NOPMD
        Objects.requireNonNull(ctx, "ctx must not be null");
        Objects.requireNonNull(audit, "audit must not be null");
        Objects.requireNonNull(role, "role must not be null");

        // Emit creation metadata if we can resolve it
        String ctxId = UUID.randomUUID().toString();
        String algoId = null;
        String provider = null;
        String keyFp;
        Map<String, Object> specMeta = null;
        Key keyObj = null;
        ContextSpec specObj = null;

        if (ctx instanceof CryptoContext cctx) { // NOPMD
            try {
                CryptoAlgorithm alg = cctx.algorithm();
                if (alg != null) {
                    try {
                        algoId = safeString(invokeNoArg(alg, "id"));
                    } catch (Throwable ignore) { // NOPMD
                        algoId = alg.getClass().getSimpleName();
                    }
                    try {
                        provider = safeString(invokeNoArg(alg, "providerLabel"));
                    } catch (Throwable ignore) { // NOPMD
                        try {
                            provider = safeString(invokeNoArg(alg, "provider"));
                        } catch (Throwable ignoredToo) { // NOPMD
                            provider = alg.getClass().getPackageName();
                        }
                    }
                }
            } catch (Throwable ignore) { // NOPMD
                // best-effort
            }
            try {
                keyObj = cctx.key();
                keyFp = fingerprint(keyObj);
            } catch (Throwable ignore) { // NOPMD
                keyFp = "n/a";
            }
            try {
                // optional: contexts may expose a spec() accessor
                Object s = invokeNoArg(cctx, "spec");
                if (s instanceof ContextSpec) {
                    specObj = (ContextSpec) s;
                    specMeta = SpecIntrospector.summarize(specObj);
                }
            } catch (Throwable ignore) { // NOPMD
                specObj = null;
                specMeta = null;
            }

            // New-style context-created event with metadata
            audit.onContextCreatedMeta(ctxId, algoId == null ? UNKNOWN : algoId, provider == null ? UNKNOWN : provider,
                    role, keyFp, specMeta);

            // Back-compat event forms
            try {
                // Generic with id/provider/role/key/spec
                audit.onContextCreated(algoId == null ? UNKNOWN : algoId, provider == null ? UNKNOWN : provider, role,
                        keyObj, specObj);
            } catch (Throwable ignore) { // NOPMD
            }
            try {
                // Legacy single-arg callback
                audit.onContextCreated(cctx);
            } catch (Throwable ignore) { // NOPMD
            }
        }

        ClassLoader cl = ctx.getClass().getClassLoader(); // NOPMD
        Class<?>[] ifaces = allInterfaces(ctx.getClass());
        InvocationHandler handler = new AuditingHandler(ctx, audit, role, ctxId, algoId == null ? UNKNOWN : algoId,
                provider == null ? UNKNOWN : provider, keyObj);

        return (T) Proxy.newProxyInstance(cl, ifaces, handler);
    }

    private static Class<?>[] allInterfaces(Class<?> type) {
        Set<Class<?>> set = new LinkedHashSet<>();
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            Class<?>[] local = c.getInterfaces();
            for (Class<?> i : local) {
                set.add(i);
            }
        }
        return set.toArray(Class<?>[]::new);
    }

    private static final class AuditingHandler implements InvocationHandler { // NOPMD
        private final Object target;
        private final AuditListener audit;
        private final KeyUsage role;

        private final String ctxId;
        private final String algoId;
        private final String provider;
        private final Key keyForClose; // may be null

        private long bodyBytes;
        private long trailerBytes;
        private final long startNanos;

        private Integer tagLen; // for TagEngine contexts
        private boolean verifyMode; // true if setExpectedTag(...) was called
        private String policyLabel = "UNSET";
        private String expectedSource = "provided"; // default for setExpectedTag(byte[])

        private AuditingHandler(Object target, AuditListener audit, KeyUsage role, String ctxId, String algoId,
                String provider, Key keyForClose) {
            this.target = target;
            this.audit = audit;
            this.role = role;
            this.ctxId = ctxId;
            this.algoId = algoId;
            this.provider = provider;
            this.keyForClose = keyForClose;
            this.startNanos = System.nanoTime();
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable { // NOPMD
            final String name = method.getName();

            // Object methods
            if ("toString".equals(name) && (args == null || args.length == 0)) {
                return "AuditedProxy(" + target + ")";
            }
            if ("hashCode".equals(name) && (args == null || args.length == 0)) {
                return System.identityHashCode(proxy);
            }
            if ("equals".equals(name) && args != null && args.length == 1) {
                return proxy == args[0]; // NOPMD
            }

            try {
                // --- TagEngine plumbing ---

                // Track tagLength() if requested explicitly
                if ("tagLength".equals(name) && (args == null || args.length == 0)) {
                    Object res = method.invoke(target, args);
                    if (res instanceof Integer) {
                        this.tagLen = (Integer) res;
                    }
                    return res;
                }

                // Track verification policy (label only; do not depend on specific enum type)
                if ("setVerificationPolicy".equals(name) && args != null && args.length == 1) {
                    Object pol = args[0];
                    this.policyLabel = (pol == null ? "null" : pol.toString());
                    return method.invoke(target, args);
                }

                // setExpectedTag(byte[]) marks verify mode
                if ("setExpectedTag".equals(name) && args != null && args.length == 1 && args[0] instanceof byte[]) {
                    this.verifyMode = true;
                    this.expectedSource = "provided";
                    return method.invoke(target, args);
                }

                // Intercept wrap(InputStream) for TagEngine contexts
                if ("wrap".equals(name) && args != null && args.length == 1 && args[0] instanceof InputStream) {
                    // Update tagLen lazily if not known
                    if (this.tagLen == null) {
                        try {
                            Object tl = target.getClass().getMethod("tagLength").invoke(target);
                            if (tl instanceof Integer i) { // NOPMD
                                this.tagLen = i;
                            }
                        } catch (Throwable ignore) { // NOPMD
                            this.tagLen = null;
                        }
                    }
                    InputStream transformed = (InputStream) method.invoke(target, args);
                    return countingTagAware(transformed, audit, ctxId, role, this);
                }

                // --- Classic attach(InputStream) counting ---
                if ("attach".equals(name) && args != null && args.length == 1 && args[0] instanceof InputStream) {
                    InputStream transformed = (InputStream) method.invoke(target, args);
                    return counting(transformed, audit, ctxId, role, this);
                }

                // --- AgreementContext (DH/ECDH/X25519, etc.) ---
                if (target instanceof AgreementContext) {
                    // setPeerPublic(PublicKey)
                    if ("setPeerPublic".equals(name) && args != null && args.length == 1
                            && args[0] instanceof PublicKey) {
                        try {
                            Object res = method.invoke(target, args);
                            try {
                                String peerFp = fingerprint((Key) args[0]); // short, non-reversible
                                audit.onAgreementPeerSet(ctxId, peerFp);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            return res;
                        } catch (Throwable t) { // NOPMD
                            Throwable cause = unwrapInvocationTarget(t);
                            try {
                                audit.onFailure(ctxId, "invoke:setPeerPublic", role.name(), cause);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            throw cause;
                        }
                    }

                    // deriveSecret()
                    if ("deriveSecret".equals(name) && (args == null || args.length == 0)) {
                        try {
                            byte[] secret = (byte[]) method.invoke(target);
                            try {
                                audit.onAgreementDerived(ctxId, secret == null ? -1 : secret.length);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            return secret;
                        } catch (Throwable t) { // NOPMD
                            Throwable cause = unwrapInvocationTarget(t);
                            try {
                                audit.onFailure(ctxId, "invoke:deriveSecret", role.name(), cause);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            throw cause;
                        }
                    }
                }

                // =========== MessageAgreementContext (KEM-style) ===========
                if (target instanceof MessageAgreementContext) {
                    // setPeerMessage(byte[])
                    if ("setPeerMessage".equals(name) && args != null && args.length == 1
                            && args[0] instanceof byte[]) {
                        try {
                            Object r = method.invoke(target, args);
                            try {
                                int len = ((byte[]) args[0]).length;
                                audit.onAgreementPeerMessageSet(ctxId, len);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            return r;
                        } catch (Throwable t) { // NOPMD
                            Throwable cause = unwrapInvocationTarget(t);
                            try {
                                audit.onFailure(ctxId, "invoke:setPeerMessage", role.name(), cause);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            throw cause;
                        }
                    }

                    // getPeerMessage()
                    if ("getPeerMessage".equals(name) && (args == null || args.length == 0)) {
                        try {
                            byte[] msg = (byte[]) method.invoke(target);
                            try {
                                audit.onAgreementPeerMessageGet(ctxId, msg == null ? -1 : msg.length);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            return msg;
                        } catch (Throwable t) { // NOPMD
                            Throwable cause = unwrapInvocationTarget(t);
                            try {
                                audit.onFailure(ctxId, "invoke:getPeerMessage", role.name(), cause);
                            } catch (Throwable ignore) { // NOPMD
                            }
                            throw cause;
                        }
                    }
                }

                // --- KEM ---
                if (target instanceof KemContext) {
                    if ("encapsulate".equals(name) && (args == null || args.length == 0)) {
                        KemResult r = (KemResult) method.invoke(target);
                        try {
                            audit.onKemEncapsulated(r == null || r.ciphertext() == null ? -1 : r.ciphertext().length,
                                    r == null || r.sharedSecret() == null ? -1 : r.sharedSecret().length);
                        } catch (Throwable ignore) { // NOPMD
                        }
                        return r;
                    }
                    if ("decapsulate".equals(name) && args != null && args.length == 1 && args[0] instanceof byte[]) {
                        byte[] secret = (byte[]) method.invoke(target, args);
                        try {
                            audit.onKemDecapsulated(secret == null ? -1 : secret.length);
                        } catch (Throwable ignore) { // NOPMD
                        }
                        return secret;
                    }
                }

                // --- close(): emit closure metadata ---
                if ("close".equals(name) && (args == null || args.length == 0)) {
                    try {
                        return method.invoke(target);
                    } finally {
                        long durationMs = Math.max(1L, (System.nanoTime() - startNanos) / 1_000_000L);
                        try {
                            audit.onContextClosed(ctxId, bodyBytes, trailerBytes, durationMs);
                        } catch (Throwable ignore) { // NOPMD
                        }
                        try {
                            audit.onContextClosed(algoId, provider, role, keyForClose);
                        } catch (Throwable ignore) { // NOPMD
                        }
                    }
                }

                // Default delegation
                return method.invoke(target, args);
            } catch (Throwable t) { // NOPMD
                Throwable cause = unwrapInvocationTarget(t);
                try {
                    audit.onFailure(ctxId, "invoke:" + name, role.name(), cause);
                } catch (Throwable ignore) { // NOPMD
                }
                throw cause;
            }
        }
    }

    private static InputStream counting(final InputStream in, final AuditListener audit, final String ctxId,
            final KeyUsage role, final AuditingHandler h) {
        return new FilterInputStream(in) {
            private long count;

            @Override
            public int read() throws IOException {
                try {
                    int r = super.read();
                    if (r >= 0) {
                        count++;
                        h.bodyBytes++;
                        try {
                            audit.onBytes(role, count); // legacy
                            audit.onProgress(ctxId, h.bodyBytes, h.trailerBytes); // new
                        } catch (Throwable ignore) { // NOPMD
                        }
                    }
                    return r;
                } catch (IOException ioe) {
                    try {
                        audit.onFailure(ctxId, "read", role.name(), ioe);
                    } catch (Throwable ignore) { // NOPMD
                    }
                    throw ioe;
                }
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                try {
                    int n = super.read(b, off, len);
                    if (n > 0) {
                        count += n;
                        h.bodyBytes += n;
                        try {
                            audit.onBytes(role, count); // legacy
                            audit.onProgress(ctxId, h.bodyBytes, h.trailerBytes); // new
                        } catch (Throwable ignore) { // NOPMD
                        }
                    }
                    return n;
                } catch (IOException ioe) {
                    try {
                        audit.onFailure(ctxId, "read", role.name(), ioe);
                    } catch (Throwable ignore) { // NOPMD
                    }
                    throw ioe;
                }
            }
        };
    }

    private static InputStream countingTagAware(final InputStream in, final AuditListener audit, final String ctxId,
            final KeyUsage role, final AuditingHandler h) {
        return new FilterInputStream(in) {
            private long total;
            private boolean eof;

            @Override
            public int read() throws IOException {
                try {
                    int r = super.read();
                    if (r >= 0) {
                        total++;
                        h.bodyBytes++; // provisional (reclassified at EOF if tagLen known)
                        emitProgress();
                    } else {
                        onEof();
                    }
                    return r;
                } catch (IOException ioe) {
                    onFailureMaybeVerify(ioe);
                    throw ioe;
                }
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                try {
                    int n = super.read(b, off, len);
                    if (n > 0) {
                        total += n;
                        h.bodyBytes += n; // provisional
                        emitProgress();
                    } else if (n == -1) {
                        onEof();
                    }
                    return n;
                } catch (IOException ioe) {
                    onFailureMaybeVerify(ioe);
                    throw ioe;
                }
            }

            @Override
            public void close() throws IOException {
                try { // NOPMD
                    transferTo(OutputStream.nullOutputStream());
                    onEof();
                } finally {
                    super.close();
                }
            }

            private void emitProgress() {
                try {
                    audit.onBytes(role, total); // legacy cumulative
                    audit.onProgress(ctxId, h.bodyBytes, h.trailerBytes);
                } catch (Throwable ignore) { // NOPMD
                }
            }

            private void onEof() {
                if (eof) {
                    return;
                }
                eof = true;

                // Reclassify trailer if tagLen known
                if (h.tagLen != null && h.tagLen > 0 && h.bodyBytes >= h.tagLen) {
                    h.bodyBytes -= h.tagLen;
                    h.trailerBytes += h.tagLen;
                    try {
                        audit.onProgress(ctxId, h.bodyBytes, h.trailerBytes);
                    } catch (Throwable ignore) { // NOPMD
                    }

                    // Produce tag or verification result at EOF (no exception thrown)
                    try {
                        if (h.verifyMode) {
                            audit.onVerifyResult(ctxId, true, h.policyLabel, h.expectedSource, h.tagLen);
                        } else {
                            audit.onTagProduced(ctxId, h.tagLen, h.policyLabel);
                        }
                    } catch (Throwable ignore) { // NOPMD
                    }
                }
            }

            private void onFailureMaybeVerify(IOException ioe) {
                try {
                    audit.onFailure(ctxId, "read", role.name(), ioe);
                    if (h.verifyMode && h.tagLen != null && h.tagLen > 0) {
                        // Heuristic: verification failures commonly bubble as IOException from the
                        // engine.
                        audit.onVerifyResult(ctxId, false, h.policyLabel, h.expectedSource, h.tagLen);
                    }
                } catch (Throwable ignore) { // NOPMD
                }
            }
        };
    }

    private static Object invokeNoArg(Object target, String method) throws Throwable {
        Method m = target.getClass().getMethod(method);
        m.setAccessible(true); // NOPMD
        return m.invoke(target);
    }

    private static Throwable unwrapInvocationTarget(Throwable t) {
        if (t instanceof java.lang.reflect.InvocationTargetException ite && ite.getTargetException() != null) {
            return ite.getTargetException();
        }
        return t;
    }

    private static String safeString(Object o) {
        return o == null ? "null" : o.toString();
    }

    private static String fingerprint(Key key) {
        if (key == null) {
            return "n/a";
        }
        try {
            byte[] enc = key.getEncoded();
            if (enc == null) {
                // Non-extractable key: fall back to type information
                return key.getAlgorithm() + ":" + key.getClass().getSimpleName();
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(enc);
            // hex-short: first 8 bytes
            StringBuilder sb = new StringBuilder(2 * 8);
            for (int i = 0; i < Math.min(8, d.length); i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return key.getAlgorithm() + ":" + sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return key.getAlgorithm() + ":fp-error";
        }
    }
}
