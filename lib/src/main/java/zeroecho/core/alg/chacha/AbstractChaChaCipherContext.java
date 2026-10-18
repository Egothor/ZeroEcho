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
package zeroecho.core.alg.chacha;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.SymmetricHeaderCodec;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.err.ProviderFailureException;
import zeroecho.core.io.CipherTransformInputStreamBuilder;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.util.RandomSupport;

/**
 * <h2>Abstract streaming cipher context for ChaCha algorithms</h2>
 *
 * Base implementation of {@link zeroecho.core.context.EncryptionContext} for
 * ChaCha20 and ChaCha20-Poly1305. Provides a streaming
 * {@link java.io.InputStream}-based interface for encryption and decryption,
 * with support for nonce management and optional {@link SymmetricHeaderCodec}
 * headers.
 *
 * <h3>Features</h3>
 * <ul>
 * <li>Automatic 12-byte nonce generation (encryption) or validation
 * (decryption).</li>
 * <li>Optional header encoding/decoding via {@link SymmetricHeaderCodec} bound
 * in the spec.</li>
 * <li>Streaming transformation using {@link javax.crypto.Cipher} with staged
 * {@code doFinal()}.</li>
 * <li>Integration with {@link ConfluxKeys} for propagating IV/nonce
 * values.</li>
 * </ul>
 *
 * <h3>Subclass responsibilities</h3>
 * <ul>
 * <li>Implement {@link #jceName()} to return a JCE transformation string (e.g.,
 * {@code "ChaCha20"} or {@code "ChaCha20-Poly1305"}).</li>
 * <li>Implement {@link #initCipher(Cipher, byte[])} to configure parameters and
 * AAD if required.</li>
 * </ul>
 *
 * <h3>Usage</h3> <pre>{@code
 * EncryptionContext enc = new ChaCha20Poly1305Context(algo, key, true, spec, null);
 * InputStream ciphertext = enc.attach(plaintextStream);
 *
 * EncryptionContext dec = new ChaCha20Poly1305Context(algo, key, false, spec, null);
 * InputStream plaintext = dec.attach(ciphertext);
 * }</pre>
 *
 * @param <S> specification type carrying ChaCha parameters
 * @since 1.0
 */
abstract class AbstractChaChaCipherContext<S extends ChaChaBaseSpec> implements EncryptionContext, ContextAware {
    /** Required ChaCha nonce length (12 bytes). */
    private static final int NONCE_LEN = 12; // both variants
    /** Algorithm definition that created this context. */
    protected final CryptoAlgorithm algorithm;
    /** Symmetric key used by this context. */
    protected final SecretKey key;
    /**
     * Operation mode flag - {@code true} for encryption, {@code false} for
     * decryption.
     */
    protected final boolean encrypt;
    /** Algorithm-specific specification (e.g., AEAD parameters). */
    protected final S spec;
    /** Secure random source for nonce generation. */
    protected final SecureRandom rnd;
    private final AtomicReference<OperationState> operationState = new AtomicReference<>(OperationState.NEW);
    /** Optional per-operation context for exchanging headers, IVs, etc. */
    protected CtxInterface ctx; // optional

    /**
     * Creates a new ChaCha cipher context.
     *
     * @param algorithm parent algorithm
     * @param key       ChaCha secret key
     * @param encrypt   {@code true} for encryption, {@code false} for decryption
     * @param spec      ChaCha-specific context specification
     * @param rnd       source of randomness for nonces (uses default if null)
     */
    protected AbstractChaChaCipherContext(CryptoAlgorithm algorithm, SecretKey key, boolean encrypt, S spec,
            SecureRandom rnd) {
        this.algorithm = algorithm;
        this.key = key;
        this.encrypt = encrypt;
        this.spec = spec;
        this.rnd = (rnd != null ? rnd : RandomSupport.getRandom());
    }

    /** {@inheritDoc} */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /** {@inheritDoc} */
    @Override
    public java.security.Key key() {
        return key;
    }

    /** {@inheritDoc} */
    @Override
    public void setContext(CtxInterface context) {
        this.ctx = context;
    }

    /** {@inheritDoc} */
    @Override
    public CtxInterface context() {
        return ctx;
    }

    /**
     * Returns the JCE transformation string, e.g. "ChaCha20" or
     * "ChaCha20-Poly1305".
     *
     * @return transformation string for
     *         {@link javax.crypto.Cipher#getInstance(String)}
     */
    protected abstract String jceName();

    /**
     * Initializes the cipher with algorithm-specific parameters and optional AAD.
     *
     * @param cipher configured cipher instance
     * @param nonce  12-byte nonce generated or supplied from context
     * @throws GeneralSecurityException if parameter initialization fails
     * @throws IOException              if AAD setup or parameter resolution fails
     */
    protected abstract void initCipher(Cipher cipher, byte[] nonce) throws GeneralSecurityException, IOException;

    /**
     * Attaches this context to an upstream input stream and returns a
     * transformation stream.
     *
     * <p>
     * Encryption prepends optional headers; decryption consumes headers first.
     * </p>
     *
     * @param upstream plaintext or ciphertext input stream
     * @return transformed stream (ciphertext for encryption, plaintext for
     *         decryption)
     * @throws IOException if cipher initialization fails
     */
    @Override
    public InputStream attach(InputStream upstream) throws IOException {
        java.util.Objects.requireNonNull(upstream, "upstream must not be null");
        claimEncryption();
        boolean attached = false;
        try {
            final SymmetricHeaderCodec header = spec.header();
            final boolean hasCtxHeader = ctx != null && header != null;

            InputStream in = upstream;
            if (!encrypt && hasCtxHeader) {
                in = header.readHeader(in, algorithm, ctx);
            }

            final Cipher cipher = Cipher.getInstance(jceName());
            final byte[] nonce = ensureNonce();
            initCipher(cipher, nonce);

            InputStream out = // new Stream(in, cipher, jceName()); // same stream pattern as AES
                    CipherTransformInputStreamBuilder.builder().withUpstream(in).withCipher(cipher)
                            .withUpdateStreaming().withInputBlockSize(64 /* chacha block */ ).withOutputBlockSize(64)
                            .withBufferedBlocks(100).withFinalizationOutputChunks(2).build();
            if (encrypt && hasCtxHeader) {
                final ByteArrayOutputStream hdr = new ByteArrayOutputStream(48);
                header.writeHeader(hdr, algorithm, ctx);
                out = new SequenceInputStream(new ByteArrayInputStream(hdr.toByteArray()), out);
            }
            attached = true;
            return encrypt ? new LifecycleInputStream(out) : out;
        } catch (GeneralSecurityException e) {
            throw new ProviderFailureException(jceName() + " attach/init failed", e);
        } finally {
            if (!attached) {
                failEncryption();
            }
        }
    }

    /**
     * Releases context resources.
     * <p>
     * No-op for ChaCha contexts.
     * </p>
     */
    @Override
    public void close() { // NOPMD
        /* no-op */
    }

    /**
     * Ensures a nonce is available in the context.
     *
     * <ul>
     * <li>For encryption, always generates a new nonce after the context has been
     * atomically claimed and stores a copy in the context.</li>
     * <li>For decryption, validates presence and correct length.</li>
     * </ul>
     *
     * @return 12-byte nonce
     * @throws IOException if nonce is missing or invalid
     */
    private byte[] ensureNonce() throws IOException {
        final String id = algorithm.id();
        byte[] nonce;
        if (encrypt) {
            nonce = new byte[NONCE_LEN];
            rnd.nextBytes(nonce);
            if (ctx != null) {
                ctx.put(ConfluxKeys.iv(id), nonce.clone());
            }
        } else {
            nonce = (ctx == null) ? null : ctx.get(ConfluxKeys.iv(id));
            if (nonce == null || nonce.length != NONCE_LEN) {
                throw new IOException("Nonce missing/invalid for " + jceName() + " decryption");
            }
        }
        return nonce;
    }

    private void claimEncryption() throws IOException {
        if (encrypt && !operationState.compareAndSet(OperationState.NEW, OperationState.ENCRYPTING)) {
            throw new IOException(jceName() + " encryption context is single-use");
        }
    }

    private void failEncryption() {
        if (encrypt) {
            operationState.set(OperationState.FAILED);
        }
    }

    /** Single-use encryption lifecycle states. */
    private enum OperationState {
        NEW, ENCRYPTING, COMPLETED, FAILED
    }

    /** Marks the owning encryption context terminal as its stream is consumed. */
    private final class LifecycleInputStream extends FilterInputStream {
        private boolean endOfInput;

        private LifecycleInputStream(InputStream delegate) {
            super(delegate);
        }

        @Override
        public int read() throws IOException {
            boolean successful = false;
            try {
                int value = super.read();
                successful = true;
                completeAtEnd(value < 0);
                return value;
            } finally {
                if (!successful) {
                    failEncryption();
                }
            }
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            boolean successful = false;
            try {
                int count = super.read(bytes, offset, length);
                successful = true;
                completeAtEnd(count < 0);
                return count;
            } finally {
                if (!successful) {
                    failEncryption();
                }
            }
        }

        @Override
        public void close() throws IOException {
            boolean successful = false;
            try {
                super.close();
                successful = true;
                if (!endOfInput) {
                    failEncryption();
                }
            } finally {
                if (!successful) {
                    failEncryption();
                }
            }
        }

        private void completeAtEnd(boolean ended) {
            if (ended) {
                endOfInput = true;
                operationState.compareAndSet(OperationState.ENCRYPTING, OperationState.COMPLETED);
            }
        }
    }
}
