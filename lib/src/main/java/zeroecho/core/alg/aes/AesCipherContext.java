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
package zeroecho.core.alg.aes;

import java.io.IOException;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

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
 * Streaming AES cipher context for GCM / CBC / CTR.
 *
 * <p>
 * IV and optional AAD are exchanged via a {@link conflux.CtxInterface} set with
 * {@link #setContext(conflux.CtxInterface)}. Encryption always generates a fresh
 * IV after atomically claiming the context; a caller-provided IV is never used
 * for encryption. Decryption requires the IV from the context or encoded header.
 * </p>
 *
 * <p>
 * When a {@link zeroecho.core.SymmetricHeaderCodec} is embedded in the
 * {@link AesSpec} and a context is present, the context reads/writes a minimal
 * header carrying IV, tag bits, and an optional AAD hash.
 * </p>
 *
 * @since 1.0
 */
public final class AesCipherContext implements EncryptionContext, ContextAware {
    private static final Logger LOG = Logger.getLogger(AesCipherContext.class.getName());

    private static final int AES_BLOCK = 16;
    private static final int GCM_DEFAULT_IV_BYTES = 12;

    private final CryptoAlgorithm algorithm;
    private final SecretKey key;
    private final boolean encrypt;
    private final AesSpec spec;
    private final SecureRandom rnd;
    private final AtomicReference<OperationState> operationState = new AtomicReference<>(OperationState.NEW);

    private volatile CtxInterface ctx; // NOPMD

    /**
     * Creates a new AES streaming context.
     *
     * @param algorithm the owning algorithm descriptor (ID {@code "AES"}); not null
     * @param key       the AES {@link SecretKey}; not null
     * @param encrypt   whether this context encrypts ({@code true}) or decrypts
     *                  ({@code false})
     * @param spec      static AES settings (mode/padding and GCM tag bits); not
     *                  null
     * @param rnd       secure random source; if null, the library's shared source
     *                  is used
     * @throws NullPointerException     if any required parameter is null
     * @throws IllegalArgumentException if {@code spec} is inconsistent (e.g., GCM
     *                                  without NOPADDING)
     */
    public AesCipherContext(CryptoAlgorithm algorithm, SecretKey key, boolean encrypt, AesSpec spec, SecureRandom rnd) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.key = Objects.requireNonNull(key, "secret key must not be null");
        this.encrypt = encrypt;
        this.spec = Objects.requireNonNull(spec, "spec must not be null");
        this.rnd = (rnd != null ? rnd : RandomSupport.getRandom());
    }

    /**
     * Returns the algorithm descriptor (ID {@code "AES"}).
     *
     * @return the algorithm
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * @return the secret key
     */
    @Override
    public java.security.Key key() {
        return key;
    }

    /**
     * Sets the Conflux session context used to exchange IV/AAD/tagBits and to
     * enable header I/O.
     *
     * @param context the context; may be {@code null} to disable context features
     */
    @Override
    public void setContext(CtxInterface context) {
        this.ctx = context;
    }

    /**
     * Returns the currently set Conflux context (possibly {@code null}).
     *
     * @return the context or {@code null}
     */
    @Override
    public CtxInterface context() {
        return ctx;
    }

    /**
     * Attaches this context to an upstream stream and returns a transforming
     * stream.
     * <ul>
     * <li>Decrypt + header → reads header first, hydrates context, then
     * transforms</li>
     * <li>Transform → initializes JCA cipher with IV/AAD (GCM), staging final
     * output if necessary</li>
     * <li>Encrypt + header → prepends header after IV is determined</li>
     * </ul>
     *
     * @param upstream the source stream; not null
     * @return a stream that yields ciphertext (encrypt) or plaintext (decrypt)
     * @throws IOException on I/O or provider errors; includes IV length mismatches
     *                     and missing IV for decrypt
     */
    @Override
    public InputStream attach(InputStream upstream) throws IOException {
        Objects.requireNonNull(upstream, "upstream must not be null");
        claimEncryption();
        boolean attached = false;
        try {
            // If both spec.header() and ctx are present, let this context read/write the
            // header.
            final SymmetricHeaderCodec header = spec.header();
            final boolean activeHeader = (ctx != null) && header != null;

            InputStream in = upstream;
            if (!encrypt && activeHeader) {
                // DECRYPT: parse header first; hydrate ctx (IV / tag bits / AAD check).
                LOG.log(Level.FINE, "decryption: reading header for {0}", algorithm);
                in = header.readHeader(in, algorithm, ctx);
            }

            Cipher cipher = Cipher.getInstance(jcaTransform(spec));
            initCipher(cipher);

            InputStream out = // new Stream(in, cipher, spec);
                    CipherTransformInputStreamBuilder.builder().withCipher(cipher).withUpstream(in)
                            .withUpdateStreaming().withInputBlockSize(AES_BLOCK).withOutputBlockSize(AES_BLOCK)
                            .withFinalizationOutputChunks(2).build();
            if (encrypt && activeHeader) {
                // ENCRYPT: after IV exists in ctx, prepend header
                LOG.log(Level.FINE, "encryption: reading header for {0}", algorithm);
                java.io.ByteArrayOutputStream hdr = new java.io.ByteArrayOutputStream(64);
                header.writeHeader(hdr, algorithm, ctx);
                out = new java.io.SequenceInputStream(new java.io.ByteArrayInputStream(hdr.toByteArray()), out);
            }
            attached = true;
            return encrypt ? new LifecycleInputStream(out) : out;
        } catch (GeneralSecurityException e) {
            throw new ProviderFailureException("AES attach/init failed", e);
        } finally {
            if (!attached) {
                failEncryption();
            }
        }
    }

    @Override
    public void close() {
        /* no-op; stream finalizes itself */
    }

    // ---- internals ----

    private static String jcaTransform(AesSpec s) {
        return switch (s.mode()) {
            case GCM -> "AES/GCM/NOPADDING";
            case CTR -> "AES/CTR/NOPADDING";
            case CBC -> "AES/CBC/" + s.padding().name();
        };
    }

    private void initCipher(Cipher cipher) throws GeneralSecurityException, IOException {
        final String id = algorithm.id();
        byte[] iv;

        final int ivLen = (spec.mode() == AesSpec.Mode.GCM) ? GCM_DEFAULT_IV_BYTES : AES_BLOCK;

        if (encrypt) {
            iv = new byte[ivLen];
            rnd.nextBytes(iv);
            putCtxBytes(ConfluxKeys.iv(id), iv.clone());
        } else {
            iv = getCtxBytes(ConfluxKeys.iv(id));
            if (iv == null) {
                throw new IOException("IV not found in context for AES " + spec.mode() + " decryption");
            }
            if (iv.length != ivLen) {
                throw new IOException("IV length mismatch: expected " + ivLen + " bytes, got " + iv.length);
            }
        }

        switch (spec.mode()) {
            case GCM: {
                int tagBits = 0;
                if (ctx != null) {
                    Integer val = ctx.get(ConfluxKeys.tagBits(id));
                    if (val != null) {
                        tagBits = val;
                    }
                }
                // tagBits was not in ctx => spec settings are applied
                if (tagBits < 1) { // NOPMD
                    tagBits = spec.tagLenBits() > 0 ? spec.tagLenBits() : 128;
                }
                GCMParameterSpec gps = new GCMParameterSpec(tagBits, iv);
                cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, gps);
                byte[] aad = getCtxBytes(ConfluxKeys.aad(id));
                if (aad == null) {
                    // AAD should be defined empty
                    aad = new byte[0];
                    putCtxBytes(ConfluxKeys.aad(id), aad);
                }
                cipher.updateAAD(aad);

                LOG.log(Level.FINE, "GCM setup complete: tagBits={0}", tagBits);

                break;
            }
            case CTR:
            case CBC: {
                cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                break;
            }
        }
    }

    private byte[] getCtxBytes(conflux.Key<byte[]> key) {
        if (ctx == null || key == null) {
            return null; // NOPMD
        }
        return ctx.get(key);
    }

    private void putCtxBytes(conflux.Key<byte[]> key, byte[] value) {
        if (ctx != null && key != null) {
            ctx.put(key, value);
        }
    }

    private void claimEncryption() throws IOException {
        if (encrypt && !operationState.compareAndSet(OperationState.NEW, OperationState.ENCRYPTING)) {
            throw new IOException("AES encryption context is single-use");
        }
    }

    private void failEncryption() {
        if (encrypt) {
            operationState.set(OperationState.FAILED);
        }
    }

    /** Single-use encryption lifecycle states. */
    private enum OperationState {
        NEW,
        ENCRYPTING,
        COMPLETED,
        FAILED
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
