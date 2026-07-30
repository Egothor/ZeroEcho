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
package zeroecho.core.io;

import java.io.InputStream;
import java.util.Objects;

import javax.crypto.Cipher;

/**
 * Builder for chunk-transforming {@link InputStream}s backed by a
 * {@link Cipher}.
 *
 * <p>
 * This builder configures and creates an {@code InputStream} that reads from an
 * upstream source and applies a block-based transformation using a provided
 * {@link Cipher}. Three stream variants are available:
 * </p>
 * <ul>
 * <li><b>Independent block stream</b> - invokes
 * {@link Cipher#doFinal(byte[], int, int, byte[], int)} for each full input
 * block; a final partial block (if any) is processed by a single
 * {@code doFinal}. This mode is restricted to RSA and ElGamal.</li>
 * <li><b>Left-padded independent block stream</b> - like the independent block
 * stream, but left-pads each transformed output block with zeros up to
 * {@code outChunkSize}. Final blocks must be complete; otherwise an
 * {@link IllegalStateException} is thrown.</li>
 * <li><b>Continuous stream</b> - uses {@code Cipher.update(...)} for bulk bytes
 * and a single {@code doFinal()} at end of stream. This is suitable for
 * CTR/CFB/OFB/GCM and padding modes.</li>
 * </ul>
 *
 * <h2>Block sizing</h2>
 * <p>
 * The builder exposes {@code inChunkSize} and {@code outChunkSize}. For AES in
 * ECB/CBC/CTR-like modes these are typically 16 bytes, but the stream can use
 * larger logical chunks for I/O efficiency. The implementation buffers up to
 * {@code bufferedBlocks} chunks per fill to balance throughput and memory.
 * </p>
 *
 * <h2>Finalization headroom</h2>
 * <p>
 * Some ciphers or modes produce extra bytes at end-of-stream (for example, a
 * padding block for CBC/PKCS5 or an authentication tag for GCM). To ensure the
 * final {@code doFinal(...)} fits even when the steady-state output area is
 * full, you can reserve additional output capacity via
 * {@link #withFinalizationOutputChunks(int)}. This increases only the
 * output-side buffer, leaving the input buffer size unchanged.
 * </p>
 *
 * <h2>Thread-safety</h2> Instances produced by this builder are not
 * thread-safe. Do not share a single stream across threads without external
 * synchronization.
 *
 * <h2>Examples</h2> <pre>{@code
 * // AES/ECB/NOPADDING: aligned input, no extra finalization output
 * Cipher c1 = Cipher.getInstance("AES/ECB/NOPADDING");
 * c1.init(Cipher.ENCRYPT_MODE, key);
 * InputStream s1 = CipherTransformInputStreamBuilder.builder()
 *     .withUpstream(in)
 *     .withCipher(c1)
 *     .withUpdateStreaming(true)     // allowed; final len must be multiple of 16
 *     .withInputBlockSize(16)
 *     .withOutputBlockSize(16)
 *     .withBufferedBlocks(200)
 *     .withFinalizationOutputChunks(0)
 *     .build();
 *
 * // AES/CBC/PKCS5PADDING: one final padding block
 * Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
 * c2.init(Cipher.ENCRYPT_MODE, key, ivSpec);
 * InputStream s2 = CipherTransformInputStreamBuilder.builder()
 *     .withUpstream(in)
 *     .withCipher(c2)
 *     .withUpdateStreaming(true)
 *     .withInputBlockSize(16)
 *     .withOutputBlockSize(16)
 *     .withBufferedBlocks(200)
 *     .withFinalizationOutputChunks(1)
 *     .build();
 *
 * // AES/GCM/NOPADDING (16-byte tag): tail + tag -> reserve two chunks
 * Cipher c3 = Cipher.getInstance("AES/GCM/NOPADDING");
 * c3.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
 * InputStream s3 = CipherTransformInputStreamBuilder.builder()
 *     .withUpstream(in)
 *     .withCipher(c3)
 *     .withUpdateStreaming(true)
 *     .withInputBlockSize(16).withOutputBlockSize(16)
 *     .withBufferedBlocks(200)
 *     .withFinalizationOutputChunks(2)
 *     .build();
 *
 * // ElGamal (asymmetric; non-streaming semantics): no extra finalization output
 * Cipher c4 = Cipher.getInstance("ElGamal/None/NOPADDING"); // provider-specific
 * c4.init(Cipher.ENCRYPT_MODE, publicKey, params);
 * InputStream s4 = CipherTransformInputStreamBuilder.builder()
 *     .withUpstream(in)
 *     .withCipher(c4)
 *     .withIndependentBlocks()
 *     .withInputBlockSize(elgIn)
 *     .withOutputBlockSize(elgOut)
 *     .withBufferedBlocks(200)
 *     .withFinalizationOutputChunks(0)
 *     .build();
 * }</pre>
 *
 * @since 1.0
 */
public final class CipherTransformInputStreamBuilder {
    private InputStream upstream;
    private Cipher cipher;
    private int inChunkSize = 256;
    private int outChunkSize = 256;
    private int bufferedBlocks = 100;
    /**
     * When > 0, enlarges the output buffer by this many extra chunks for the
     * finalization burst.
     */
    private int finalizationOutputChunks;
    private boolean padding;
    private boolean updateStreaming; // when true, use SmartContinuousBlockStream

    private CipherTransformInputStreamBuilder() {
    }

    /**
     * Returns a new builder instance with default settings.
     *
     * <p>
     * Defaults: {@code inChunkSize=256}, {@code outChunkSize=256},
     * {@code bufferedBlocks=100}, padding disabled.
     * </p>
     *
     * @return a new builder
     */
    public static CipherTransformInputStreamBuilder builder() {
        return new CipherTransformInputStreamBuilder();
    }

    /**
     * Sets the upstream source from which bytes will be read and transformed.
     *
     * @param upstream the input stream to wrap; must not be null
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withUpstream(InputStream upstream) {
        this.upstream = upstream;
        return this;
    }

    /**
     * Sets the {@link Cipher} used to transform blocks.
     *
     * <p>
     * The cipher must be fully initialized for the intended mode (encrypt or
     * decrypt) before calling {@link #build()}.
     * </p>
     *
     * @param cipher initialized cipher instance; must not be null
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withCipher(Cipher cipher) {
        this.cipher = cipher;
        return this;
    }

    /**
     * Configures whether left zero padding is applied to each output block.
     *
     * <p>
     * If set to {@code true}, the builder will produce a padded stream variant
     * where each block is left-filled with zeros up to {@code outChunkSize}. If
     * {@code false}, the plain non-padded variant is used.
     * </p>
     *
     * @param padding {@code true} to enable left zero padding, {@code false} to
     *                disable it
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withLeftZeroPadding(boolean padding) {
        this.padding = padding;
        return this;
    }

    /**
     * Sets the size of a single input block fed to the cipher.
     *
     * @param inSize input chunk size in bytes; must be > 1
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withInputBlockSize(int inSize) {
        this.inChunkSize = inSize;
        return this;
    }

    /**
     * Sets the size of a single output block expected from the cipher.
     *
     * @param outSize output chunk size in bytes; must be > 0
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withOutputBlockSize(int outSize) {
        this.outChunkSize = outSize;
        return this;
    }

    /**
     * Sets the number of blocks buffered per internal fill cycle.
     *
     * <p>
     * The internal buffers will be sized to {@code inChunkSize * bufferedBlocks}
     * and {@code outChunkSize * bufferedBlocks}.
     * </p>
     *
     * @param bufferedBlocks number of blocks to buffer; must be > 0
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withBufferedBlocks(int bufferedBlocks) {
        this.bufferedBlocks = bufferedBlocks;
        return this;
    }

    /**
     * Sets the number of extra output chunks reserved for the finalization step.
     *
     * <p>
     * Some modes may emit additional bytes at the very end (padding block for
     * CBC/PKCS5, authentication tag for GCM/CCM/EAX, provider flush). The output
     * buffer is allocated with {@code bufferedBlocks + finalizationOutputChunks}
     * chunks to guarantee that the final {@code doFinal(...)} fits even when the
     * steady-state area is full.
     * </p>
     *
     * <h4>Recommended values</h4>
     * <ul>
     * <li><b>AES/CBC/PKCS5PADDING</b>: {@code 1}</li>
     * <li><b>AES/GCM (16-byte tag)</b>: {@code 2}</li>
     * <li><b>AES/CTR, CFB, OFB</b>: {@code 1} (covers a tail up to 15 bytes)</li>
     * <li><b>AES/CBC/NOPADDING</b>: {@code 0} (total length must be a multiple of
     * block size)</li>
     * <li><b>ElGamal/RSA</b>: {@code 0} (non-streaming; no extra finalization
     * block)</li>
     * </ul>
     *
     * <h4>Notes</h4>
     * <ul>
     * <li>For GCM with a different tag size, use
     * {@code ceil((15 + tagLen)/outChunkSize)}. With 12–16 byte tags and
     * {@code outChunkSize=16}, {@code 2} is still safe.</li>
     * <li>This setting enlarges only the <i>output</i> buffer capacity; the input
     * buffer remains {@code inChunkSize * bufferedBlocks}.</li>
     * </ul>
     *
     * @param chunks extra output chunks reserved for finalization; must be
     *               {@code >= 0}
     * @return this builder for chaining
     */
    public CipherTransformInputStreamBuilder withFinalizationOutputChunks(int chunks) {
        this.finalizationOutputChunks = chunks;
        return this;
    }

    /**
     * Enables update-driven streaming (Cipher.update during transform, single
     * doFinal at EOF). Suitable for CTR/CFB/OFB/GCM and padding modes.
     */
    public CipherTransformInputStreamBuilder withUpdateStreaming() {
        this.updateStreaming = true;
        return this;
    }

    /**
     * Controls update-driven streaming explicitly.
     *
     * @param enable true to use update-driven streaming, false for per-block
     *               doFinal variant
     * @return this builder
     */
    public CipherTransformInputStreamBuilder withUpdateStreaming(boolean enable) {
        this.updateStreaming = enable;
        return this;
    }

    /**
     * Selects independent-block processing, in which every logical input block is
     * passed to a separate {@link Cipher#doFinal(byte[], int, int, byte[], int)}
     * invocation.
     *
     * <p>
     * This mode is supported only for RSA and ElGamal transformations. Stateful
     * symmetric modes, including AES-GCM and AES-CBC, must use
     * {@link #withUpdateStreaming()}.
     * </p>
     *
     * @return this builder
     */
    public CipherTransformInputStreamBuilder withIndependentBlocks() {
        this.updateStreaming = false;
        return this;
    }

    /**
     * Builds a chunk-transforming {@link InputStream} using the configured options.
     *
     * <p>
     * The returned stream pulls from {@code upstream} and applies the configured
     * {@code cipher}. The output buffer is allocated to
     * {@code outChunkSize * (bufferedBlocks + finalizationOutputChunks)} bytes so
     * that the final {@code doFinal(...)} can emit padding or tags even when the
     * steady-state output window is full.
     * </p>
     *
     * @return a new InputStream that transforms bytes on the fly
     * @throws NullPointerException     if {@code upstream} or {@code cipher} is
     *                                  null
     * @throws IllegalArgumentException if independent-block processing is selected
     *                                  for an unsupported algorithm or buffer
     *                                  geometry is invalid
     */
    public InputStream build() {
        Objects.requireNonNull(upstream, "upstream must not be null");
        Objects.requireNonNull(cipher, "cipher must not be null");

        if (updateStreaming) {
            return new SmartContinuousBlockStream(upstream, cipher, inChunkSize, outChunkSize, bufferedBlocks,
                    finalizationOutputChunks);
        }
        validateIndependentBlockAlgorithm(cipher);
        return padding ? new SmartPaddedBlockStream(upstream, cipher, inChunkSize, outChunkSize, bufferedBlocks)
                : new SmartBlockStream(upstream, cipher, inChunkSize, outChunkSize, bufferedBlocks);
    }

    private static void validateIndependentBlockAlgorithm(Cipher cipher) {
        String transformation = cipher.getAlgorithm();
        int separator = transformation.indexOf('/');
        String baseAlgorithm = separator < 0 ? transformation : transformation.substring(0, separator);
        if (!"RSA".equalsIgnoreCase(baseAlgorithm) && !"ElGamal".equalsIgnoreCase(baseAlgorithm)) {
            throw new IllegalArgumentException(
                    "Independent-block processing supports only RSA and ElGamal transformations");
        }
    }
}
