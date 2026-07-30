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
/**
 * I/O helpers for block-based transforms, passthrough processing, and tail
 * handling.
 *
 * <p>
 * This package provides building blocks for cryptographic I/O:
 * chunk-transforming streams that call into a cipher, passthrough streams that
 * compute or append trailers, a builder for configuring cipher-backed streams,
 * a tail-stripping stream, and small I/O utilities. Components are designed to
 * be allocation-conscious and to make finalization output (padding blocks, AEAD
 * tags) explicit and predictable.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link AbstractChunkTransformInputStream} - base class that reads
 * upstream data in aligned chunks and lets subclasses implement
 * {@code transform(...)} and {@code doFinal(...)}.</li>
 * <li>{@link AbstractPassthroughInputStream} - forwards body bytes unchanged,
 * invokes {@code update(...)} on each chunk, optionally emits a single trailer,
 * then calls {@code onCompleted()} exactly once at EOF.</li>
 * <li>{@link CipherTransformInputStreamBuilder} - fluent builder that creates
 * cipher-backed streams for RSA/ElGamal independent-block processing,
 * left-zero-padded independent blocks, or continuous
 * {@code update}+{@code doFinal} streaming.</li>
 * <li>{@link SmartBlockStream}, {@link SmartPaddedBlockStream},
 * {@link SmartContinuousBlockStream} - internal cipher-backed stream variants;
 * the first two are restricted to independent RSA or ElGamal blocks used by the
 * builder.</li>
 * <li>{@link TailStrippingInputStream} - withholds the last N bytes from the
 * payload and delivers them to a callback at EOF (useful for tags, checksums,
 * or footers).</li>
 * <li>{@link Util} - static helpers for compact length-prefix I/O, UTF-8, UUID,
 * and packed 7-bit integers.</li>
 * </ul>
 *
 * <h2>Typical usage</h2>
 * <h3>Build a streaming AES/GCM transform</h3> <pre>{@code
 * javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NOPADDING");
 * javax.crypto.spec.GCMParameterSpec gcm = new javax.crypto.spec.GCMParameterSpec(128, ivBytes);
 * cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, gcm);
 *
 * java.io.InputStream s = zeroecho.core.io.CipherTransformInputStreamBuilder.builder()
 *     .withUpstream(upstream)
 *     .withCipher(cipher)
 *     .withUpdateStreaming()          // use update(...) for bulk, doFinal() at EOF
 *     .withInputBlockSize(16)         // logical chunking for I/O
 *     .withOutputBlockSize(16)
 *     .withBufferedBlocks(200)        // steady-state buffering
 *     .withFinalizationOutputChunks(2) // room for tail bytes + 16-byte tag
 *     .build();
 *
 * // Pipe transformed bytes
 * s.transferTo(out);
 * s.close();
 * }</pre>
 *
 * <h3>Strip a fixed trailer (for example, 16-byte tag) from the end of a
 * stream</h3> <pre>{@code
 * int tagLen = 16;
 * zeroecho.core.io.TailStrippingInputStream in =
 *     new zeroecho.core.io.TailStrippingInputStream(raw, tagLen, 4096) {
 *         &#64;Override
 *         protected void processTail(byte[] tail) throws java.io.IOException {
 *             // verify MAC, parse footer, etc. (do not write to 'out' here)
 *         }
 *     };
 *
 * // Read payload only; the last 'tagLen' bytes are withheld and delivered to processTail(...)
 * byte[] payload = in.readAllBytes();
 * in.close(); // ensures processTail(...) runs even if not fully consumed
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Streams are not thread-safe; use one instance per pipeline.</li>
 * <li>Finalization headroom is explicit: reserve extra output chunks when a
 * mode emits padding or tags at EOF.</li>
 * <li>{@code close()} implementations drain upstream as needed to guarantee
 * trailer emission and completion hooks.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.io;
