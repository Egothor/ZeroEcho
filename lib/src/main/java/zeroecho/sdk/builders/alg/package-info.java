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
/**
 * Streaming cryptographic builders for symmetric encryption, signatures, MACs,
 * digests, and KEM envelopes.
 *
 * <p>
 * Classes in this package provide small, composable builders that configure
 * cryptographic operations and produce streaming {@code DataContent} stages.
 * The emphasis is on zero-copy streaming where feasible, clear separation
 * between configuration (builders) and execution (content stages), and
 * provider-agnostic algorithm lookup via the central registry.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>Enable large-payload processing without materializing data in
 * memory.</li>
 * <li>Keep configuration fluent and explicit; keep execution
 * pipeline-friendly.</li>
 * <li>Resolve algorithms through the registry so applications can swap JCA
 * providers easily.</li>
 * <li>Offer explicit control of headers, trailers, and verification behavior
 * where applicable.</li>
 * </ul>
 *
 * <h2>Builders overview</h2>
 * <ul>
 * <li>{@link AesDataContentBuilder} and {@link ChaChaDataContentBuilder} -
 * stream symmetric encryption and decryption.</li>
 * <li>{@link HmacDataContentBuilder} - compute or verify MAC tags in a
 * streaming pipeline.</li>
 * <li>{@link DigestDataContentBuilder} - compute digests/XOFs and, where
 * supported, emit textual encodings.</li>
 * <li>{@link RsaEncDataContentBuilder} and {@link ElgamalEncDataContentBuilder}
 * - wrap asymmetric encryption.</li>
 * <li>{@link RsaSigDataContentBuilder}, {@link EcdsaDataContentBuilder},
 * {@link Ed25519DataContentBuilder}, {@link Ed448DataContentBuilder},
 * {@link SphincsPlusDataContentBuilder}, {@link SlhDsaDataContentBuilder}, and
 * {@link MldsaDataContentBuilder} - perform streaming signatures and
 * verification.</li>
 * <li>{@link KemDataContentBuilder} - implement KEM-first envelopes and inject
 * the derived key into a chosen symmetric payload builder.</li>
 * </ul>
 *
 * <h2>Streaming model</h2>
 * <p>
 * Each builder implements a content-builder contract and produces a
 * {@code DataContent} stage when built. The stage uses the registry to obtain a
 * core context and attaches to an upstream {@link java.io.InputStream}; output
 * is produced lazily as the stream is read. Signature and MAC stages can pass
 * the body through while appending or verifying a trailing tag; symmetric
 * stages may emit a compact header with non-secret parameters such as IV,
 * nonce, tag length, or AAD hints.
 * </p>
 *
 * <h2>Signatures and MACs</h2>
 * <p>
 * Signature builders share common mechanics via
 * {@link AbstractStreamingSignatureDataBuilder}. They support:
 * </p>
 * <ul>
 * <li><b>Pass-through:</b> output the message body while a trailing signature
 * is captured or verified.</li>
 * <li><b>Emit-only:</b> consume the body and output only the signature (or a
 * boolean verification result, when selected).</li>
 * </ul>
 * <p>
 * MAC builders mirror this pattern and can verify against an expected tag or a
 * tag carried in the input trailer.
 * </p>
 *
 * <h2>KEM envelopes</h2>
 * <p>
 * {@link KemDataContentBuilder} first collects KEM parameters (algorithm id,
 * recipient key, KDF configuration), runs encapsulation or decapsulation to
 * derive a symmetric key, and then injects that key into an explicit symmetric
 * payload builder such as {@link AesDataContentBuilder} or
 * {@link ChaChaDataContentBuilder}. This avoids duplicating KEM configuration
 * across symmetric builders and matches a natural envelope workflow.
 * </p>
 *
 * <h2>Key management</h2>
 * <ul>
 * <li>Use a caller-supplied key object.</li>
 * <li>Generate a new key or key pair using an algorithm-specific key-generation
 * spec.</li>
 * <li>Import a key from standard encodings (for example, X.509 public or PKCS#8
 * private) or other supported forms.</li>
 * </ul>
 * <p>
 * Builders typically provide convenience methods for common defaults (for
 * example, AES-GCM or Ed25519).
 * </p>
 *
 * <h2>Error handling and verification</h2>
 * <ul>
 * <li>Verification failures usually surface as {@code IOException} at
 * end-of-stream in verify mode.</li>
 * <li>Some builders offer explicit emit-boolean modes or callbacks to report
 * verification outcomes without throwing.</li>
 * <li>Configuration errors (incompatible keys/specs) are detected early by
 * underlying core factories.</li>
 * </ul>
 *
 * <h2>Usage pattern</h2> <pre>{@code
 * // A builder in this package produces a DataContent stage:
 * zeroecho.sdk.content.api.DataContent content = ...;
 *
 * // Wire the upstream and stream the result to an output sink:
 * content.setInput(upstreamContent);
 * try (java.io.InputStream in = content.getStream()) {
 *     in.transferTo(out);
 * }
 * }</pre>
 *
 * <h2>Thread safety</h2>
 * <ul>
 * <li>Builder instances are mutable and not thread-safe; configure and use each
 * instance on a single thread.</li>
 * <li>Produced content stages are single-use; create a fresh instance per
 * pipeline run.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.builders.alg;