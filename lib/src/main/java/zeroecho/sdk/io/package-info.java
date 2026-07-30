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
 * Stream utilities for SDK pipelines.
 *
 * <p>
 * This package contains small helpers that adapt or post-process streams
 * produced by SDK builders and core contexts. Utilities focus on trailer
 * handling and other pipeline-friendly behaviors without buffering entire
 * payloads.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link SignatureTrailerInputStream} - a specialized tail-stripping stream
 * for signature workflows. It wraps a
 * {@link zeroecho.core.context.SignatureContext}, exposes only the original
 * body, and captures the trailing fixed-length signature. Built atop
 * {@link zeroecho.core.io.TailStrippingInputStream}.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Create a signature context (for example, Ed25519) in SIGN mode using your algorithm descriptor.
 * zeroecho.core.context.SignatureContext sc = ... created by an algorithm for SIGN ...;
 *
 * // Wrap the producing stream; only the body is exposed and the signature is delivered to a callback.
 * try (java.io.InputStream in = new zeroecho.sdk.io.SignatureTrailerInputStream(
 *          sc,
 *          upstream,                  // original message bytes
 *          8192,                      // buffer size for the stripper
 *          sig -> { ... store or transmit 'sig' ... })) {
 *     in.transferTo(out);             // writes only the body to 'out'
 * }
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Utilities are single-purpose and not thread-safe; create a new instance
 * per pipeline.</li>
 * <li>Resource ownership is explicit: where a stream is created from a core
 * context, closing the utility also closes the underlying context.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.io;
