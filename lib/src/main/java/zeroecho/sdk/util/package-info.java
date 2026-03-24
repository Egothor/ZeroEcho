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
 * Utility helpers for provider setup, key derivation, randomness, encoding, and
 * X.509 handling.
 *
 * <p>
 * This package gathers small, focused utilities used across the SDK: activation
 * of Bouncy Castle providers, RFC 5869 HKDF helpers, adapters that expose
 * output-style transforms as readable streams, streaming decoders for
 * length-prefixed payloads, password helpers, random-byte support, and simple
 * X.509 PEM utilities.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link BouncyCastleActivator} - one-time registration of Bouncy Castle
 * providers. A static initializer adds providers;
 * {@link BouncyCastleActivator#init()} can be called explicitly to confirm
 * activation.</li>
 * <li>{@link Kdf} - HKDF-SHA-256 derivation utilities for producing symmetric
 * keys from KEM or agreement secrets.</li>
 * <li>{@link OutputToInputStreamAdapter} - base class that adapts an
 * {@link java.io.OutputStream} driven transformation into an
 * {@link java.io.InputStream}; subclasses provide the transforming output and
 * the adapter exposes transformed bytes as they become available.</li>
 * <li>{@link Pack7LStreamWriter} - incremental writer that consumes a 7-bit
 * packed length prefix, then copies exactly that many payload bytes to a target
 * stream.</li>
 * <li>{@link Password} - helpers for generating random bytes and printable
 * passwords.</li>
 * <li>{@link RandomSupport} - shared or per-call
 * {@link java.security.SecureRandom} access with thread-safe helpers for
 * filling arrays.</li>
 * <li>{@link X509Support} - minimal PEM-based load and print helpers for
 * certificates, private keys, and certificate signing requests.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Ensure Bouncy Castle providers are present.
 * zeroecho.sdk.util.BouncyCastleActivator.init();
 *
 * // Derive 32 bytes with HKDF-SHA-256 for a symmetric key.
 * byte[] key = zeroecho.sdk.util.Kdf.hkdfSha256(ikm, salt, info, 32);
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Utilities avoid retaining sensitive material and prefer cloning caller
 * arrays where appropriate.</li>
 * <li>Streaming adapters do not buffer whole payloads except where transform
 * semantics require it.</li>
 * <li>Provider setup is explicit and emits concise diagnostics to aid
 * development.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.util;
