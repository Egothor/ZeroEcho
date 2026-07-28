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
 * Builders for composing streaming data-content pipelines across core sources
 * and algorithm-specific stages.
 *
 * <p>
 * This package groups the top-level builder APIs used by the SDK to create
 * streaming {@code DataContent} pipelines. It ties together the generic chain
 * and plain-source builders from {@link zeroecho.sdk.builders.core} with the
 * algorithm-focused builders from {@link zeroecho.sdk.builders.alg}, and
 * provides cross-cutting utilities such as
 * {@link TagTrailerDataContentBuilder}.
 * </p>
 *
 * <h2>What lives where</h2>
 * <ul>
 * <li><b>Core builders</b> - generic composition and plain sources in
 * {@link zeroecho.sdk.builders.core}:
 * <ul>
 * <li>{@link zeroecho.sdk.builders.core.DataContentBuilder} - minimal contract
 * implemented by all builders.</li>
 * <li>{@link zeroecho.sdk.builders.core.DataContentChainBuilder} - chains
 * multiple stages in encrypt or decrypt mode.</li>
 * <li>{@link zeroecho.sdk.builders.core.PlainBytesBuilder},
 * {@link zeroecho.sdk.builders.core.PlainStringBuilder},
 * {@link zeroecho.sdk.builders.core.PlainFileBuilder} - plain,
 * non-cryptographic sources.</li>
 * </ul>
 * </li>
 * <li><b>Algorithm builders</b> - streaming crypto stages in
 * {@link zeroecho.sdk.builders.alg}:
 * <ul>
 * <li>Symmetric encryption:
 * {@link zeroecho.sdk.builders.alg.AesDataContentBuilder},
 * {@link zeroecho.sdk.builders.alg.ChaChaDataContentBuilder}.</li>
 * <li>Asymmetric encryption:
 * {@link zeroecho.sdk.builders.alg.RsaEncDataContentBuilder},
 * {@link zeroecho.sdk.builders.alg.ElgamalEncDataContentBuilder}.</li>
 * <li>RSA signatures:
 * {@link zeroecho.sdk.builders.alg.RsaSigDataContentBuilder}; generic signature
 * trailers use {@link zeroecho.sdk.builders.SignatureTrailerDataContentBuilder}.</li>
 * <li>MAC and digest: {@link zeroecho.sdk.builders.alg.HmacDataContentBuilder},
 * {@link zeroecho.sdk.builders.alg.DigestDataContentBuilder}.</li>
 * <li>KEM envelopes: {@link zeroecho.sdk.builders.alg.KemDataContentBuilder}
 * (derives a symmetric key and injects it into a chosen symmetric payload
 * builder).</li>
 * </ul>
 * </li>
 * <li><b>Cross-cutting</b>:
 * <ul>
 * <li>{@link TagTrailerDataContentBuilder} - appends or verifies an
 * authentication tag carried as an input trailer using a
 * {@link zeroecho.core.tag.TagEngine}.</li>
 * <li>{@link SignatureTrailerDataContentBuilder} - signature-specialized
 * trailer builder intended to replace
 * {@code TagTrailerDataContentBuilder<Signature>} in most signature use cases.
 * It can wrap existing signature engines and construct single-algorithm and
 * hybrid signature contexts.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Chaining model</h2>
 * <p>
 * Pipelines are assembled by creating a
 * {@link zeroecho.sdk.builders.core.DataContentChainBuilder} in encrypt or
 * decrypt mode and adding builder stages in order. Each stage is built in the
 * selected mode, linked to the previous tail via {@code setInput(...)} and
 * exposed as a single tail {@link zeroecho.sdk.content.api.DataContent}.
 * </p>
 *
 * <h2>Headers, trailers, and verification</h2>
 * <ul>
 * <li>Symmetric builders can emit compact headers containing non-secret
 * parameters (for example, IV or nonce) and parse them on decrypt.</li>
 * <li>Signature and MAC builders support pass-through or emit-only forms for
 * signatures or tags.</li>
 * <li>{@link TagTrailerDataContentBuilder} focuses on trailer-style tags with
 * explicit verify policies.</li>
 * <li>{@link SignatureTrailerDataContentBuilder} provides the corresponding
 * trailer functionality specialized for digital signatures, including hybrid
 * signature construction.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Build a simple HMAC trailer pipeline over a plain string and append the tag.
 * zeroecho.sdk.content.api.DataContent macEnc =
 *     zeroecho.sdk.builders.core.DataContentChainBuilder.encrypt()
 *         .add(zeroecho.sdk.builders.core.PlainStringBuilder.builder().value("hello"))
 *         .add(new zeroecho.sdk.builders.TagTrailerDataContentBuilder(
 *                 zeroecho.core.tag.TagEngineBuilder.hmac(secretKey, zeroecho.core.alg.hmac.HmacSpec.sha256())))
 *         .build();
 *
 * // Build the corresponding verification pipeline that strips the trailer and throws on mismatch.
 * zeroecho.sdk.content.api.DataContent macDec =
 *     zeroecho.sdk.builders.core.DataContentChainBuilder.decrypt()
 *         .add(new zeroecho.sdk.builders.TagTrailerDataContentBuilder(
 *                 zeroecho.core.tag.TagEngineBuilder.hmac(secretKey, zeroecho.core.alg.hmac.HmacSpec.sha256())))
 *         .build();
 * }</pre>
 *
 * <h2>Thread safety</h2>
 * <ul>
 * <li>Builder instances are mutable and not thread-safe; configure and use each
 * instance on a single thread.</li>
 * <li>Produced {@code DataContent} stages are single-use and should not be
 * shared across pipelines.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.builders;
