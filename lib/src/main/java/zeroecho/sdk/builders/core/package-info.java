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
/**
 * Core builders for composing streaming {@code DataContent} pipelines and plain
 * sources.
 *
 * <p>
 * This package provides a small set of generic builder interfaces plus
 * plain-content builders for bytes, strings, and files. Builders create
 * {@code DataContent} stages that can be chained so that each stage reads from
 * the previous one while applying transformation or sourcing bytes.
 * </p>
 *
 * <h2>What is here</h2>
 * <ul>
 * <li>{@link DataContentBuilder} - functional interface that builds a
 * {@code DataContent} configured for encryption or decryption.</li>
 * <li>{@link DataContentChainBuilder} - composes multiple
 * {@code DataContentBuilder} instances into one tail stage via
 * {@code setInput(...)} chaining.</li>
 * <li>{@link PlainBytesBuilder} - wraps a caller-provided byte array as plain
 * content.</li>
 * <li>{@link PlainStringBuilder} - wraps a {@code String} as plain
 * content.</li>
 * <li>{@link PlainFileBuilder} - wraps a {@link java.net.URL}-addressed file as
 * plain content.</li>
 * </ul>
 *
 * <h2>Chaining model</h2>
 * <p>
 * A chain builder holds the current tail stage. Each {@code add(...)} call
 * builds the next stage (in a consistent encrypt/decrypt mode) and links the
 * previous tail as its input. The final {@code build()} returns the tail, which
 * internally references the rest of the chain via {@code setInput(...)}.
 * </p>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Encrypt: plain text -> (for example) AES-GCM stage defined elsewhere.
 * zeroecho.sdk.content.api.DataContent chain =
 *     zeroecho.sdk.builders.core.DataContentChainBuilder.encrypt()
 *         .add(zeroecho.sdk.builders.core.PlainStringBuilder.builder().value("hello"))
 *         // .add(zeroecho.sdk.builders.alg.AesDataContentBuilder.builder().modeGcm(128).generateKey(256))
 *         .build();
 *
 * // Decrypt: build the inverse chain with the decrypt() factory.
 * zeroecho.sdk.content.api.DataContent decChain =
 *     zeroecho.sdk.builders.core.DataContentChainBuilder.decrypt()
 *         // .add(zeroecho.sdk.builders.alg.AesDataContentBuilder.builder().modeGcm(128).withHeader())
 *         .build();
 * }</pre>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>Plain-content builders ignore the encrypt/decrypt flag; they simply
 * provide bytes.</li>
 * <li>Builders and produced stages are not thread-safe; configure and use per
 * pipeline.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.builders.core;
