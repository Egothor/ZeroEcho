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
 * Helpers for generating pseudo-random cover text using character frequency
 * tables.
 *
 * <p>
 * This package provides utilities for producing benign-looking textual fillers
 * that mimic the statistical properties of a target language. The primary use
 * is to generate cover text for covert or steganographic workflows where
 * ciphertext or opaque data needs a plausible textual carrier. These helpers do
 * not offer confidentiality by themselves; combine them with encryption when
 * handling secrets.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link TextualCodec} - utility container for text-oriented helpers.</li>
 * <li>{@link TextualCodec.Generator} - frequency-driven character generator
 * with a default English distribution and APIs to produce single characters or
 * fixed-length strings.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Use the built-in English distribution (factory creates a fresh, non-shared instance).
 * zeroecho.ext.integrations.covert.TextualCodec.Generator gen =
 *     zeroecho.ext.integrations.covert.TextualCodec.Generator.english();
 * String sample = gen.getText(256);
 *
 * // Or construct a custom distribution.
 * java.util.Map<Character, Double> freq = java.util.Map.ofEntries(
 *     java.util.Map.entry('e', 12.7), java.util.Map.entry('t', 9.1),
 *     java.util.Map.entry('a', 8.2),  java.util.Map.entry(' ', 25.4)
 * );
 * zeroecho.ext.integrations.covert.TextualCodec.Generator custom =
 *     new zeroecho.ext.integrations.covert.TextualCodec.Generator(freq);
 * String cover = custom.getText(128);
 * }</pre>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>Generated text is intended as camouflage, not as a security control.</li>
 * <li>Distributions should be non-negative and representative of the intended
 * cover domain.</li>
 * <li>Instances are not thread-safe; use a separate generator per thread.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.ext.integrations.covert;
