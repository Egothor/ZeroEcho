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
 * Marshalling utilities and conventions for compact, human-readable
 * representations.
 *
 * <p>
 * This package defines a small SPI for bidirectional codecs and a lightweight
 * text representation for structured metadata. It enables algorithms and
 * specifications to serialize themselves into a simple key-value sequence and
 * reconstruct objects from that form.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link Codec} - a bidirectional contract between a domain type and a
 * serialized representation.</li>
 * <li>{@link PairSeq} - an immutable sequence of {@code String} key-value
 * pairs, optimized for compact transport.</li>
 * <li>{@link PairSeqCodec} - a reflection-based codec that adapts a domain type
 * to {@code PairSeq} by convention.</li>
 * </ul>
 *
 * <h2>Conventions</h2>
 * <ul>
 * <li>Domain types that use {@link PairSeqCodec} should provide
 * {@code marshal(): PairSeq} and either {@code static unmarshal(PairSeq)} or a
 * public constructor {@code T(PairSeq)}.</li>
 * <li>{@link PairSeq} text serialization uses one {@code key=value} pair per
 * line with optional comment lines starting with {@code #}. Binary values
 * should be Base64-encoded.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // A small domain type that follows the PairSeq convention.
 * public record User(String id, String name) {
 *     public PairSeq marshal() {
 *         return PairSeq.of("id", id, "name", name);
 *     }
 *     public static User unmarshal(PairSeq ps) {
 *         String id = null, name = null;
 *         for (PairSeq.Cursor c = ps.cursor(); c.next();) {
 *             if ("id".equals(c.key())) id = c.value();
 *             else if ("name".equals(c.key())) name = c.value();
 *         }
 *         return new User(id, name);
 *     }
 * }
 *
 * // Use a reflection-based codec for the domain type.
 * PairSeqCodec<User> codec = new PairSeqCodec<>(User.class);
 * PairSeq repr = codec.marshal(new User("u-1", "Alice"));
 * User copy = codec.unmarshal(repr);
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho.core.marshal;
