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
package zeroecho.core.marshal;

/**
 * General-purpose bidirectional codec between a domain type {@code T} and a
 * serialized representation {@code R}.
 *
 * <p>
 * A {@code Codec} provides two complementary operations:
 * </p>
 * <ul>
 * <li>{@link #marshal(Object)} encodes a domain object into its representation
 * (e.g., object → string, object → byte array).</li>
 * <li>{@link #unmarshal(Object)} decodes a representation back into the domain
 * object.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>The type parameters {@code T} and {@code R} are application-defined; for
 * example, {@code Codec<MyMessage, byte[]>} or {@code Codec<Key, String>}.</li>
 * <li>Codecs are expected to be symmetric: unmarshalling the result of
 * marshalling yields an equivalent domain object, subject to lossiness in the
 * chosen representation.</li>
 * <li>Implementations should document whether {@code null} values are
 * permitted, and whether marshalling is deterministic.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * Codec<Integer, String> intToString = new Codec<>() {
 *     public String marshal(Integer value) { return value.toString(); }
 *     public Integer unmarshal(String repr) { return Integer.parseInt(repr); }
 * };
 *
 * String repr = intToString.marshal(42);   // "42"
 * int val = intToString.unmarshal("42");   // 42
 * }</pre>
 *
 * @param <T> domain type to encode and decode
 * @param <R> representation type (serialized form)
 */
public interface Codec<T, R> {
    /**
     * Converts a domain value into its serialized representation.
     *
     * @param value domain object to encode
     * @return representation corresponding to {@code value}
     * @throws IllegalArgumentException if {@code value} is invalid or cannot be
     *                                  encoded
     */
    R marshal(T value);

    /**
     * Converts a serialized representation back into the domain object.
     *
     * @param repr representation to decode
     * @return domain object reconstructed from {@code repr}
     * @throws IllegalArgumentException if {@code repr} is malformed or cannot be
     *                                  decoded
     */
    T unmarshal(R repr);
}
