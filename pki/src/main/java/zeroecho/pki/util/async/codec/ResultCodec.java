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
package zeroecho.pki.util.async.codec;

import java.util.Optional;

/**
 * Optional persistence codec for results.
 *
 * <p>
 * If results are sensitive or large, do not persist them in the bus log.
 * Instead, store results in a dedicated storage layer and persist only
 * references.
 * </p>
 *
 * @param <R> result type
 */
public interface ResultCodec<R> {

    /**
     * Encodes a result to a single-line string.
     *
     * @param result result (never {@code null})
     * @return encoded token (never blank)
     */
    String encode(R result);

    /**
     * Decodes a previously encoded result token.
     *
     * @param token token (never blank)
     * @return decoded result
     */
    R decode(String token);

    /**
     * Indicates whether this codec persists results in the bus log.
     *
     * @return true if results are persisted; false if results are not persisted
     */
    default boolean persistsResults() {
        return true;
    }

    /**
     * Convenience: a codec that never persists any result.
     *
     * @param <R> result type
     * @return codec that rejects encode/decode and signals non-persistence
     */
    static <R> ResultCodec<R> none() {
        return new ResultCodec<>() {
            @Override
            public String encode(R result) {
                throw new UnsupportedOperationException("Result persistence disabled.");
            }

            @Override
            public R decode(String token) {
                throw new UnsupportedOperationException("Result persistence disabled.");
            }

            @Override
            public boolean persistsResults() {
                return false;
            }
        };
    }

    /**
     * Convenience: optional decode wrapper.
     *
     * @param token token
     * @return optional decoded result (empty if token is empty)
     */
    default Optional<R> decodeOptional(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(decode(token));
    }
}
