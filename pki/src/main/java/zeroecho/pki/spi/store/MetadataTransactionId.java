/* *****************************************************************************
 * Copyright (C) 2025, Leo Galambos
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
package zeroecho.pki.spi.store;

import java.util.Objects;

/**
 * Canonical durable transaction identity issued by one metadata store.
 *
 * <p>Constructing an equal value does not prove that the owning store issued it.</p>
 *
 * @param storeId durable owning-store identity
 * @param token 32 lowercase hexadecimal transaction token
 */
public record MetadataTransactionId(MetadataStoreId storeId, String token) {
    private static final String PREFIX = "v1:";

    /** Validates the canonical identity components. */
    public MetadataTransactionId {
        Objects.requireNonNull(storeId, "storeId");
        Objects.requireNonNull(token, "token");
        if (!token.matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException(
                    "Metadata transaction token must be 32 lowercase hexadecimal characters");
        }
    }

    /**
     * Parses one complete current canonical representation.
     *
     * @param encoded canonical representation
     * @return parsed identity
     * @throws NullPointerException if {@code encoded} is {@code null}
     * @throws IllegalArgumentException if the representation is malformed
     */
    public static MetadataTransactionId parse(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        String[] parts = encoded.split(":", -1);
        if (parts.length != 3 || !"v1".equals(parts[0])) {
            throw new IllegalArgumentException("Metadata transaction identifier is not canonical");
        }
        MetadataTransactionId result = new MetadataTransactionId(
                new MetadataStoreId(parts[1]), parts[2]);
        if (!result.toString().equals(encoded)) {
            throw new IllegalArgumentException("Metadata transaction identifier is not canonical");
        }
        return result;
    }

    /** Returns the complete current canonical representation. */
    @Override
    public String toString() {
        return PREFIX + storeId.value() + ":" + token;
    }
}
