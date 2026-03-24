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
package zeroecho.pki.api.attr;

import java.time.Instant;

/**
 * Typed attribute value.
 *
 * <p>
 * Values are modeled as a sealed hierarchy for type safety and deterministic
 * mapping. Implementations must treat values as potentially sensitive and apply
 * redaction where required.
 * </p>
 */
public sealed interface AttributeValue permits AttributeValue.StringValue, AttributeValue.BooleanValue,
        AttributeValue.IntegerValue, AttributeValue.InstantValue, AttributeValue.BytesValue {

    /**
     * String value.
     *
     * @param value string content (may be empty depending on attribute definition)
     */
    record StringValue(String value) implements AttributeValue {

        /**
         * Creates a string value.
         *
         * @param value string content
         * @throws IllegalArgumentException if {@code value} is null
         */
        public StringValue {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    /**
     * Boolean value.
     *
     * @param value boolean content
     */
    record BooleanValue(boolean value) implements AttributeValue {
    }

    /**
     * Integer/long value.
     *
     * @param value numeric content
     */
    record IntegerValue(long value) implements AttributeValue {
    }

    /**
     * Instant value.
     *
     * @param value timestamp content
     */
    record InstantValue(Instant value) implements AttributeValue {

        /**
         * Creates an instant value.
         *
         * @param value timestamp
         * @throws IllegalArgumentException if {@code value} is null
         */
        public InstantValue {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    /**
     * Byte string value.
     *
     * <p>
     * Byte values should be treated as potentially sensitive. Implementations must
     * not log full contents.
     * </p>
     *
     * @param value non-empty byte array
     */
    record BytesValue(byte[] value) implements AttributeValue {

        /**
         * Creates a byte string value.
         *
         * @param value byte array (non-empty)
         * @throws IllegalArgumentException if {@code value} is null or empty
         */
        public BytesValue {
            if (value == null || value.length == 0) {
                throw new IllegalArgumentException("value must not be null/empty");
            }
        }
    }
}
