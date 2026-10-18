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
package zeroecho.pki.application;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Closed transport-neutral value model used by safe operation results and plan
 * arguments.
 *
 * <p>The model deliberately excludes byte arrays and arbitrary Java objects, so
 * private keys, unrestricted DER and provider exception graphs cannot become
 * operation output accidentally.</p>
 */
public sealed interface PkiOperationValue permits PkiOperationValue.Text, PkiOperationValue.IntegerValue,
        PkiOperationValue.BooleanValue, PkiOperationValue.ObjectValue, PkiOperationValue.ListValue {

    /**
     * Text scalar.
     *
     * @param value nonnull text
     */
    record Text(String value) implements PkiOperationValue {
        /** Validates the value. */
        public Text {
            Objects.requireNonNull(value, "value");
        }
    }

    /**
     * Signed 64-bit integer scalar.
     *
     * @param value scalar value
     */
    record IntegerValue(long value) implements PkiOperationValue {
    }

    /**
     * Boolean scalar.
     *
     * @param value scalar value
     */
    record BooleanValue(boolean value) implements PkiOperationValue {
    }

    /**
     * Deterministically ordered object value.
     *
     * @param fields immutable named fields in insertion order
     */
    record ObjectValue(Map<String, PkiOperationValue> fields) implements PkiOperationValue {
        /** Validates names and snapshots insertion order. */
        public ObjectValue {
            Objects.requireNonNull(fields, "fields");
            Map<String, PkiOperationValue> copy = new LinkedHashMap<>();
            for (Map.Entry<String, PkiOperationValue> entry : fields.entrySet()) {
                String name = Objects.requireNonNull(entry.getKey(), "field name");
                if (name.isBlank() || copy.putIfAbsent(name, Objects.requireNonNull(entry.getValue(), "field value"))
                        != null) {
                    throw new IllegalArgumentException("Operation object field names must be unique and nonblank");
                }
            }
            fields = Collections.unmodifiableMap(copy);
        }
    }

    /**
     * Immutable ordered list value.
     *
     * @param values immutable ordered values
     */
    record ListValue(List<PkiOperationValue> values) implements PkiOperationValue {
        /** Snapshots the list and rejects null entries. */
        public ListValue {
            Objects.requireNonNull(values, "values");
            values = List.copyOf(values);
        }
    }
}
