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
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;

/**
 * Minimal immutable {@link AttributeSet} implementation used by the Bouncy
 * Castle backed X.509 framework adapter.
 *
 * <p>
 * This class provides a compact internal representation of framework-specific
 * attributes keyed by {@link AttributeId}. It is intended primarily for
 * adapter-side wiring, override propagation, and lightweight attribute
 * transport between X.509-specific implementation components.
 * </p>
 *
 * <p>
 * Attribute values are grouped by identifier and stored as ordered {@link List
 * lists} of {@link AttributeValue} instances. The implementation preserves
 * insertion order of attribute identifiers by using a {@link LinkedHashMap}
 * during construction.
 * </p>
 *
 * <h2>Lookup semantics</h2>
 * <ul>
 * <li>{@link #get(AttributeId)} returns the first value associated with the
 * supplied identifier, or an empty optional if the identifier is absent or its
 * value list is empty.</li>
 * <li>{@link #getAll(AttributeId)} returns the full immutable value list for
 * the supplied identifier, or an empty immutable list if the identifier is
 * absent.</li>
 * <li>{@link #ids()} returns the set of identifiers currently present in this
 * attribute set.</li>
 * </ul>
 *
 * <h2>Immutability</h2>
 * <p>
 * Instances of this class are immutable after construction. The internal map is
 * wrapped as unmodifiable, and all stored value lists are defensively copied
 * through {@link List#copyOf(java.util.Collection)}.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of this class are immutable and therefore thread-safe.
 * </p>
 */
public final class SimpleAttributeSet implements AttributeSet {

    private final Map<AttributeId, List<AttributeValue>> values;

    /**
     * Creates an empty attribute set.
     */
    public SimpleAttributeSet() {
        this.values = Map.of();
    }

    /**
     * Creates an immutable attribute set from an already prepared identifier-to-
     * values map.
     *
     * <p>
     * The supplied map is expected to contain only non-{@code null} keys and value
     * lists. The constructor itself is private because external callers are
     * expected to use {@link #of(Map)} or {@link Builder}, both of which perform
     * defensive copying and validation.
     * </p>
     *
     * @param values internal attribute map, already validated and defensively
     *               copied; must not be {@code null}
     */
    private SimpleAttributeSet(Map<AttributeId, List<AttributeValue>> values) {
        this.values = Collections.unmodifiableMap(values);
    }

    /**
     * Creates an immutable attribute set from the supplied map.
     *
     * <p>
     * The input map is defensively copied. Each value list is also defensively
     * copied so that subsequent mutations of the caller-provided map or lists do
     * not affect the resulting {@link SimpleAttributeSet}.
     * </p>
     *
     * <p>
     * The iteration order of the supplied map is preserved in the resulting
     * attribute set because copying is performed into a {@link LinkedHashMap}.
     * </p>
     *
     * @param input source map of attribute identifiers to ordered value lists; must
     *              not be {@code null}
     * @return immutable attribute set built from the supplied map
     * @throws NullPointerException     if {@code input} is {@code null}
     * @throws IllegalArgumentException if the input contains a {@code null}
     *                                  attribute identifier or a {@code null} value
     *                                  list
     */
    public static SimpleAttributeSet of(Map<AttributeId, List<AttributeValue>> input) {
        Objects.requireNonNull(input, "input");
        Map<AttributeId, List<AttributeValue>> copy = new LinkedHashMap<>();
        for (Map.Entry<AttributeId, List<AttributeValue>> e : input.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) {
                throw new IllegalArgumentException("Null key/value in attributes");
            }
            copy.put(e.getKey(), List.copyOf(e.getValue()));
        }
        return new SimpleAttributeSet(copy);
    }

    /**
     * Creates a mutable builder for assembling a {@link SimpleAttributeSet}.
     *
     * @return new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns the identifiers present in this attribute set.
     *
     * <p>
     * The returned set is backed by the immutable internal map view and must be
     * treated as read-only.
     * </p>
     *
     * @return set of present attribute identifiers, never {@code null}
     */
    @Override
    public Set<AttributeId> ids() {
        return values.keySet();
    }

    /**
     * Returns the first value associated with the supplied attribute identifier.
     *
     * <p>
     * If the identifier is absent or the associated value list is empty, this
     * method returns {@link Optional#empty()}.
     * </p>
     *
     * @param id attribute identifier to resolve; must not be {@code null}
     * @return optional first value for the supplied identifier
     * @throws NullPointerException if {@code id} is {@code null}
     */
    @Override
    public Optional<AttributeValue> get(AttributeId id) {
        Objects.requireNonNull(id, "id");
        List<AttributeValue> v = values.get(id);
        if (v == null || v.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(v.get(0));
    }

    /**
     * Returns all values associated with the supplied attribute identifier.
     *
     * @param id attribute identifier to resolve; must not be {@code null}
     * @return immutable list of values associated with the identifier, or an empty
     *         immutable list if the identifier is absent
     * @throws NullPointerException if {@code id} is {@code null}
     */
    @Override
    public List<AttributeValue> getAll(AttributeId id) {
        Objects.requireNonNull(id, "id");
        List<AttributeValue> v = values.get(id);
        if (v == null) {
            return List.of();
        }
        return v;
    }

    /**
     * Mutable builder for {@link SimpleAttributeSet}.
     *
     * <p>
     * The builder preserves insertion order of attribute identifiers. Repeated
     * calls to {@link #put(AttributeId, AttributeValue)} for the same identifier
     * replace the previously associated value list with a new single-value list.
     * Likewise, {@link #putAll(AttributeSet)} replaces previously stored values for
     * each identifier copied from the supplied set.
     * </p>
     *
     * <p>
     * Builder instances are mutable and not thread-safe.
     * </p>
     */
    public static final class Builder {

        private final Map<AttributeId, List<AttributeValue>> map;

        /**
         * Creates an empty builder.
         */
        private Builder() {
            this.map = new LinkedHashMap<>();
        }

        /**
         * Associates the supplied attribute identifier with exactly one value.
         *
         * <p>
         * If the identifier already exists in the builder, any previously associated
         * values are replaced.
         * </p>
         *
         * @param id    attribute identifier; must not be {@code null}
         * @param value attribute value; must not be {@code null}
         * @return this builder
         * @throws NullPointerException if {@code id} or {@code value} is {@code null}
         */
        public Builder put(AttributeId id, AttributeValue value) {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(value, "value");
            map.put(id, List.of(value));
            return this;
        }

        /**
         * Copies all attributes from the supplied set into this builder.
         *
         * <p>
         * For each identifier present in the supplied set, the full value list is
         * copied and stored in this builder. Existing values associated with the same
         * identifier are replaced.
         * </p>
         *
         * @param set source attribute set; must not be {@code null}
         * @return this builder
         * @throws NullPointerException if {@code set} is {@code null}
         */
        public Builder putAll(AttributeSet set) {
            Objects.requireNonNull(set, "set");
            for (AttributeId id : set.ids()) {
                map.put(id, List.copyOf(set.getAll(id)));
            }
            return this;
        }

        /**
         * Builds a new immutable {@link SimpleAttributeSet} from the current builder
         * contents.
         *
         * @return newly created immutable attribute set
         */
        public SimpleAttributeSet build() {
            return of(map);
        }
    }
}
