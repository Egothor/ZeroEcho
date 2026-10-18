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
package zeroecho.pki.impl.core.attr;

import java.util.ArrayList;
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
 * Minimal immutable {@link AttributeSet} implementation used by PKI core
 * runtime services.
 *
 * <p>
 * This implementation provides a compact, explicit, and persistence-friendly
 * representation of attribute collections for internal PKI service wiring. It
 * is primarily intended for service-layer overrides, framework input assembly,
 * and other runtime attribute transport scenarios where a lightweight immutable
 * implementation is sufficient.
 * </p>
 *
 * <p>
 * The implementation preserves entry insertion order and stores values grouped
 * by {@link AttributeId}. For each attribute identifier, zero or more
 * {@link AttributeValue} instances may be associated with the entry.
 * </p>
 *
 * <h2>Lookup semantics</h2>
 * <ul>
 * <li>{@link #get(AttributeId)} returns the first value of the first matching
 * entry, or an empty result when the entry is absent or contains no
 * values.</li>
 * <li>{@link #getAll(AttributeId)} returns all values associated with the first
 * matching entry, or an empty list when the attribute is absent.</li>
 * <li>{@link #ids()} returns the distinct set of identifiers currently present
 * in the attribute set.</li>
 * </ul>
 *
 * <p>
 * In normal construction paths through {@link Builder}, each attribute
 * identifier is represented at most once. The record form nevertheless allows
 * callers to construct instances directly, so the operational semantics above
 * are defined in terms of the first matching entry to keep behavior explicit
 * even for non-canonical input.
 * </p>
 *
 * <h2>Persistence considerations</h2>
 * <p>
 * This type is modeled as a {@code record} so that it remains simple and stable
 * for explicit codec-based persistence, including filesystem-backed store
 * implementations, without relying on reflective construction or ad-hoc mutable
 * containers.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of this type are immutable and therefore thread-safe after
 * construction.
 * </p>
 *
 * @param entries ordered attribute entries; must not be {@code null}. The list
 *                is defensively copied during construction.
 */
public record SimpleAttributeSet(List<Entry> entries) implements AttributeSet {

    /**
     * Creates an immutable attribute set from the supplied ordered entries.
     *
     * <p>
     * The provided list is defensively copied. The resulting instance does not
     * expose mutable internal state through its canonical record component.
     * </p>
     *
     * @param entries ordered attribute entries; must not be {@code null}
     * @throws IllegalArgumentException if {@code entries} is {@code null}
     */
    public SimpleAttributeSet {
        if (entries == null) {
            throw new IllegalArgumentException("entries must not be null");
        }
        entries = List.copyOf(entries);
    }

    /**
     * Creates an empty attribute set.
     */
    public SimpleAttributeSet() {
        this(List.of());
    }

    /**
     * Immutable representation of one attribute entry.
     *
     * <p>
     * Each entry binds one {@link AttributeId} to an ordered list of
     * {@link AttributeValue} instances. The value list may be empty, which allows
     * the entry to preserve explicit identifier presence even when no concrete
     * values are currently associated with it.
     * </p>
     *
     * <p>
     * The value list is defensively copied during construction.
     * </p>
     *
     * @param id     attribute identifier; must not be {@code null}
     * @param values ordered attribute values associated with the identifier; must
     *               not be {@code null}
     */
    public record Entry(AttributeId id, List<AttributeValue> values) {

        /**
         * Creates an immutable attribute entry.
         *
         * @param id     attribute identifier; must not be {@code null}
         * @param values ordered attribute values; must not be {@code null}
         * @throws IllegalArgumentException if {@code id} or {@code values} is
         *                                  {@code null}
         */
        public Entry {
            if (id == null) {
                throw new IllegalArgumentException("id must not be null");
            }
            if (values == null) {
                throw new IllegalArgumentException("values must not be null");
            }
            values = List.copyOf(values);
        }
    }

    /**
     * Returns the distinct set of attribute identifiers present in this set.
     *
     * <p>
     * Identifier order follows encounter order of the underlying entries, but the
     * returned {@link Set} should be treated primarily as a membership view rather
     * than as an ordered collection contract.
     * </p>
     *
     * @return distinct attribute identifiers present in this set; never
     *         {@code null}
     */
    @Override
    public Set<AttributeId> ids() {
        Map<AttributeId, Boolean> seen = new LinkedHashMap<>();
        for (Entry e : entries) {
            seen.put(e.id(), Boolean.TRUE);
        }
        return Set.copyOf(seen.keySet());
    }

    /**
     * Returns the first value associated with the supplied attribute identifier.
     *
     * <p>
     * If the first matching entry contains no values, this method returns an empty
     * optional. If no matching entry exists, it also returns an empty optional.
     * </p>
     *
     * @param id attribute identifier to resolve; must not be {@code null}
     * @return optional containing the first associated value, or an empty optional
     *         when no value is available
     * @throws NullPointerException if {@code id} is {@code null}
     */
    @Override
    public Optional<AttributeValue> get(AttributeId id) {
        Objects.requireNonNull(id, "id");
        for (Entry e : entries) {
            if (e.id().equals(id)) {
                if (e.values().isEmpty()) {
                    return Optional.empty();
                }
                return Optional.of(e.values().get(0));
            }
        }
        return Optional.empty();
    }

    /**
     * Returns all values associated with the supplied attribute identifier.
     *
     * <p>
     * If no matching entry exists, this method returns an empty immutable list.
     * </p>
     *
     * @param id attribute identifier to resolve; must not be {@code null}
     * @return immutable list of associated values, or an empty list when the
     *         attribute is absent
     * @throws NullPointerException if {@code id} is {@code null}
     */
    @Override
    public List<AttributeValue> getAll(AttributeId id) {
        Objects.requireNonNull(id, "id");
        for (Entry e : entries) {
            if (e.id().equals(id)) {
                return e.values();
            }
        }
        return List.of();
    }

    /**
     * Creates a new mutable builder for assembling a {@link SimpleAttributeSet}.
     *
     * @return new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Mutable builder for {@link SimpleAttributeSet}.
     *
     * <p>
     * The builder preserves insertion order of attribute identifiers. For each
     * identifier, the current implementation stores exactly one value list in the
     * internal map. Repeated {@link #put(AttributeId, AttributeValue)} calls for
     * the same identifier therefore replace the previously associated values rather
     * than appending a second independent entry.
     * </p>
     *
     * <p>
     * Likewise, {@link #putAll(AttributeSet)} copies all values for each identifier
     * from the supplied set and replaces any previously stored values for the same
     * identifier in this builder.
     * </p>
     *
     * <p>
     * Builder instances are mutable and not thread-safe.
     * </p>
     */
    public static final class Builder {

        private final Map<AttributeId, List<AttributeValue>> map;

        private Builder() {
            this.map = new LinkedHashMap<>();
        }

        /**
         * Associates the supplied identifier with exactly one value.
         *
         * <p>
         * If the identifier already exists in the builder, any previously associated
         * values are replaced by a single-element list containing {@code value}.
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
         * For each identifier present in {@code set}, the full value list returned by
         * {@link AttributeSet#getAll(AttributeId)} is copied and stored in this
         * builder. Existing values for the same identifier are replaced.
         * </p>
         *
         * @param set attribute set to copy from; must not be {@code null}
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
         * Builds a new immutable attribute set from the builder contents.
         *
         * @return newly created immutable attribute set
         */
        public AttributeSet build() {
            List<Entry> out = new ArrayList<>();
            for (Map.Entry<AttributeId, List<AttributeValue>> e : map.entrySet()) {
                out.add(new Entry(e.getKey(), e.getValue()));
            }
            return new SimpleAttributeSet(out);
        }
    }
}
