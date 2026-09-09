/*******************************************************************************
 * Copyright (c) 2025 ZeroEcho
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

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * An immutable, store-issued view of one committed metadata revision.
 *
 * <p>Reads and scans never observe later commits. The snapshot and all live
 * objects it issues remain bound to the exact issuing store instance.
 */
public interface MetadataSnapshot extends AutoCloseable {

    /**
     * A repeatable record view owned by a snapshot.
     */
    interface Record extends RepeatableContent {

        /**
         * Returns the semantic record identity.
         *
         * @return record key
         */
        MetadataKey key();

        /**
         * Returns the non-negative record revision.
         *
         * @return record revision
         */
        long recordRevision();

        /**
         * Returns the committed store revision containing this record revision.
         *
         * @return committed store revision
         */
        long commitRevision();

        /**
         * Returns stable adapter-supplied integrity metadata when available.
         *
         * @return optional integrity metadata
         */
        Optional<Integrity> integrity();
    }

    /**
     * Stable content-integrity metadata without payload or storage details.
     *
     * @param algorithm canonical integrity algorithm identity
     * @param value canonical integrity value
     */
    record Integrity(String algorithm, String value) {
        /**
         * Creates integrity metadata.
         *
         * @param algorithm canonical integrity algorithm identity
         * @param value canonical integrity value
         */
        public Integrity {
            Objects.requireNonNull(algorithm, "algorithm");
            Objects.requireNonNull(value, "value");
            if (algorithm.isBlank() || value.isBlank()) {
                throw new IllegalArgumentException("Integrity fields must not be blank");
            }
        }
    }

    /**
     * An ordered range within one semantic namespace.
     *
     * @param namespace canonical extension namespace
     * @param lowerInclusive optional inclusive key-component lower bound
     * @param upperExclusive optional exclusive key-component upper bound
     */
    record KeyRange(
            String namespace,
            Optional<String> lowerInclusive,
            Optional<String> upperExclusive) {
        /**
         * Creates a validated range.
         *
         * @param namespace canonical extension namespace
         * @param lowerInclusive optional inclusive lower bound
         * @param upperExclusive optional exclusive upper bound
         */
        public KeyRange {
            MetadataKey.validateNamespace(namespace);
            Objects.requireNonNull(lowerInclusive, "lowerInclusive");
            Objects.requireNonNull(upperExclusive, "upperExclusive");
            lowerInclusive.ifPresent(MetadataKey::validateKeyComponent);
            upperExclusive.ifPresent(MetadataKey::validateOrderingBoundary);
            if (lowerInclusive.isPresent()
                    && upperExclusive.isPresent()
                    && MetadataKey.compareKeyComponents(
                                    lowerInclusive.orElseThrow(),
                                    upperExclusive.orElseThrow()) >= 0) {
                throw new IllegalArgumentException("Range lower bound must precede upper bound");
            }
        }

        /**
         * Returns a range containing the complete namespace.
         *
         * @param namespace canonical extension namespace
         * @return complete-namespace range
         */
        public static KeyRange all(String namespace) {
            return new KeyRange(namespace, Optional.empty(), Optional.empty());
        }

        /**
         * Returns the total ordered range for a canonical key prefix.
         *
         * @param namespace canonical extension namespace
         * @param prefix canonical key prefix, possibly empty
         * @return prefix range with an unbounded upper limit when no successor exists
         */
        public static KeyRange prefix(String namespace, String prefix) {
            MetadataKey.validateNamespace(namespace);
            Objects.requireNonNull(prefix, "prefix");
            if (prefix.isEmpty()) {
                return all(namespace);
            }
            MetadataKey.validateKeyComponent(prefix);
            return new KeyRange(
                    namespace,
                    Optional.of(prefix),
                    MetadataKey.prefixSuccessor(prefix));
        }

        /**
         * Tests whether a key belongs to this range.
         *
         * @param candidate key to test
         * @return {@code true} when the candidate belongs to this range
         */
        public boolean contains(MetadataKey candidate) {
            Objects.requireNonNull(candidate, "candidate");
            if (!namespace.equals(candidate.namespace())) {
                return false;
            }
            String component = candidate.key();
            boolean aboveLower = lowerInclusive.isEmpty()
                    || MetadataKey.compareKeyComponents(
                                    component,
                                    lowerInclusive.orElseThrow()) >= 0;
            boolean belowUpper = upperExclusive.isEmpty()
                    || MetadataKey.compareKeyComponents(
                                    component,
                                    upperExclusive.orElseThrow()) < 0;
            return aboveLower && belowUpper;
        }
    }

    /**
     * Returns the issuing store identity.
     *
     * @return store identity
     */
    MetadataStoreId storeId();

    /**
     * Returns the captured non-negative committed store revision.
     *
     * @return snapshot revision
     */
    long revision();

    /**
     * Reads one record from this stable view.
     *
     * @param key semantic record identity
     * @return the stable record, or empty when absent
     * @throws IOException when content metadata cannot be opened
     * @throws MetadataStoreException when this snapshot is closed or foreign
     */
    Optional<Record> get(MetadataKey key) throws IOException;

    /**
     * Returns the greatest key in one namespace without opening record content.
     *
     * @param namespace canonical metadata namespace
     * @return greatest snapshot key, or empty when the namespace is empty
     * @throws IllegalStateException when this snapshot is closed or foreign
     */
    Optional<MetadataKey> greatestKey(String namespace);

    /**
     * Opens a lazy deterministic scan over this stable view.
     *
     * @param range ordered semantic range
     * @param cancellation cooperative cancellation signal
     * @return store-issued cursor
     * @throws IOException when the scan cannot be opened
     * @throws MetadataStoreException when this snapshot is closed or foreign
     */
    MetadataCursor scan(KeyRange range, CancellationSignal cancellation) throws IOException;

    /**
     * Closes this snapshot idempotently and invalidates its cursors.
     */
    @Override
    void close();
}
