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
import java.util.OptionalLong;
import java.util.Set;

/**
 * Immutable adapter capability declaration.
 *
 * <p>Atomic transactions, conflict detection, outcome resolution, stable
 * snapshots, deterministic scans and synchronous content detachment are
 * intrinsic store requirements. Only optional adapter properties appear here.</p>
 *
 * @param writerModel active-writer model
 * @param contentLengthModel accepted content-length forms
 * @param outcomeRetention authoritative outcome-retention model
 * @param optionalFeatures optional adapter facilities
 * @param maximumIndividualRecordBytes optional positive technical record limit
 */
public record MetadataStoreCapabilities(WriterModel writerModel,
        ContentLengthModel contentLengthModel, OutcomeRetention outcomeRetention,
        Set<OptionalFeature> optionalFeatures, OptionalLong maximumIndividualRecordBytes) {
    /** Adapter writer-concurrency model. */
    public enum WriterModel {
        /** At most one writer transaction may be active. */ EXCLUSIVE_WRITER,
        /** Concurrent writers have serializable transaction outcomes. */ SERIALIZABLE_MULTI_WRITER
    }

    /** Accepted repeatable-content length forms. */
    public enum ContentLengthModel {
        /** Every admitted value must declare its exact length. */ KNOWN_LENGTH_ONLY,
        /** Known and initially unknown lengths can be staged safely. */ KNOWN_OR_UNKNOWN_LENGTH
    }

    /** Authoritative transaction-outcome retention model. */
    public enum OutcomeRetention {
        /** Known terminal outcomes may be released after acknowledgement. */ UNTIL_ACKNOWLEDGED,
        /** Known terminal outcomes remain resolvable indefinitely. */ INDEFINITE
    }

    /** Optional facilities that do not weaken required store semantics. */
    public enum OptionalFeature {
        /** Store authority coordinates cooperating processes. */ CROSS_PROCESS_COORDINATION,
        /** Adapter supports explicit checkpoints. */ CHECKPOINT,
        /** Adapter supports history compaction. */ COMPACTION
    }

    /** Validates and defensively copies capability values. */
    public MetadataStoreCapabilities {
        Objects.requireNonNull(writerModel, "writerModel");
        Objects.requireNonNull(contentLengthModel, "contentLengthModel");
        Objects.requireNonNull(outcomeRetention, "outcomeRetention");
        optionalFeatures = Set.copyOf(Objects.requireNonNull(optionalFeatures,
                "optionalFeatures"));
        Objects.requireNonNull(maximumIndividualRecordBytes,
                "maximumIndividualRecordBytes");
        if (maximumIndividualRecordBytes.isPresent()
                && maximumIndividualRecordBytes.getAsLong() <= 0L) {
            throw new IllegalArgumentException(
                    "Adapter technical record limit must be positive");
        }
    }
}
