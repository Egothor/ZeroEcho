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
