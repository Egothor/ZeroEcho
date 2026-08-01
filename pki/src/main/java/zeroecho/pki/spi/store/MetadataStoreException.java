package zeroecho.pki.spi.store;

import java.io.IOException;
import java.util.Objects;

/** Checked metadata-store failure carrying a stable, non-sensitive category. */
public class MetadataStoreException extends IOException {
    private static final long serialVersionUID = -8014654957838033436L;
    private final MetadataCommitResult.FailureCategory category;

    /**
     * Creates a categorized failure.
     *
     * @param category stable safe category
     * @param safeMessage non-sensitive diagnostic message
     */
    public MetadataStoreException(MetadataCommitResult.FailureCategory category,
            String safeMessage) {
        super(Objects.requireNonNull(safeMessage, "safeMessage"));
        this.category = Objects.requireNonNull(category, "category");
    }

    /**
     * Creates a categorized failure retaining its cause.
     *
     * @param category stable safe category
     * @param safeMessage non-sensitive diagnostic message
     * @param cause original cause
     */
    public MetadataStoreException(MetadataCommitResult.FailureCategory category,
            String safeMessage, Throwable cause) {
        super(Objects.requireNonNull(safeMessage, "safeMessage"), cause);
        this.category = Objects.requireNonNull(category, "category");
    }

    /**
     * Returns the stable safe category.
     *
     * @return failure category
     */
    public MetadataCommitResult.FailureCategory category() {
        return category;
    }
}
