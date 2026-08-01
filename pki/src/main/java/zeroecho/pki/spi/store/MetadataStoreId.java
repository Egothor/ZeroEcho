package zeroecho.pki.spi.store;

import java.util.Objects;

/**
 * Stable provider-neutral metadata-store identity.
 *
 * <p>Possession of an equal value does not grant live store authority.</p>
 *
 * @param value 32 lowercase hexadecimal characters
 */
public record MetadataStoreId(String value) {
    /** Validates the canonical identity. */
    public MetadataStoreId {
        Objects.requireNonNull(value, "value");
        if (!value.matches("[0-9a-f]{32}")) {
            throw new IllegalArgumentException(
                    "Metadata store identifier must be 32 lowercase hexadecimal characters");
        }
    }

    /** Returns the canonical identity. */
    @Override
    public String toString() {
        return value;
    }
}
