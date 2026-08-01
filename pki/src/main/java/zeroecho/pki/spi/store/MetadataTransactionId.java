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
