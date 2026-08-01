package zeroecho.pki.spi.store;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable provider-neutral identity of one metadata record.
 *
 * <p>The namespace is canonical and extension-owned. The {@code zeroecho}
 * root and its children are reserved. The key is exact, case-sensitive visible
 * ASCII and has no filesystem interpretation.</p>
 *
 * @param namespace canonical extension namespace
 * @param key exact logical key
 */
public record MetadataKey(String namespace, String key) implements Comparable<MetadataKey> {
    private static final int MINIMUM_KEY_BYTE = 0x21;
    private static final int MAXIMUM_KEY_BYTE = 0x7e;
    /** Maximum canonical namespace length in UTF-8 bytes. */
    public static final int MAXIMUM_NAMESPACE_UTF8_BYTES = 255;
    /** Maximum exact logical-key length in UTF-8 bytes. */
    public static final int MAXIMUM_KEY_UTF8_BYTES = 4096;
    private static final String RESERVED_ROOT = "zeroecho";
    private static final String RESERVED_PREFIX = RESERVED_ROOT + ".";

    /** Validates both identity components. */
    public MetadataKey {
        validateNamespace(namespace);
        validateKey(key, false);
    }

    /* package */ static void validateNamespace(String value) {
        Objects.requireNonNull(value, "namespace");
        if (!value.matches("[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*")) {
            throw new IllegalArgumentException("Metadata namespace is not canonical");
        }
        if (RESERVED_ROOT.equals(value) || value.startsWith(RESERVED_PREFIX)) {
            throw new IllegalArgumentException("The zeroecho namespace domain is reserved");
        }
        requireUtf8Limit(value, MAXIMUM_NAMESPACE_UTF8_BYTES, "Metadata namespace");
    }

    /* package */ static void validateKey(String value, boolean emptyAllowed) {
        Objects.requireNonNull(value, "key");
        if (!emptyAllowed && value.isEmpty()) {
            throw new IllegalArgumentException("Metadata key must not be empty");
        }
        requireUtf8Limit(value, MAXIMUM_KEY_UTF8_BYTES, "Metadata key");
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current < MINIMUM_KEY_BYTE
                    || current > MAXIMUM_KEY_BYTE
                    || current == ':'
                    || current == '/'
                    || current == '\\') {
                throw new IllegalArgumentException("Metadata key is not canonical visible ASCII");
            }
        }
    }

    /* package */ static void validateKeyComponent(String value) {
        validateKey(value, false);
    }

    /*
     * Package-private because ranges share the exact unsigned canonical-key
     * ordering without widening this implementation detail into public API.
     */
    /* package */ static int compareKeyComponents(String first, String second) {
        return Arrays.compareUnsigned(first.getBytes(StandardCharsets.UTF_8),
                second.getBytes(StandardCharsets.UTF_8));
    }

    /*
     * An ordering boundary may contain a byte forbidden in a stored key. It is
     * compared only and never accepted as semantic record identity.
     */
    /* package */ static void validateOrderingBoundary(String value) {
        Objects.requireNonNull(value, "ordering boundary");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("Ordering boundary must not be empty");
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current < MINIMUM_KEY_BYTE || current > MAXIMUM_KEY_BYTE) {
                throw new IllegalArgumentException(
                        "Ordering boundary is not canonical visible ASCII");
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public int compareTo(MetadataKey other) {
        Objects.requireNonNull(other, "other");
        int namespaceOrder = namespace.compareTo(other.namespace);
        if (namespaceOrder == 0) {
            return compareKeyComponents(key, other.key);
        }
        return namespaceOrder;
    }

    /**
     * Parses one complete canonical extension-owned identity.
     *
     * @param encoded canonical namespace and key separated by one colon
     * @return parsed metadata key
     * @throws NullPointerException if {@code encoded} is {@code null}
     * @throws IllegalArgumentException if the representation is malformed
     */
    public static MetadataKey parse(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        int separator = encoded.indexOf(':');
        if (separator <= 0 || separator != encoded.lastIndexOf(':')
                || separator == encoded.length() - 1) {
            throw new IllegalArgumentException("Metadata key representation is not canonical");
        }
        MetadataKey result = new MetadataKey(
                encoded.substring(0, separator), encoded.substring(separator + 1));
        if (!result.canonical().equals(encoded)) {
            throw new IllegalArgumentException("Metadata key representation is not canonical");
        }
        return result;
    }

    /**
     * Returns the complete canonical representation.
     *
     * @return namespace and exact key separated by one colon
     */
    public String canonical() {
        return namespace + ':' + key;
    }

    /*
     * Package-private because only KeyRange constructs ordering boundaries.
     * The scan is O(p) time and the returned boundary uses O(p) memory.
     */
    /* package */ static Optional<String> prefixSuccessor(String prefix) {
        byte[] value = prefix.getBytes(StandardCharsets.UTF_8);
        int successorIndex = -1;
        for (int index = value.length - 1; index >= 0; index--) {
            if (Byte.toUnsignedInt(value[index]) < MAXIMUM_KEY_BYTE) {
                value[index]++;
                successorIndex = index;
                break;
            }
        }
        if (successorIndex < 0) {
            return Optional.empty();
        }
        byte[] boundary = Arrays.copyOf(value, successorIndex + 1);
        return Optional.of(new String(boundary, StandardCharsets.UTF_8));
    }

    private static void requireUtf8Limit(String value, int maximumBytes, String component) {
        if (value.getBytes(StandardCharsets.UTF_8).length > maximumBytes) {
            throw new IllegalArgumentException(component + " exceeds its canonical UTF-8 limit");
        }
    }
}
