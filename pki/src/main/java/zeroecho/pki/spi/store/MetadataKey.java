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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
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
    private static final String CANONICAL_VERSION_PREFIX = "mk1:";
    private static final byte[] CANONICAL_VERSION_BYTES =
            CANONICAL_VERSION_PREFIX.getBytes(StandardCharsets.US_ASCII);
    private static final byte LENGTH_SEPARATOR = ':';
    private static final int MAXIMUM_CANONICAL_CHARACTERS = 4364;
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
        if (value.length() > MAXIMUM_NAMESPACE_UTF8_BYTES) {
            throw new IllegalArgumentException("Metadata namespace exceeds its canonical UTF-8 limit");
        }
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
        if (value.length() > MAXIMUM_KEY_UTF8_BYTES) {
            throw new IllegalArgumentException("Metadata key exceeds its canonical UTF-8 limit");
        }
        if (!emptyAllowed && value.isEmpty()) {
            throw new IllegalArgumentException("Metadata key must not be empty");
        }
        requireUtf8Limit(value, MAXIMUM_KEY_UTF8_BYTES, "Metadata key");
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (current < MINIMUM_KEY_BYTE
                    || current > MAXIMUM_KEY_BYTE
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
     * Parses one complete versioned length-framed identity.
     *
     * @param encoded current versioned length-framed representation
     * @return parsed metadata key
     * @throws NullPointerException if {@code encoded} is {@code null}
     * @throws IllegalArgumentException if the representation is malformed
     */
    public static MetadataKey parse(String encoded) {
        return CanonicalCodec.parse(encoded);
    }

    /**
     * Returns the complete versioned length-framed canonical representation.
     *
     * @return current versioned length-framed representation
     */
    public String canonical() {
        int namespaceLength = namespace.getBytes(StandardCharsets.UTF_8).length;
        int keyLength = key.getBytes(StandardCharsets.UTF_8).length;
        return CANONICAL_VERSION_PREFIX + namespaceLength + ':' + keyLength + ':' + namespace + key;
    }

    /** Returns the canonical serialized representation. */
    @Override
    public String toString() {
        return canonical();
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

    /** Strict current-version textual framing isolated from semantic identity rules. */
    private static final class CanonicalCodec {
        private static MetadataKey parse(String encoded) {
            Objects.requireNonNull(encoded, "encoded");
            if (encoded.length() > MAXIMUM_CANONICAL_CHARACTERS) {
                throw malformedRepresentation();
            }
            byte[] bytes = strictEncode(encoded);
            if (!hasCanonicalPrefix(bytes)) {
                throw malformedRepresentation();
            }
            LengthField namespaceLength = parseLength(bytes, CANONICAL_VERSION_BYTES.length,
                    MAXIMUM_NAMESPACE_UTF8_BYTES);
            LengthField keyLength = parseLength(bytes, namespaceLength.nextOffset(), MAXIMUM_KEY_UTF8_BYTES);
            int componentLength;
            int expectedEnd;
            try {
                componentLength = Math.addExact(namespaceLength.value(), keyLength.value());
                expectedEnd = Math.addExact(keyLength.nextOffset(), componentLength);
            } catch (ArithmeticException exception) {
                throw new IllegalArgumentException("Metadata key representation length overflows", exception);
            }
            if (namespaceLength.value() == 0 || keyLength.value() == 0 || expectedEnd != bytes.length) {
                throw malformedRepresentation();
            }
            int namespaceStart = keyLength.nextOffset();
            int keyStart;
            try {
                keyStart = Math.addExact(namespaceStart, namespaceLength.value());
            } catch (ArithmeticException exception) {
                throw new IllegalArgumentException("Metadata key representation length overflows", exception);
            }
            MetadataKey result = new MetadataKey(
                    strictDecode(bytes, namespaceStart, namespaceLength.value()),
                    strictDecode(bytes, keyStart, keyLength.value()));
            if (!result.canonical().equals(encoded)) {
                throw malformedRepresentation();
            }
            return result;
        }

        private static LengthField parseLength(byte[] bytes, int offset, int maximum) {
        if (offset >= bytes.length) {
            throw malformedRepresentation();
        }
        int value = 0;
        int cursor = offset;
        while (cursor < bytes.length && bytes[cursor] != LENGTH_SEPARATOR) {
            int digit = bytes[cursor] - '0';
            if (digit < 0 || digit > 9 || cursor > offset && bytes[offset] == '0') {
                throw malformedRepresentation();
            }
            try {
                value = Math.addExact(Math.multiplyExact(value, 10), digit);
            } catch (ArithmeticException exception) {
                throw new IllegalArgumentException("Metadata key representation length overflows", exception);
            }
            if (value > maximum) {
                throw malformedRepresentation();
            }
            cursor++;
        }
        if (cursor == offset || cursor >= bytes.length) {
            throw malformedRepresentation();
        }
        return new LengthField(value, cursor + 1);
        }

        private static boolean hasCanonicalPrefix(byte[] bytes) {
        if (bytes.length < CANONICAL_VERSION_BYTES.length) {
            return false;
        }
        for (int index = 0; index < CANONICAL_VERSION_BYTES.length; index++) {
            if (bytes[index] != CANONICAL_VERSION_BYTES[index]) {
                return false;
            }
        }
        return true;
        }

        private static byte[] strictEncode(String value) {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Metadata key representation is not valid UTF-8", exception);
        }
        }

        private static String strictDecode(byte[] bytes, int offset, int length) {
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, offset, length))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Metadata key component is not valid UTF-8", exception);
        }
        }

        private static IllegalArgumentException malformedRepresentation() {
            return new IllegalArgumentException("Metadata key representation is not canonical");
        }

        private record LengthField(int value, int nextOffset) {
        }
    }
}
