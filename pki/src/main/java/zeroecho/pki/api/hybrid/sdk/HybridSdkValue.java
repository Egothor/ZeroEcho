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
package zeroecho.pki.api.hybrid.sdk;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Represents one immutable canonical typed value of the version-one hybrid SDK encoding.
 *
 * <p>The closed value types are text, signed 64-bit integers, booleans, bytes,
 * ordered lists and identifier-keyed objects. Arbitrary Java object serialization
 * is not supported. Scalars are bounded to 262,144 payload bytes, complete values
 * to 1,048,576 bytes, nesting to eight value levels, and aggregate collection entries
 * to 4,096. Canonical representation alone provides no authentication or signature proof.
 */
public final class HybridSdkValue {
    private static final int LIMIT_5 = 5;
    private static final int LIMIT_6 = 6;
    private static final int LIMIT_1 = 1;
    private static final int LIMIT_2 = 2;
    private static final int LIMIT_8 = 8;

    private static final int MAX_BYTES = 1_048_576;
    private static final int MAX_FIELD = 262_144;
    private static final int MAX_ENTRIES = 4_096;
    private final byte[] encoded;

    private HybridSdkValue(byte[] encoded) {
        this.encoded = encoded.clone();
    }

    /**
     * Creates an exact UTF-8 text value without normalization or trimming.
     *
     * <p>Empty text is permitted. NUL, unpaired surrogates and text whose UTF-8
     * representation exceeds the scalar bound are rejected.
     *
     * @param value Unicode text without NUL
     * @return a new immutable canonical text value
     * @throws IllegalArgumentException if text is null, malformed or exceeds 262,144 UTF-8 bytes
     */
    public static HybridSdkValue text(String value) {
        if (value == null || value.length() > MAX_FIELD) {
            throw invalid();
        }
        return scalar(LIMIT_1, utf8(value));
    }
    /**
     * Creates a signed 64-bit integer value using the exact two's-complement representation.
     *
     * @param value signed integer, including either {@code long} endpoint
     * @return a new immutable canonical integer value
     */
    public static HybridSdkValue integer(long value) {
        return new HybridSdkValue(ByteBuffer.allocate(9).put((byte) LIMIT_2).putLong(value).array());
    }
    /**
     * Creates a canonical boolean value with exactly one encoded true/false discriminator.
     *
     * @param value boolean to encode
     * @return a new immutable canonical boolean value
     */
    public static HybridSdkValue bool(boolean value) {
        return new HybridSdkValue(new byte[] {3, (byte) (value ? LIMIT_1 : 0)});
    }
    /**
     * Creates an opaque binary value from a snapshot of the supplied bytes.
     *
     * <p>The bytes are not interpreted as DER, a frame or a signature. Empty binary
     * data is permitted, and later caller mutations do not affect the value.
     *
     * @param value binary payload, borrowed for this call
     * @return an independently owned immutable canonical binary value
     * @throws NullPointerException if the input is null
     * @throws IllegalArgumentException if the payload exceeds 262,144 bytes
     */
    public static HybridSdkValue bytes(byte[] value) {
        return scalar(4, Objects.requireNonNull(value, "value"));
    }
    /**
     * Creates a canonical list preserving the supplied element order.
     *
     * <p>The list is snapshotted and encoded; no caller collection is retained.
     * The complete result is validated against total byte, depth and aggregate
     * collection-entry bounds, including nested elements. Empty lists are permitted.
     *
     * @param values ordered immutable SDK values, with no null elements
     * @return a new immutable canonical list value
     * @throws NullPointerException if the list or an element is null
     * @throws IllegalArgumentException if nesting, collection-entry or aggregate byte bounds are exceeded
     * @throws IllegalStateException if in-memory canonical encoding unexpectedly fails
     */
    public static HybridSdkValue list(List<HybridSdkValue> values) {
        if (values.size() > MAX_ENTRIES) {
            throw invalid();
        }
        List<HybridSdkValue> copy = List.copyOf(values);
        long size = LIMIT_5;
        for (HybridSdkValue value : copy) {
            size += value.encoded.length;
        }
        requireSize(size);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) size);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(LIMIT_5);
            out.writeInt(copy.size());
            for (HybridSdkValue value : copy) {
                out.write(value.encoded);
            }
            return decode(bytes.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    /**
     * Creates a canonical object whose fields are ordered by their ASCII identifier bytes.
     *
     * <p>Keys contain 1 through 128 characters from {@code A-Z}, {@code a-z},
     * {@code 0-9}, period, underscore, colon and hyphen. This restricted alphabet
     * makes string order identical to unsigned UTF-8 byte order. The map is
     * snapshotted, and nested depth, entry and byte bounds apply to the complete result.
     *
     * @param values identifier-keyed SDK values, with no null keys or values
     * @return a new immutable canonical object value in identifier order
     * @throws NullPointerException if the map, a key or a value is null
     * @throws IllegalArgumentException if a key or the complete value's bounds are invalid
     * @throws IllegalStateException if in-memory canonical encoding unexpectedly fails
     */
    public static HybridSdkValue object(Map<String, HybridSdkValue> values) {
        if (values.size() > MAX_ENTRIES) {
            throw invalid();
        }
        java.util.SortedMap<String, HybridSdkValue> sorted = new TreeMap<>(values);
        long size = LIMIT_5;
        for (Map.Entry<String, HybridSdkValue> entry : sorted.entrySet()) {
            requireIdentifier(entry.getKey());
            size += 2L + utf8(entry.getKey()).length + Objects.requireNonNull(entry.getValue()).encoded.length;
        }
        requireSize(size);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream((int) size);
            DataOutputStream out = new DataOutputStream(bytes);
            out.writeByte(LIMIT_6);
            out.writeInt(sorted.size());
            for (Map.Entry<String, HybridSdkValue> entry : sorted.entrySet()) {
                byte[] key = utf8(entry.getKey());
                out.writeShort(key.length);
                out.write(key);
                out.write(entry.getValue().encoded);
            }
            return decode(bytes.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    /**
     * Reads an already canonical ordered list without changing its encoding.
     * @return immutable ordered independent values
     * @throws IllegalArgumentException if this value is not a list
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public List<HybridSdkValue> listValues() {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != LIMIT_5) {
                throw invalid();
            }
            int count = input.readInt();
            List<HybridSdkValue> values = new ArrayList<>(count);
            int[] entries = new int[LIMIT_1];
            for (int index = 0; index < count; index++) {
                int start = encoded.length - input.available();
                entries[0] = 0;
                CanonicalReader.read(input, LIMIT_1, entries);
                int end = encoded.length - input.available();
                values.add(slice(start, end));
            }
            return List.copyOf(values);
        } catch (IOException malformed) {
            throw invalid();
        }
    }
    /**
     * Reads the fields of an already canonical object without changing its encoding.
     * @return immutable identifier-sorted map of immutable independent values
     * @throws IllegalArgumentException if this value is not an object
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public Map<String, HybridSdkValue> objectFields() {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != LIMIT_6) {
                throw invalid();
            }
            int count = input.readInt();
            java.util.SortedMap<String, HybridSdkValue> fields = new TreeMap<>();
            int[] entries = new int[LIMIT_1];
            for (int index = 0; index < count; index++) {
                String key = text(CanonicalReader.readBytes(input, input.readUnsignedShort()));
                int start = encoded.length - input.available();
                entries[0] = 0;
                CanonicalReader.read(input, LIMIT_1, entries);
                int end = encoded.length - input.available();
                fields.put(key, slice(start, end));
            }
            return java.util.Collections.unmodifiableSortedMap(fields);
        } catch (IOException malformed) {
            throw invalid();
        }
    }
    /**
     * Reads an already validated exact UTF-8 text value.
     * @return text without normalization or trimming
     * @throws IllegalArgumentException if this value is not text
     */
    public String textValue() {
        if (encoded[0] != LIMIT_1) {
            throw invalid();
        }
        return text(java.util.Arrays.copyOfRange(encoded, LIMIT_5, encoded.length));
    }
    /**
     * Reads the signed 64-bit integer value.
     * @return exact integer
     * @throws IllegalArgumentException if this value is not an integer
     */
    public long integerValue() {
        if (encoded[0] != LIMIT_2) {
            throw invalid();
        }
        return ByteBuffer.wrap(encoded, LIMIT_1, Long.BYTES).getLong();
    }
    /**
     * Returns a copy of the exact canonical typed-value encoding.
     *
     * @return independently owned encoded bytes
     */
    public byte[] encode() {
        return encoded.clone();
    }
    /**
     * Decodes one complete value and validates its canonical closed grammar.
     *
     * <p>The input is copied before parsing. Unknown tags, invalid text, noncanonical
     * boolean or object order, duplicate keys, truncated fields, excessive nesting
     * or entries, and trailing bytes are rejected. Integer payloads are exact signed
     * 64-bit values; no arbitrary object deserialization or cryptographic verification occurs.
     *
     * @param encoded complete canonical typed bytes, borrowed for this call
     * @return an independently owned immutable validated value
     * @throws NullPointerException if the input is null
     * @throws IllegalArgumentException if the grammar, canonical ordering or size/depth/entry bounds are invalid
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static HybridSdkValue decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        requireSize(encoded.length);
        byte[] snapshot = encoded.clone();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(snapshot))) {
            CanonicalReader.read(input, LIMIT_1, new int[LIMIT_1]);
            if (input.available() != 0) {
                throw invalid();
            }
            return new HybridSdkValue(snapshot);
        } catch (IOException invalid) {
            throw invalid();
        }
    }
    private HybridSdkValue slice(int start, int end) {
        return new HybridSdkValue(java.util.Arrays.copyOfRange(encoded, start, end));
    }

    private static HybridSdkValue scalar(int tag, byte[] value) {
        if (value.length > MAX_FIELD) {
            throw invalid();
        }
        return new HybridSdkValue(ByteBuffer.allocate(LIMIT_5 + value.length).put((byte) tag).putInt(value.length).put(value).array());
    }




    private static void requireSize(long length) {
        if (length < LIMIT_1 || length > MAX_BYTES) {
            throw invalid();
        }
    }
    /**
     * Checks the SDK identifier alphabet and length without interpreting the identifier.
     *
     * @param value one to 128 ASCII letters, digits, periods, underscores, colons or hyphens
     * @throws IllegalArgumentException if the identifier is null or violates the wire syntax
     */
    /* default */ static void requireIdentifier(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw invalid();
        }
    }
    /**
     * Encodes text as strict UTF-8 while rejecting embedded NUL characters.
     *
     * @param value text to encode; empty text is permitted
     * @return newly allocated UTF-8 bytes
     * @throws IllegalArgumentException if the text is null, contains NUL or contains malformed Unicode
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static byte[] utf8(String value) {
        if (value == null || value.indexOf('\0') >= 0) {
            throw invalid();
        }
        try {
            ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
            byte[] result = new byte[bytes.remaining()];
            bytes.get(result);
            return result;
        } catch (CharacterCodingException invalid) {
            throw invalid();
        }
    }
    /**
     * Decodes strict UTF-8 bytes while rejecting embedded NUL characters.
     *
     * @param bytes encoded text; empty input is permitted
     * @return decoded text with no embedded NUL character
     * @throws NullPointerException if the byte array is null
     * @throws IllegalArgumentException if the input is malformed UTF-8 or decodes to a NUL character
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ static String text(byte... bytes) {
        try {
            String result = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (result.indexOf('\0') >= 0) {
                throw invalid();
            }
            return result;
        } catch (CharacterCodingException invalid) {
            throw invalid();
        }
    }


    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_VALUE_INVALID");
    }
    /** Reads the closed canonical value grammar with bounded aggregate entry accounting. */
    private static final class CanonicalReader {
    private static void read(DataInputStream input, int depth, int... entries) throws IOException {
        if (depth > LIMIT_8) {
            throw invalid();
        }
        switch (input.readUnsignedByte()) {
            case LIMIT_1 -> text(readBytes(input, bounded(input.readInt(), MAX_FIELD, input.available())));
            case LIMIT_2 -> input.readLong();
            case 3 -> {
                if (input.readUnsignedByte() > LIMIT_1) {
                    throw invalid();
                }
            }
            case 4 -> readBytes(input, bounded(input.readInt(), MAX_FIELD, input.available()));
            case LIMIT_5 -> {
                int count = collectionCount(input.readInt(), entries);
                for (int index = 0; index < count; index++) {
                    read(input, depth + LIMIT_1, entries);
                }
            }
            case LIMIT_6 -> {
                int count = collectionCount(input.readInt(), entries);
                String previous = null;
                for (int index = 0; index < count; index++) {
                    int length = bounded(input.readUnsignedShort(), 128, input.available());
                    String key = text(readBytes(input, length));
                    requireIdentifier(key);
                    if (previous != null && previous.compareTo(key) >= 0) {
                        throw invalid();
                    }
                    previous = key;
                    read(input, depth + LIMIT_1, entries);
                }
            }
            default -> throw invalid();
        }
    }
    private static int collectionCount(int count, int... entries) {
        if (count < 0 || count > MAX_ENTRIES || entries[0] > MAX_ENTRIES - count) {
            throw invalid();
        }
        entries[0] += count;
        return count;
    }
    private static byte[] readBytes(DataInputStream input, int length) throws IOException {
        byte[] bytes = input.readNBytes(length);
        if (bytes.length != length) {
            throw invalid();
        }
        return bytes;
    }
    private static int bounded(int length, int maximum, int available) {
        if (length < 0 || length > maximum || length > available) {
            throw invalid();
        }
        return length;
    }
    }
}
