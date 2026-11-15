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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Immutable canonical v1 SDK typed value; it never serializes arbitrary Java objects. */
public final class HybridSdkValue {
    private static final int MAX_BYTES = 1048576;
    private static final int MAX_FIELD = 262144;
    private static final int MAX_ENTRIES = 4096;
    private final byte[] encoded;

    private HybridSdkValue(byte[] encoded) { this.encoded = encoded.clone(); }

    /** @param value exact Unicode text without NUL @return canonical text value @throws IllegalArgumentException for malformed text or an exceeded limit */
    public static HybridSdkValue text(String value) {
        if (value == null || value.length() > MAX_FIELD) throw invalid(); return scalar(1, utf8(value));
    }
    /** @param value signed 64-bit integer @return canonical integer value */
    public static HybridSdkValue integer(long value) { return new HybridSdkValue(ByteBuffer.allocate(9).put((byte) 2).putLong(value).array()); }
    /** @param value boolean @return canonical boolean value */
    public static HybridSdkValue bool(boolean value) { return new HybridSdkValue(new byte[] {3, (byte) (value ? 1 : 0)}); }
    /** @param value borrowed public binary data @return independent canonical binary value @throws IllegalArgumentException if its bound is exceeded */
    public static HybridSdkValue bytes(byte[] value) { return scalar(4, Objects.requireNonNull(value, "value")); }
    /** @param values ordered finite values @return canonical list @throws IllegalArgumentException if nesting or aggregate bounds are exceeded */
    public static HybridSdkValue list(List<HybridSdkValue> values) {
        if (values.size() > MAX_ENTRIES) throw invalid();
        List<HybridSdkValue> copy = List.copyOf(values);
        long size = 5;
        for (HybridSdkValue value : copy) size += value.encoded.length;
        requireSize(size);
        try {
            var bytes = new ByteArrayOutputStream((int) size); var out = new DataOutputStream(bytes);
            out.writeByte(5); out.writeInt(copy.size());
            for (HybridSdkValue value : copy) out.write(value.encoded);
            return decode(bytes.toByteArray());
        } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
    /** @param values identifier-keyed values @return canonical object sorted by unsigned UTF-8 key bytes @throws IllegalArgumentException if identifiers or bounds are invalid */
    public static HybridSdkValue object(Map<String, HybridSdkValue> values) {
        if (values.size() > MAX_ENTRIES) throw invalid();
        var sorted = new TreeMap<>(values); long size = 5;
        for (var entry : sorted.entrySet()) {
            requireIdentifier(entry.getKey()); size += 2L + utf8(entry.getKey()).length + Objects.requireNonNull(entry.getValue()).encoded.length;
        }
        requireSize(size);
        try {
            var bytes = new ByteArrayOutputStream((int) size); var out = new DataOutputStream(bytes);
            out.writeByte(6); out.writeInt(sorted.size());
            for (var entry : sorted.entrySet()) {
                byte[] key = utf8(entry.getKey()); out.writeShort(key.length); out.write(key); out.write(entry.getValue().encoded);
            }
            return decode(bytes.toByteArray());
        } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
    /**
     * Reads an already canonical ordered list without changing its encoding.
     * @return immutable ordered independent values
     * @throws IllegalArgumentException if this value is not a list
     */
    public List<HybridSdkValue> listValues() {
        try (var input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != 5) throw invalid();
            int count = input.readInt(); var values = new java.util.ArrayList<HybridSdkValue>(count);
            for (int index = 0; index < count; index++) {
                int start = encoded.length - input.available();
                read(input, 1, new int[1]);
                int end = encoded.length - input.available();
                values.add(new HybridSdkValue(java.util.Arrays.copyOfRange(encoded, start, end)));
            }
            return List.copyOf(values);
        } catch (IOException malformed) { throw invalid(); }
    }
    /**
     * Reads the fields of an already canonical object without changing its encoding.
     * @return immutable identifier-sorted map of immutable independent values
     * @throws IllegalArgumentException if this value is not an object
     */
    public Map<String, HybridSdkValue> objectFields() {
        try (var input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != 6) throw invalid();
            int count = input.readInt(); var fields = new TreeMap<String, HybridSdkValue>();
            for (int index = 0; index < count; index++) {
                String key = text(readBytes(input, input.readUnsignedShort()));
                int start = encoded.length - input.available();
                read(input, 1, new int[1]);
                int end = encoded.length - input.available();
                fields.put(key, new HybridSdkValue(java.util.Arrays.copyOfRange(encoded, start, end)));
            }
            return java.util.Collections.unmodifiableSortedMap(fields);
        } catch (IOException malformed) { throw invalid(); }
    }
    /**
     * Reads an already validated exact UTF-8 text value.
     * @return text without normalization or trimming
     * @throws IllegalArgumentException if this value is not text
     */
    public String textValue() {
        if (encoded[0] != 1) throw invalid();
        return text(java.util.Arrays.copyOfRange(encoded, 5, encoded.length));
    }
    /**
     * Reads the signed 64-bit integer value.
     * @return exact integer
     * @throws IllegalArgumentException if this value is not an integer
     */
    public long integerValue() {
        if (encoded[0] != 2) throw invalid();
        return ByteBuffer.wrap(encoded, 1, Long.BYTES).getLong();
    }
    /** @return defensive copy of the exact canonical bytes */
    public byte[] encode() { return encoded.clone(); }
    /** @param encoded borrowed canonical typed bytes @return independent validated value @throws IllegalArgumentException for unsupported, malformed or excessive input */
    public static HybridSdkValue decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded"); requireSize(encoded.length); encoded = encoded.clone();
        try (var input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            read(input, 1, new int[1]);
            if (input.available() != 0) throw invalid();
            return new HybridSdkValue(encoded);
        } catch (IOException invalid) { throw invalid(); }
    }
    private static HybridSdkValue scalar(int tag, byte[] value) {
        if (value.length > MAX_FIELD) throw invalid();
        return new HybridSdkValue(ByteBuffer.allocate(5 + value.length).put((byte) tag).putInt(value.length).put(value).array());
    }
    private static void read(DataInputStream input, int depth, int[] entries) throws IOException {
        if (depth > 8) throw invalid();
        switch (input.readUnsignedByte()) {
            case 1 -> text(readBytes(input, bounded(input.readInt(), MAX_FIELD, input.available())));
            case 2 -> input.readLong();
            case 3 -> { if (input.readUnsignedByte() > 1) throw invalid(); }
            case 4 -> readBytes(input, bounded(input.readInt(), MAX_FIELD, input.available()));
            case 5 -> {
                int count = collectionCount(input.readInt(), entries);
                for (int index = 0; index < count; index++) read(input, depth + 1, entries);
            }
            case 6 -> {
                int count = collectionCount(input.readInt(), entries); String previous = null;
                for (int index = 0; index < count; index++) {
                    int length = bounded(input.readUnsignedShort(), 128, input.available());
                    String key = text(readBytes(input, length)); requireIdentifier(key);
                    if (previous != null && previous.compareTo(key) >= 0) throw invalid();
                    previous = key; read(input, depth + 1, entries);
                }
            }
            default -> throw invalid();
        }
    }
    private static int collectionCount(int count, int[] entries) {
        if (count < 0 || count > MAX_ENTRIES || entries[0] > MAX_ENTRIES - count) throw invalid();
        entries[0] += count; return count;
    }
    private static byte[] readBytes(DataInputStream input, int length) throws IOException {
        byte[] bytes = input.readNBytes(length); if (bytes.length != length) throw invalid(); return bytes;
    }
    private static int bounded(int length, int maximum, int available) {
        if (length < 0 || length > maximum || length > available) throw invalid(); return length;
    }
    private static void requireSize(long length) { if (length < 1 || length > MAX_BYTES) throw invalid(); }
    static void requireIdentifier(String value) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{1,128}")) throw invalid();
    }
    static byte[] utf8(String value) {
        if (value == null || value.indexOf('\0') >= 0) throw invalid();
        try {
            ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
            byte[] result = new byte[bytes.remaining()]; bytes.get(result); return result;
        } catch (CharacterCodingException invalid) { throw invalid(); }
    }
    static String text(byte[] bytes) {
        try {
            String result = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (result.indexOf('\0') >= 0) throw invalid(); return result;
        } catch (CharacterCodingException invalid) { throw invalid(); }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK_VALUE_INVALID"); }
}
