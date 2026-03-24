/*******************************************************************************
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
package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;

import zeroecho.core.io.Util;

/**
 * Compact binary codec for filesystem persistence.
 *
 * <h2>Encoding format</h2>
 * <p>
 * The codec supports two on-wire formats:
 * </p>
 * <ul>
 * <li><b>Compact format (current)</b>: begins with a 1-byte MAGIC marker
 * {@code 0xFF}, followed by a 1-byte TAG and tag-specific payload.</li>
 * <li><b>Legacy format (backward-compatible)</b>: begins with a UTF-8 encoded
 * Java class name (written by
 * {@link zeroecho.core.io.Util#writeUTF8(OutputStream, String)}), followed by
 * value payload based on that class.</li>
 * </ul>
 *
 * <p>
 * The compact format eliminates the pathological overhead of writing a full
 * Java class name for every scalar value (e.g., {@code boolean}). It also
 * substantially reduces class-loading activity during decode.
 * </p>
 *
 * <h2>Type compatibility</h2>
 * <p>
 * During decode, the codec enforces that the encoded value type is compatible
 * with the expected type. Primitive/wrapper pairs (e.g.,
 * {@code boolean}/{@link Boolean}) are treated as compatible because values are
 * boxed when represented as {@link Object}.
 * </p>
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class FsCodec {

    private static final int MAX_STRING_BYTES = 256 * 1024;

    private static final Map<Class<?>, Class<?>> PRIMITIVE_TO_WRAPPER = Map.of(boolean.class, Boolean.class, byte.class,
            Byte.class, short.class, Short.class, int.class, Integer.class, long.class, Long.class, char.class,
            Character.class, float.class, Float.class, double.class, Double.class);

    /**
     * Magic byte that marks the compact format.
     *
     * <p>
     * This value is chosen to be extremely unlikely as a first byte of the legacy
     * UTF-8 class-name length prefix. Class names are short; legacy length prefix
     * first byte will be &lt; 0x80.
     * </p>
     */
    private static final int MAGIC_COMPACT = 0xFF;

    // Compact tags (1 byte). Keep stable.
    private static final int TAG_STRING = 1;
    private static final int TAG_INT = 2;
    private static final int TAG_LONG = 3;
    private static final int TAG_BOOL = 4;
    private static final int TAG_BYTES = 5;
    private static final int TAG_INSTANT = 6;
    private static final int TAG_DURATION = 7;
    private static final int TAG_ENUM = 8;
    private static final int TAG_RECORD = 9;
    private static final int TAG_FALLBACK_STRING = 10;
    private static final int TAG_LIST = 11;
    private static final int TAG_SET = 12;
    private static final int TAG_OPTIONAL = 13;

    private FsCodec() {
        // utility
    }

    /* default */ static <T> byte[] encode(final T value) {
        Objects.requireNonNull(value, "value");
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeAnyCompact(bos, value);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("encoding failed: " + value.getClass().getName(), e);
        }
    }

    /* default */ static <T> T decode(final byte[] data, final Class<T> expectedType) {
        Objects.requireNonNull(data, "data");
        Objects.requireNonNull(expectedType, "expectedType");
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            Object decoded = readAny(bis, expectedType);
            return expectedType.cast(decoded);
        } catch (IOException e) {
            throw new IllegalStateException("decoding failed: " + expectedType.getName(), e);
        }
    }

    private static void writeAnyCompact(final OutputStream out, final Object value) throws IOException {
        Objects.requireNonNull(out, "out");
        Objects.requireNonNull(value, "value");

        out.write(MAGIC_COMPACT);

        switch (value) {
            case String s -> writeStringCompact(out, s);
            case Integer i -> writeIntegerCompact(out, i);
            case Long l -> writeLongCompact(out, l);
            case Boolean b -> writeBooleanCompact(out, b);
            case byte[] bytes -> writeBytesCompact(out, bytes);
            case Instant instant -> writeInstantCompact(out, instant);
            case Duration duration -> writeDurationCompact(out, duration);
            case java.util.List<?> list -> writeListCompact(out, list);
            case java.util.Set<?> set -> writeSetCompact(out, set);
            case java.util.Optional<?> optional -> writeOptionalCompact(out, optional);
            default -> writeComplexCompact(out, value);
        }
    }

    private static void writeStringCompact(final OutputStream out, final String value) throws IOException {
        out.write(TAG_STRING);
        Util.writeUTF8(out, value);
    }

    private static void writeIntegerCompact(final OutputStream out, final Integer value) throws IOException {
        out.write(TAG_INT);
        Util.writePack7I(out, value);
    }

    private static void writeLongCompact(final OutputStream out, final Long value) throws IOException {
        out.write(TAG_LONG);
        Util.writePack7L(out, value);
    }

    private static void writeBooleanCompact(final OutputStream out, final Boolean value) throws IOException {
        out.write(TAG_BOOL);
        out.write(value ? 1 : 0);
    }

    private static void writeBytesCompact(final OutputStream out, final byte[] value) throws IOException {
        out.write(TAG_BYTES);
        Util.write(out, value);
    }

    private static void writeInstantCompact(final OutputStream out, final Instant value) throws IOException {
        out.write(TAG_INSTANT);
        Util.writeLong(out, value.getEpochSecond());
        Util.writePack7I(out, value.getNano());
    }

    private static void writeDurationCompact(final OutputStream out, final Duration value) throws IOException {
        out.write(TAG_DURATION);
        Util.writeLong(out, value.getSeconds());
        Util.writePack7I(out, value.getNano());
    }

    private static void writeListCompact(final OutputStream out, final java.util.List<?> list) throws IOException {
        out.write(TAG_LIST);
        Util.writePack7I(out, list.size());
        for (Object element : list) {
            Objects.requireNonNull(element, "list element must not be null");
            writeAnyCompact(out, element);
        }
    }

    private static void writeSetCompact(final OutputStream out, final java.util.Set<?> set) throws IOException {
        out.write(TAG_SET);

        java.util.List<Object> ordered = new java.util.ArrayList<>(set.size());
        ordered.addAll(set);
        sortSetElementsDeterministically(ordered);

        Util.writePack7I(out, ordered.size());
        for (Object element : ordered) {
            Objects.requireNonNull(element, "set element must not be null");
            writeAnyCompact(out, element);
        }
    }

    private static void sortSetElementsDeterministically(final java.util.List<Object> ordered) {
        ordered.sort((a, b) -> {
            if (a == b) { // NOPMD
                return 0;
            }
            if (a == null) {
                return -1;
            }
            if (b == null) {
                return 1;
            }
            if (a instanceof Comparable<?> && a.getClass() == b.getClass()) {
                @SuppressWarnings("unchecked")
                Comparable<Object> comparable = (Comparable<Object>) a;
                return comparable.compareTo(b);
            }
            return stableSortKey(a).compareTo(stableSortKey(b));
        });
    }

    private static void writeOptionalCompact(final OutputStream out, final java.util.Optional<?> optional)
            throws IOException {
        out.write(TAG_OPTIONAL);
        if (optional.isPresent()) {
            out.write(1);
            Object element = optional.get();
            Objects.requireNonNull(element, "optional element must not be null");
            writeAnyCompact(out, element);
            return;
        }
        out.write(0);
    }

    private static void writeComplexCompact(final OutputStream out, final Object value) throws IOException {
        Class<?> type = value.getClass();
        if (type.isEnum()) {
            writeEnumCompact(out, type, value);
            return;
        }
        if (type.isRecord()) {
            writeRecordCompact(out, type, value);
            return;
        }
        writeFallbackStringCompact(out, type, value);
    }

    private static void writeEnumCompact(final OutputStream out, final Class<?> type, final Object value)
            throws IOException {
        out.write(TAG_ENUM);
        Util.writeUTF8(out, type.getName());
        Enum<?> enumValue = (Enum<?>) value;
        Util.writePack7I(out, enumValue.ordinal());
    }

    private static void writeRecordCompact(final OutputStream out, final Class<?> type, final Object value)
            throws IOException {
        out.write(TAG_RECORD);
        Util.writeUTF8(out, type.getName());

        RecordComponent[] components = type.getRecordComponents();
        Util.writePack7I(out, components.length);

        for (RecordComponent component : components) {
            Object componentValue = invokeRecordAccessor(type, component, value);
            Objects.requireNonNull(componentValue, "record component " + type.getName() + "." + component.getName());
            writeAnyCompact(out, componentValue);
        }
    }

    private static Object invokeRecordAccessor(final Class<?> type, final RecordComponent component,
            final Object value) {
        try {
            Method accessor = component.getAccessor();
            return accessor.invoke(value);
        } catch (IllegalAccessException | InvocationTargetException ex) {
            throw new IllegalStateException("record encode failed: " + type.getName() + "." + component.getName(), ex);
        }
    }

    private static void writeFallbackStringCompact(final OutputStream out, final Class<?> type, final Object value)
            throws IOException {
        out.write(TAG_FALLBACK_STRING);
        Util.writeUTF8(out, type.getName());
        Util.writeUTF8(out, value.toString());
    }

    private static String stableSortKey(final Object o) {
        return o.getClass().getName() + ":" + o.toString();
    }

    private static Object readAny(final InputStream in, final Class<?> expectedType) throws IOException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(expectedType, "expectedType");

        int first = in.read();
        if (first < 0) {
            throw new IOException("unexpected EOF");
        }

        if (first != MAGIC_COMPACT) {
            throw new IllegalStateException(
                    "file mismatch, MAGIC byte expected=" + MAGIC_COMPACT + " but found=" + first);
        }

        int tag = in.read();
        if (tag < 0) {
            throw new IOException("unexpected EOF");
        }

        Object value = readByTag(in, tag);

        if (!isTypeCompatible(expectedType, value.getClass())) {
            throw new IllegalStateException(
                    "type mismatch, expected " + expectedType.getName() + " but decoded " + value.getClass().getName());
        }

        return value;
    }

    private static Object readByTag(final InputStream in, final int tag) throws IOException {
        switch (tag) {
            case TAG_STRING:
                return readStringCompact(in);
            case TAG_INT:
                return readIntegerCompact(in);
            case TAG_LONG:
                return readLongCompact(in);
            case TAG_BOOL:
                return readBooleanCompact(in);
            case TAG_BYTES:
                return readBytesCompact(in);
            case TAG_INSTANT:
                return readInstantCompact(in);
            case TAG_DURATION:
                return readDurationCompact(in);
            case TAG_ENUM:
                return readEnumCompact(in);
            case TAG_RECORD:
                return readRecordCompact(in);
            case TAG_FALLBACK_STRING:
                return readFallbackStringCompact(in);
            case TAG_LIST:
                return readListCompact(in);
            case TAG_SET:
                return readSetCompact(in);
            case TAG_OPTIONAL:
                return readOptionalCompact(in);
            default:
                throw new IllegalStateException("unknown compact tag: " + tag);
        }
    }

    private static String readStringCompact(final InputStream in) throws IOException {
        return Util.readUTF8(in, MAX_STRING_BYTES);
    }

    private static int readIntegerCompact(final InputStream in) throws IOException {
        return Util.readPack7I(in);
    }

    private static long readLongCompact(final InputStream in) throws IOException {
        return Util.readPack7L(in);
    }

    private static boolean readBooleanCompact(final InputStream in) throws IOException {
        int value = in.read();
        if (value < 0) {
            throw new IOException("unexpected EOF");
        }
        return value != 0;
    }

    private static byte[] readBytesCompact(final InputStream in) throws IOException {
        return Util.read(in, MAX_STRING_BYTES);
    }

    private static Instant readInstantCompact(final InputStream in) throws IOException {
        long seconds = Util.readLong(in);
        int nanos = Util.readPack7I(in);
        return Instant.ofEpochSecond(seconds, nanos);
    }

    private static Duration readDurationCompact(final InputStream in) throws IOException {
        long seconds = Util.readLong(in);
        int nanos = Util.readPack7I(in);
        return Duration.ofSeconds(seconds, nanos);
    }

    private static Object readEnumCompact(final InputStream in) throws IOException {
        String enumTypeName = Util.readUTF8(in, MAX_STRING_BYTES);
        Class<?> enumType = loadClass(enumTypeName);
        if (!enumType.isEnum()) {
            throw new IllegalStateException("encoded enum type is not an enum: " + enumTypeName);
        }

        int ordinal = Util.readPack7I(in);
        Object[] constants = enumType.getEnumConstants();
        if (constants == null || ordinal < 0 || ordinal >= constants.length) {
            throw new IllegalStateException("invalid enum ordinal " + ordinal + " for " + enumTypeName);
        }
        return constants[ordinal];
    }

    private static Object readRecordCompact(final InputStream in) throws IOException {
        String recordTypeName = Util.readUTF8(in, MAX_STRING_BYTES);
        Class<?> recordType = loadClass(recordTypeName);
        if (!recordType.isRecord()) {
            throw new IllegalStateException("encoded record type is not a record: " + recordTypeName);
        }

        int componentCount = Util.readPack7I(in);
        RecordComponent[] components = recordType.getRecordComponents();
        if (components.length != componentCount) {
            throw new IllegalStateException("record component count mismatch for " + recordTypeName + ", expected "
                    + components.length + " but encoded " + componentCount);
        }

        Class<?>[] constructorTypes = new Class<?>[components.length];
        Object[] constructorArgs = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            RecordComponent component = components[i];
            constructorTypes[i] = component.getType();
            constructorArgs[i] = readAny(in, constructorTypes[i]);
        }

        try {
            return recordType.getDeclaredConstructor(constructorTypes).newInstance(constructorArgs);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("record decode failed for " + recordTypeName, ex);
        }
    }

    private static Object readFallbackStringCompact(final InputStream in) throws IOException {
        String typeName = Util.readUTF8(in, MAX_STRING_BYTES);
        String value = Util.readUTF8(in, MAX_STRING_BYTES);
        Class<?> type = loadClass(typeName);

        Method stringFactory = findStringFactory(type);
        if (stringFactory != null) {
            try {
                return stringFactory.invoke(null, value);
            } catch (ReflectiveOperationException ex) {
                throw new IllegalStateException("from-string factory failed for " + type.getName(), ex);
            }
        }

        try {
            return type.getConstructor(String.class).newInstance(value);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("unsupported value type without from-string factory: " + type.getName(),
                    ex);
        }
    }

    private static Object readListCompact(final InputStream in) throws IOException {
        int size = Util.readPack7I(in);
        java.util.List<Object> out = new java.util.ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            Object element = readAny(in, Object.class);
            out.add(element);
        }
        return java.util.List.copyOf(out);
    }

    private static Object readSetCompact(final InputStream in) throws IOException {
        int size = Util.readPack7I(in);
        java.util.Set<Object> out = new java.util.LinkedHashSet<>(size);
        for (int i = 0; i < size; i++) {
            Object element = readAny(in, Object.class);
            out.add(element);
        }
        return java.util.Set.copyOf(out);
    }

    private static Object readOptionalCompact(final InputStream in) throws IOException {
        int present = in.read();
        if (present < 0) {
            throw new IOException("unexpected EOF");
        }
        if (present == 0) {
            return java.util.Optional.empty();
        }
        Object element = readAny(in, Object.class);
        return java.util.Optional.of(element);
    }

    private static boolean isTypeCompatible(final Class<?> expectedType, final Class<?> actualType) {
        if (expectedType.isAssignableFrom(actualType)) {
            return true;
        }

        Class<?> expectedWrapper = PRIMITIVE_TO_WRAPPER.get(expectedType);
        if (expectedWrapper != null && expectedWrapper == actualType) {
            return true;
        }

        Class<?> actualWrapper = PRIMITIVE_TO_WRAPPER.get(actualType);
        return actualWrapper != null && actualWrapper == expectedType;
    }

    @SuppressWarnings("PMD.UseProperClassLoader")
    private static Class<?> loadClass(final String typeName) {
        Objects.requireNonNull(typeName, "typeName");

        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = MethodHandles.lookup().lookupClass().getClassLoader();
        }

        try {
            return Class.forName(typeName, false, cl);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("unknown encoded type: " + typeName, e);
        }
    }

    private static Method findStringFactory(final Class<?> type) {
        try {
            Method of = type.getMethod("of", String.class);
            if ((of.getModifiers() & java.lang.reflect.Modifier.STATIC) != 0 && of.getReturnType() == type) {
                return of;
            }
        } catch (NoSuchMethodException ex) { // NOPMD
            // ignore
        }

        try {
            Method valueOf = type.getMethod("valueOf", String.class);
            if ((valueOf.getModifiers() & java.lang.reflect.Modifier.STATIC) != 0 && valueOf.getReturnType() == type) {
                return valueOf;
            }
        } catch (NoSuchMethodException ex) { // NOPMD
            // ignore
        }

        return null;
    }
}