/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import zeroecho.core.io.Util;

/**
 * Deterministic binary codec for PKI store objects.
 *
 * <p>
 * This codec is designed for:
 * </p>
 * <ul>
 * <li>Deterministic serialization across JVM runs.</li>
 * <li>No external dependencies.</li>
 * <li>Support for records (the dominant pattern in the PKI API).</li>
 * </ul>
 *
 * <p>
 * Supported types:
 * </p>
 * <ul>
 * <li>primitive wrappers, {@link String}, {@code byte[]}</li>
 * <li>{@link Instant}, {@link Duration}, {@link UUID}</li>
 * <li>{@link Optional}, {@link List}</li>
 * <li>{@link Enum}</li>
 * <li>Java {@code record} types, recursively</li>
 * </ul>
 *
 * <p>
 * For non-record custom value objects, decoding attempts the following (in this
 * order) using a single {@link String} argument: {@code fromString},
 * {@code parse}, {@code of}, {@code valueOf}, or a public constructor. The
 * serialized form is {@code toString()}.
 * </p>
 *
 * <p>
 * If none of the above works, an exception is thrown. This is intentional: the
 * persistence layer must be explicit and auditable.
 * </p>
 */
final class FsCodec {

    private static final int MAX_STRING_BYTES = 1024 * 1024 * 4; // 4 MiB safety cap

    /**
     * Hard upper bound for any stored binary blob (defense-in-depth against corrupt
     * files and unbounded allocations). This is not a security boundary.
     */
    private static final int MAX_BLOB_BYTES = 16 * 1024 * 1024; // 16 MiB

    private FsCodec() {
        // utility class
    }

    /* default */ static <T> byte[] encode(final T value) {
        Objects.requireNonNull(value, "value");
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            writeAny(bos, value);
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
            throw new IllegalStateException("decoding failed for " + expectedType.getName(), e);
        }
    }

    private static void writeAny(final OutputStream out, final Object value) throws IOException { // NOPMD
        Objects.requireNonNull(out, "out");
        Objects.requireNonNull(value, "value");

        Class<?> type = value.getClass();
        Util.writeUTF8(out, type.getName());

        if (value instanceof String s) {
            writeString(out, s);
            return;
        }
        if (value instanceof Integer i) {
            Util.writePack7I(out, i);
            return;
        }
        if (value instanceof Long l) {
            Util.writeLong(out, l);
            return;
        }
        if (value instanceof Boolean b) {
            out.write(b ? 1 : 0);
            return;
        }
        if (value instanceof byte[] bytes) {
            Util.write(out, bytes);
            return;
        }
        if (value instanceof Instant instant) {
            Util.writeLong(out, instant.getEpochSecond());
            Util.writePack7I(out, instant.getNano());
            return;
        }
        if (value instanceof Duration duration) {
            Util.writeLong(out, duration.getSeconds());
            Util.writePack7I(out, duration.getNano());
            return;
        }
        if (value instanceof UUID uuid) {
            Util.write(out, uuid);
            return;
        }
        if (value instanceof Optional<?> opt) {
            out.write(opt.isPresent() ? 1 : 0);
            if (opt.isPresent()) {
                writeAny(out, opt.get());
            }
            return;
        }
        if (value instanceof List<?> list) {
            Util.writePack7I(out, list.size());
            for (Object item : list) {
                writeAny(out, item);
            }
            return;
        }
        if (type.isEnum()) {
            Enum<?> e = (Enum<?>) value;
            writeString(out, e.name());
            return;
        }
        if (type.isRecord()) {
            RecordComponent[] components = type.getRecordComponents();
            Util.writePack7I(out, components.length);
            for (RecordComponent c : components) {
                try {
                    Method accessor = c.getAccessor();
                    Object componentValue = accessor.invoke(value);
                    writeAny(out, componentValue);
                } catch (ReflectiveOperationException ex) {
                    throw new IllegalStateException("record encode failed: " + type.getName() + "." + c.getName(), ex);
                }
            }
            return;
        }

        // fallback: encode as string and reconstruct via string factory on decode
        writeString(out, value.toString());
    }

    private static Object readAny(final InputStream in, final Class<?> expectedType) throws IOException {
        Objects.requireNonNull(in, "in");
        Objects.requireNonNull(expectedType, "expectedType");

        String encodedTypeName = Util.readUTF8(in, MAX_STRING_BYTES);
        Class<?> encodedType;
        ClassLoader primary = MethodHandles.lookup().lookupClass().getClassLoader(); // NOPMD
        try {
            encodedType = Class.forName(encodedTypeName, false, primary);
        } catch (ClassNotFoundException e) {
            ClassLoader tccl = Thread.currentThread().getContextClassLoader();
            if (tccl != null && tccl != primary) { // NOPMD
                try {
                    return Class.forName(encodedTypeName, false, tccl);
                } catch (ClassNotFoundException e1) {
                    e = e1; // NOPMD
                }
            }
            throw new IllegalStateException("unknown encoded type: " + encodedTypeName, e);
        }

        // decode using the encoded type (authoritative)
        Object value = readByType(in, encodedType);

        // enforce expected assignment
        if (!expectedType.isAssignableFrom(encodedType)) {
            throw new IllegalStateException(
                    "type mismatch, expected " + expectedType.getName() + " but encoded " + encodedType.getName());
        }
        return value;
    }

    private static Object readByType(final InputStream in, final Class<?> type) throws IOException { // NOPMD
        if (type == String.class) {
            return Util.readUTF8(in, MAX_STRING_BYTES);
        }
        if (type == Integer.class) {
            return Util.readPack7I(in);
        }
        if (type == Long.class) {
            return Util.readLong(in);
        }
        if (type == Boolean.class) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("unexpected EOF");
            }
            return b != 0;
        }
        if (type == byte[].class) {
            return Util.read(in, MAX_BLOB_BYTES);
        }
        if (type == Instant.class) {
            long seconds = Util.readLong(in);
            int nanos = Util.readPack7I(in);
            return Instant.ofEpochSecond(seconds, nanos);
        }
        if (type == Duration.class) {
            long seconds = Util.readLong(in);
            int nanos = Util.readPack7I(in);
            return Duration.ofSeconds(seconds, nanos);
        }
        if (type == UUID.class) {
            return Util.readUUID(in);
        }
        if (type == Optional.class) {
            int present = in.read();
            if (present < 0) {
                throw new IOException("unexpected EOF");
            }
            if (present == 0) {
                return Optional.empty();
            }
            // generic type erased; decode nested object as Object
            Object nested = readAny(in, Object.class);
            return Optional.of(nested);
        }
        if (List.class.isAssignableFrom(type)) {
            int size = Util.readPack7I(in);
            List<Object> out = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
                Object item = readAny(in, Object.class);
                out.add(item);
            }
            return out;
        }
        if (type.isEnum()) {
            String name = Util.readUTF8(in, MAX_STRING_BYTES);
            @SuppressWarnings({ "unchecked", "rawtypes" })
            Enum<?> e = Enum.valueOf((Class) type, name);
            return e;
        }
        if (type.isRecord()) {
            RecordComponent[] components = type.getRecordComponents();
            int count = Util.readPack7I(in);
            if (count != components.length) {
                throw new IllegalStateException("record component count mismatch for " + type.getName());
            }
            Object[] args = new Object[components.length];
            Class<?>[] ctorTypes = new Class<?>[components.length];

            for (int i = 0; i < components.length; i++) {
                RecordComponent c = components[i];
                ctorTypes[i] = c.getType();
                args[i] = readAny(in, c.getType());
            }

            try {
                Constructor<?> ctor = type.getDeclaredConstructor(ctorTypes);
                ctor.setAccessible(true); // NOPMD
                return ctor.newInstance(args);
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException("record decode failed: " + type.getName(), e);
            }
        }

        // fallback: read string and reconstruct with best-effort factory methods
        String stringForm = Util.readUTF8(in, MAX_STRING_BYTES);
        Object reconstructed = tryFromString(type, stringForm);
        if (reconstructed != null) {
            return reconstructed;
        }
        throw new IllegalStateException("unsupported value type without from-string factory: " + type.getName());
    }

    private static void writeString(final OutputStream out, final String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        Util.writePack7I(out, bytes.length);
        out.write(bytes);
    }

    private static Object tryFromString(final Class<?> type, final String s) {
        List<String> methodNames = List.of("fromString", "parse", "of", "valueOf");
        for (String methodName : methodNames) {
            try {
                Method m = type.getMethod(methodName, String.class);
                if (type.isAssignableFrom(m.getReturnType())) {
                    return m.invoke(null, s);
                }
            } catch (ReflectiveOperationException ignored) {
                // continue
            }
        }

        try {
            Constructor<?> ctor = type.getConstructor(String.class);
            return ctor.newInstance(s);
        } catch (ReflectiveOperationException ignored) {
            // continue
        }

        // common pattern: base64 bytes container
        try {
            Method m = type.getMethod("of", byte[].class);
            if (type.isAssignableFrom(m.getReturnType())) {
                byte[] decoded = Base64.getDecoder().decode(s);
                return m.invoke(null, decoded);
            }
        } catch (ReflectiveOperationException ignored) {
            // ignore
        }

        return null;
    }
}
