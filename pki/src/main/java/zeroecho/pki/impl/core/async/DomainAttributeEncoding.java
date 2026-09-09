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
package zeroecho.pki.impl.core.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Comparator;
import java.util.ArrayList;
import java.util.List;

import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/** Strict bounded encoding of the closed public attribute-value hierarchy. */
public final class DomainAttributeEncoding {
    private static final int VERSION = 1;
    private static final int MAXIMUM_BYTES = 786_432;
    private static final int MAXIMUM_ENTRIES = 4_096;

    private DomainAttributeEncoding() { }

    /**
     * Encodes an exact immutable attribute set as canonical base64url.
     *
     * @param attributes immutable attributes to encode
     * @return canonical unpadded base64url representation
     */
    public static String encode(AttributeSet attributes) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(VERSION);
            List<AttributeId> ids = attributes.ids().stream()
                    .sorted(Comparator.comparing(AttributeId::value)).toList();
            if (ids.size() > MAXIMUM_ENTRIES) {
                throw invalid();
            }
            output.writeInt(ids.size());
            for (AttributeId id : ids) {
                writeBytes(output, id.value().getBytes(StandardCharsets.UTF_8));
                List<AttributeValue> values = attributes.getAll(id);
                if (values.size() > MAXIMUM_ENTRIES) {
                    throw invalid();
                }
                output.writeInt(values.size());
                for (AttributeValue value : values) {
                    writeValue(output, value);
                }
            }
            output.flush();
            if (bytes.size() > MAXIMUM_BYTES) {
                throw invalid();
            }
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory attribute encoding failed", impossible);
        }
    }

    /**
     * Decodes and validates one exact canonical base64url attribute set.
     *
     * @param encoded canonical unpadded base64url representation
     * @return decoded immutable attributes
     */
    public static AttributeSet decode(String encoded) {
        byte[] bytes = decodeCanonicalBase64(encoded);
        try {
            AttributeSet decoded = decodeAttributes(bytes);
            if (!encode(decoded).equals(encoded)) {
                throw invalid();
            }
            return decoded;
        } finally {
            java.util.Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] decodeCanonicalBase64(String encoded) {
        if (encoded == null || encoded.length() > (MAXIMUM_BYTES * 4 / 3) + 4) {
            throw invalid();
        }
        byte[] bytes;
        try {
            bytes = java.util.Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException malformed) {
            throw invalid(malformed);
        }
        if (!java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(encoded)) {
            throw invalid();
        }
        return bytes;
    }

    private static AttributeSet decodeAttributes(byte[] bytes) {
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readInt() != VERSION) {
                throw invalid();
            }
            int count = boundedCount(input.readInt());
            List<SimpleAttributeSet.Entry> result = new ArrayList<>(count);
            String previous = null;
            for (int index = 0; index < count; index++) {
                previous = readEntry(input, result, previous);
            }
            if (input.read() != -1) {
                throw invalid();
            }
            return new SimpleAttributeSet(result);
        } catch (IOException malformed) {
            throw invalid(malformed);
        }
    }

    private static String readEntry(DataInputStream input, List<SimpleAttributeSet.Entry> result,
            String previous) throws IOException {
        String identity = canonicalText(readBytes(input));
        if (previous != null && previous.compareTo(identity) >= 0) {
            throw invalid();
        }
        AttributeId id = new AttributeId(identity);
        int values = boundedCount(input.readInt());
        List<AttributeValue> decoded = new ArrayList<>(values);
        for (int value = 0; value < values; value++) {
            decoded.add(readValue(input));
        }
        result.add(new SimpleAttributeSet.Entry(id, decoded));
        return identity;
    }

    private static void writeValue(DataOutputStream output, AttributeValue value) throws IOException {
        switch (value) {
            case AttributeValue.StringValue text -> {
                output.writeByte(1); writeBytes(output, text.value().getBytes(StandardCharsets.UTF_8));
            }
            case AttributeValue.BooleanValue flag -> {
                output.writeByte(2); output.writeBoolean(flag.value());
            }
            case AttributeValue.IntegerValue number -> {
                output.writeByte(3); output.writeLong(number.value());
            }
            case AttributeValue.InstantValue instant -> {
                output.writeByte(4); writeBytes(output, instant.value().toString().getBytes(StandardCharsets.US_ASCII));
            }
            case AttributeValue.BytesValue binary -> {
                output.writeByte(5); writeBytes(output, binary.value());
            }
        }
    }

    private static AttributeValue readValue(DataInputStream input) throws IOException {
        return switch (input.readUnsignedByte()) {
            case 1 -> new AttributeValue.StringValue(canonicalText(readBytes(input)));
            case 2 -> new AttributeValue.BooleanValue(readBoolean(input));
            case 3 -> new AttributeValue.IntegerValue(input.readLong());
            case 4 -> new AttributeValue.InstantValue(readInstant(input));
            case 5 -> new AttributeValue.BytesValue(readBytes(input));
            default -> throw invalid();
    };
    }

    private static boolean readBoolean(DataInputStream input) throws IOException {
        int value = input.readUnsignedByte();
        if (value != 0 && value != 1) {
            throw invalid();
        }
        return value == 1;
    }

    private static Instant readInstant(DataInputStream input) throws IOException {
        String encoded = canonicalText(readBytes(input));
        Instant instant;
        try {
            instant = Instant.parse(encoded);
        } catch (java.time.format.DateTimeParseException malformed) {
            throw invalid(malformed);
        }
        if (!instant.toString().equals(encoded)) {
            throw invalid();
        }
        return instant;
    }

    private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
        if (value.length > MAXIMUM_BYTES) {
            throw invalid();
        }
        output.writeInt(value.length);
        output.write(value);
    }

    private static byte[] readBytes(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAXIMUM_BYTES || length > input.available()) {
            throw invalid();
        }
        return input.readNBytes(length);
    }

    private static String canonicalText(byte[] value) throws IOException {
        String result = new String(value, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(value, result.getBytes(StandardCharsets.UTF_8))) {
            throw invalid();
        }
        return result;
    }

    private static int boundedCount(int value) throws IOException {
        if (value < 0 || value > MAXIMUM_ENTRIES) {
            throw invalid();
        }
        return value;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Domain attribute encoding is invalid");
    }

    private static IllegalArgumentException invalid(Exception cause) {
        return new IllegalArgumentException("Domain attribute encoding is invalid", cause);
    }
}
