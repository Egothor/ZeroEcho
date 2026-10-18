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
package zeroecho.pki.impl.core.continuation;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.List;
import java.util.ArrayList;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Strict length-framed encoding for frozen outer-operation command fields. */
public final class DomainCommandEncoding {
    private static final int MAGIC = 0x5A45444F;
    private static final int VERSION = 1;
    private static final int MAXIMUM_BYTES = 1_048_576;

    private DomainCommandEncoding() { }

    /**
     * Derives the immutable authority identity for an internal root creation.
     * The identity is frozen before acceptance and does not depend on a signature.
     * @param operationId exact signing submission identifier
     * @return domain-separated deterministic root authority identity
     */
    public static zeroecho.pki.api.PkiId rootAuthorityId(zeroecho.pki.api.PkiId operationId) {
        zeroecho.pki.api.orch.SigningSubmissionId.parse(operationId);
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update("zeroecho:pki:root-authority:v1\0".getBytes(StandardCharsets.US_ASCII));
            return new zeroecho.pki.api.PkiId("ca:" + java.util.HexFormat.of().formatHex(
                    digest.digest(operationId.value().getBytes(StandardCharsets.UTF_8))));
        } catch (java.security.NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 unavailable", unavailable);
        }
    }

    /**
     * Encodes one exact prepared domain command from stable canonical fields.
     * Field order is part of the command schema selected by {@code operation}.
     *
     * @param kind durable outer-continuation kind
     * @param operation nonblank schema discriminator
     * @param fields ordered canonical command fields
     * @return immutable domain continuation template
     */
    public static DomainContinuationTemplate template(DomainContinuationStore.Kind kind,
            String operation, String... fields) {
        return template(kind, Optional.empty(), operation, fields);
    }

    /**
     * Encodes a command carrying an exact restart idempotency identity.
     *
     * @param kind durable outer-continuation kind
     * @param correlationId exact restart idempotency identity
     * @param operation nonblank schema discriminator
     * @param fields ordered canonical command fields
     * @return immutable correlated continuation template
     */
    public static DomainContinuationTemplate correlatedTemplate(DomainContinuationStore.Kind kind,
            String correlationId, String operation, String... fields) {
        return template(kind, Optional.of(Objects.requireNonNull(correlationId, "correlationId")),
                operation, fields);
    }

    private static DomainContinuationTemplate template(DomainContinuationStore.Kind kind,
            Optional<String> correlationId, String operation, String... fields) {
        Objects.requireNonNull(kind, "kind");
        if (operation == null || operation.isBlank()) {
            throw new IllegalArgumentException("operation must not be blank");
        }
        Objects.requireNonNull(fields, "fields");
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(MAGIC);
            output.writeByte(VERSION);
            writeField(output, operation);
            output.writeInt(fields.length);
            for (String field : fields) {
                writeField(output, Objects.requireNonNull(field, "field"));
            }
            output.flush();
            if (bytes.size() > MAXIMUM_BYTES) {
                throw new IllegalArgumentException("Domain command exceeds its durable bound");
            }
            EncodedObject command = new EncodedObject(Encoding.BINARY, bytes.toByteArray());
            return correlationId.isPresent()
                    ? DomainContinuationTemplate.createCorrelated(kind, correlationId.orElseThrow(), command)
                    : DomainContinuationTemplate.create(kind, command);
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory domain command encoding failed", impossible);
        }
    }

    /**
     * Returns the strict operation discriminator from a persisted command.
     *
     * @param command bounded binary command encoding
     * @return nonblank operation discriminator
     */
    public static String operation(EncodedObject command) {
        return decode(command).operation();
    }

    /**
     * Strictly decodes one bounded command into its discriminator and fields.
     *
     * @param command bounded binary command encoding
     * @return immutable decoded discriminator and fields
     */
    public static Decoded decode(EncodedObject command) {
        Objects.requireNonNull(command, "command");
        if (command.encoding() != Encoding.BINARY) {
            throw new IllegalArgumentException("Domain command encoding is invalid");
        }
        byte[] bytes = command.bytes();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readInt() != MAGIC || input.readUnsignedByte() != VERSION) {
                throw new IllegalArgumentException("Domain command header is invalid");
            }
            String operation = readField(input);
            int fields = input.readInt();
            if (fields < 0 || fields > 4096) {
                throw new IllegalArgumentException("Domain command field count is invalid");
            }
            List<String> values = new ArrayList<>(fields);
            for (int index = 0; index < fields; index++) {
                values.add(readField(input));
            }
            if (input.available() != 0) {
                throw new IllegalArgumentException("Domain command has trailing data");
            }
            return new Decoded(operation, values);
        } catch (IOException malformed) {
            throw new IllegalArgumentException("Domain command is truncated", malformed);
        }
    }

    /**
     * Immutable decoded command.
     *
     * @param operation nonblank operation discriminator
     * @param fields immutable ordered command fields
     */
    public record Decoded(String operation, List<String> fields) {
        /** Snapshots decoded values. */
        public Decoded {
            if (operation == null || operation.isBlank()) {
                throw new IllegalArgumentException("Domain command operation is invalid");
            }
            fields = List.copyOf(Objects.requireNonNull(fields, "fields"));
        }

        /**
         * Returns an exact field or rejects the schema mismatch.
         *
         * @param index zero-based field index
         * @return exact field at {@code index}
         */
        public String field(int index) {
            if (index < 0 || index >= fields.size()) {
                throw new IllegalArgumentException("Domain command field is unavailable");
            }
            return fields.get(index);
        }

        /**
         * Requires the exact current field count.
         *
         * @param expected required nonnegative field count
         * @return this decoded command after validation
         */
        public Decoded requireFields(int expected) {
            if (fields.size() != expected) {
                throw new IllegalArgumentException("Domain command field count differs");
            }
            return this;
        }
    }

    private static void writeField(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Domain command field exceeds its durable bound");
        }
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static String readField(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length < 0 || length > MAXIMUM_BYTES || length > input.available()) {
            throw new IOException("Domain command field length is invalid");
        }
        byte[] bytes = input.readNBytes(length);
        String value = new String(bytes, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, value.getBytes(StandardCharsets.UTF_8))) {
            throw new IOException("Domain command field is not canonical UTF-8");
        }
        return value;
    }
}
