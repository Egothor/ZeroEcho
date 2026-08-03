/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.publication.PublicationEvidence;
import zeroecho.pki.api.publication.PublicationFailure;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.spi.store.StagedContentStore;

/** Strict current-schema codec for finite publication control metadata. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidCatchingGenericException",
        "PMD.PreserveStackTrace" })
final class PublicationRecordCodec {
    private static final int MAGIC = 0x5a505542;
    private static final int VERSION = 1;
    private static final int MAXIMUM_RECORD_BYTES = 32 * 1024;
    private static final int MAXIMUM_STRING_BYTES = 4096;
    private static final int OPTIONAL_ABSENT = 0;
    private static final int OPTIONAL_PRESENT = 1;

    private PublicationRecordCodec() {
    }

    /* package */ static byte[] encode(PublicationRecord record) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                writeString(output, record.publicationId().value());
                output.writeInt(sourceTypeCode(record.sourceType()));
                writeString(output, record.sourceId().value());
                writeContent(output, record.content());
                output.writeInt(targetTypeCode(record.target().type()));
                writeString(output, record.target().targetId());
                output.writeInt(statusCode(record.status()));
                output.writeLong(record.attemptNumber());
                writeOptionalString(output, record.attemptToken());
                writeInstant(output, record.createdAt());
                writeInstant(output, record.updatedAt());
                output.writeInt(record.failure().map(PublicationRecordCodec::failureCode).orElse(0));
                output.writeInt(record.evidence().map(PublicationRecordCodec::evidenceCode).orElse(0));
            }
            byte[] encoded = buffer.toByteArray();
            if (encoded.length > MAXIMUM_RECORD_BYTES) {
                throw new IllegalArgumentException("Publication record exceeds its finite metadata limit");
            }
            return encoded;
        } catch (IOException impossible) {
            throw new IllegalStateException("Publication record encoding failed", impossible);
        }
    }

    /* package */ static PublicationRecord decode(byte[] encoded, StagedContentStore stagedContent)
            throws IOException {
        if (encoded.length > MAXIMUM_RECORD_BYTES) {
            throw malformed();
        }
        try (ByteArrayInputStream bytes = new ByteArrayInputStream(encoded);
                DataInputStream input = new DataInputStream(bytes)) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw malformed();
            }
            PkiId publicationId = new PkiId(readString(input));
            PublicationSourceType sourceType = sourceType(input.readInt());
            PkiId sourceId = new PkiId(readString(input));
            DurableContentReference content = readContent(input, stagedContent);
            PublicationTarget target = new PublicationTarget(targetType(input.readInt()), readString(input));
            PublicationStatus status = status(input.readInt());
            long attemptNumber = input.readLong();
            Optional<String> attemptToken = readOptionalString(input);
            Instant createdAt = readInstant(input);
            Instant updatedAt = readInstant(input);
            Optional<PublicationFailure> failure = optionalFailure(input.readInt());
            Optional<PublicationEvidence> evidence = optionalEvidence(input.readInt());
            if (bytes.available() != 0) {
                throw malformed();
            }
            return new PublicationRecord(publicationId, sourceType, sourceId, content, target, status,
                    attemptNumber, attemptToken, createdAt, updatedAt, failure, evidence);
        } catch (EOFException | RuntimeException failure) {
            throw malformed();
        }
    }

    private static void writeContent(DataOutputStream output, DurableContentReference content) throws IOException {
        writeString(output, content.storeId());
        writeString(output, content.contentId());
        output.writeInt(encodingCode(content.encoding()));
        output.writeLong(content.length());
        writeString(output, content.sha256());
        output.writeInt(lifecycleCode(content.lifecycle()));
    }

    private static DurableContentReference readContent(DataInputStream input, StagedContentStore stagedContent)
            throws IOException {
        return stagedContent.restoreReference(readString(input), readString(input), encoding(input.readInt()),
                input.readLong(), readString(input), lifecycle(input.readInt()));
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length == 0 || encoded.length > MAXIMUM_STRING_BYTES) {
            throw new IllegalArgumentException("Publication metadata string is not finite");
        }
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > MAXIMUM_STRING_BYTES) {
            throw malformed();
        }
        byte[] value = input.readNBytes(length);
        if (value.length != length) {
            throw malformed();
        }
        String decoded = new String(value, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(value, decoded.getBytes(StandardCharsets.UTF_8))) {
            throw malformed();
        }
        return decoded;
    }

    private static void writeOptionalString(DataOutputStream output, Optional<String> value) throws IOException {
        output.writeByte(value.isPresent() ? OPTIONAL_PRESENT : OPTIONAL_ABSENT);
        if (value.isPresent()) {
            writeString(output, value.orElseThrow());
        }
    }

    private static Optional<String> readOptionalString(DataInputStream input) throws IOException {
        int marker = input.readUnsignedByte();
        if (marker == OPTIONAL_ABSENT) {
            return Optional.empty();
        }
        if (marker == OPTIONAL_PRESENT) {
            return Optional.of(readString(input));
        }
        throw malformed();
    }

    private static void writeInstant(DataOutputStream output, Instant value) throws IOException {
        output.writeLong(value.getEpochSecond());
        output.writeInt(value.getNano());
    }

    private static Instant readInstant(DataInputStream input) throws IOException {
        return Instant.ofEpochSecond(input.readLong(), input.readInt());
    }

    private static int sourceTypeCode(PublicationSourceType value) {
        return switch (value) {
            case CREDENTIAL -> 1;
            case STATUS_OBJECT -> 2;
        };
    }

    private static PublicationSourceType sourceType(int code) throws IOException {
        return switch (code) {
            case 1 -> PublicationSourceType.CREDENTIAL;
            case 2 -> PublicationSourceType.STATUS_OBJECT;
            default -> throw malformed();
        };
    }

    private static int targetTypeCode(PublicationTargetType value) {
        return switch (value) {
            case FILESYSTEM -> 1;
            case LDAP -> 2;
            case HTTP -> 3;
            case OBJECT_STORE -> 4;
            case CUSTOM -> 5;
        };
    }

    private static PublicationTargetType targetType(int code) throws IOException {
        return switch (code) {
            case 1 -> PublicationTargetType.FILESYSTEM;
            case 2 -> PublicationTargetType.LDAP;
            case 3 -> PublicationTargetType.HTTP;
            case 4 -> PublicationTargetType.OBJECT_STORE;
            case 5 -> PublicationTargetType.CUSTOM;
            default -> throw malformed();
        };
    }

    private static int statusCode(PublicationStatus value) {
        return switch (value) {
            case PENDING -> 1;
            case DISPATCH_PREPARED -> 2;
            case SUCCEEDED -> 3;
            case RETRYABLE_FAILURE -> 4;
            case TERMINAL_FAILURE -> 5;
            case OUTCOME_UNKNOWN -> 6;
        };
    }

    private static PublicationStatus status(int code) throws IOException {
        return switch (code) {
            case 1 -> PublicationStatus.PENDING;
            case 2 -> PublicationStatus.DISPATCH_PREPARED;
            case 3 -> PublicationStatus.SUCCEEDED;
            case 4 -> PublicationStatus.RETRYABLE_FAILURE;
            case 5 -> PublicationStatus.TERMINAL_FAILURE;
            case 6 -> PublicationStatus.OUTCOME_UNKNOWN;
            default -> throw malformed();
        };
    }

    private static int failureCode(PublicationFailure value) {
        return switch (value) {
            case EXTERNAL_RETRYABLE -> 1;
            case EXTERNAL_TERMINAL -> 2;
            case EXTERNAL_OUTCOME_UNKNOWN -> 3;
            case CONTENT_INVALID -> 4;
            case RESULT_PERSISTENCE_UNKNOWN -> 5;
        };
    }

    private static Optional<PublicationFailure> optionalFailure(int code) throws IOException {
        return switch (code) {
            case 0 -> Optional.empty();
            case 1 -> Optional.of(PublicationFailure.EXTERNAL_RETRYABLE);
            case 2 -> Optional.of(PublicationFailure.EXTERNAL_TERMINAL);
            case 3 -> Optional.of(PublicationFailure.EXTERNAL_OUTCOME_UNKNOWN);
            case 4 -> Optional.of(PublicationFailure.CONTENT_INVALID);
            case 5 -> Optional.of(PublicationFailure.RESULT_PERSISTENCE_UNKNOWN);
            default -> throw malformed();
        };
    }

    private static int evidenceCode(PublicationEvidence value) {
        return switch (value) {
            case DIRECT_RESPONSE -> 1;
            case RECONCILIATION_RESPONSE -> 2;
        };
    }

    private static Optional<PublicationEvidence> optionalEvidence(int code) throws IOException {
        return switch (code) {
            case 0 -> Optional.empty();
            case 1 -> Optional.of(PublicationEvidence.DIRECT_RESPONSE);
            case 2 -> Optional.of(PublicationEvidence.RECONCILIATION_RESPONSE);
            default -> throw malformed();
        };
    }

    private static int encodingCode(Encoding value) {
        return switch (value) {
            case DER -> 1;
            case PEM -> 2;
            case BINARY -> 3;
        };
    }

    private static Encoding encoding(int code) throws IOException {
        return switch (code) {
            case 1 -> Encoding.DER;
            case 2 -> Encoding.PEM;
            case 3 -> Encoding.BINARY;
            default -> throw malformed();
        };
    }

    private static int lifecycleCode(DurableContentReference.Lifecycle value) {
        return switch (value) {
            case OPERATION -> 1;
            case PERSISTED -> 2;
            case TEMPORARY -> 3;
        };
    }

    private static DurableContentReference.Lifecycle lifecycle(int code) throws IOException {
        return switch (code) {
            case 1 -> DurableContentReference.Lifecycle.OPERATION;
            case 2 -> DurableContentReference.Lifecycle.PERSISTED;
            case 3 -> DurableContentReference.Lifecycle.TEMPORARY;
            default -> throw malformed();
        };
    }

    private static IOException malformed() {
        return new IOException("Publication record metadata is malformed");
    }
}
