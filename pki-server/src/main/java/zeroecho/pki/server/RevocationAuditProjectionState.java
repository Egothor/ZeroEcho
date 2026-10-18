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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

/** Strict non-authoritative delivery state for one revocation-audit projection. */
record RevocationAuditProjectionState(MetadataStoreId sourceStoreId,
        Optional<RevocationTransitionFeed.Position> lastPosition, int failureCount,
        Optional<Instant> nextEligible, long observedHighRevision, String observedHighCommitment) {

    /* default */ static final String RECORD_ID = "revocation-v1";
    /* default */ static final int MAXIMUM_FAILURE_COUNT = 31;

    private static final int MAGIC = 0x5A455241;
    private static final int VERSION = 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 1_024;
    private static final int MAXIMUM_TEXT_BYTES = 256;

    /** Validates one immutable state snapshot. */
    RevocationAuditProjectionState {
        Objects.requireNonNull(sourceStoreId, "sourceStoreId");
        lastPosition = Objects.requireNonNull(lastPosition, "lastPosition");
        nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
        if (failureCount < 0 || failureCount > MAXIMUM_FAILURE_COUNT
                || failureCount == 0 != nextEligible.isEmpty()) {
            throw new IllegalArgumentException("Revocation audit projection failure state is invalid");
        }
        if (observedHighRevision < 0L || observedHighCommitment == null
                || !observedHighCommitment.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Revocation audit projection watermark is invalid");
        }
    }

    /** One decoded state paired with its control-record CAS commitment. */
    /* default */
    record Loaded(RevocationAuditProjectionState state, String recordCommitment) {
        /** Validates the loaded state identity. */
        Loaded {
            Objects.requireNonNull(state, "state");
            requireDigest(recordCommitment);
        }
    }

    /* default */ static Optional<Loaded> load(ServerControlStore control) {
        Objects.requireNonNull(control, "control");
        return control.protocolRecord(ServerControlStore.REVOCATION_AUDIT_PROJECTION, RECORD_ID)
                .map(record -> {
                    byte[] payload = record.payload();
                    String calculated = digest(payload);
                    if (!RECORD_ID.equals(record.recordId()) || !calculated.equals(record.commitment())) {
                        throw invalidState();
                    }
                    return new Loaded(decode(payload), record.commitment());
                });
    }

    /* default */ static Loaded persist(ServerControlStore control, Optional<Loaded> current,
            RevocationAuditProjectionState next) {
        Objects.requireNonNull(control, "control");
        Optional<Loaded> prior = Objects.requireNonNull(current, "current");
        byte[] payload = encode(Objects.requireNonNull(next, "next"));
        String commitment = digest(payload);
        ServerControlStore.ProtocolRecord record = new ServerControlStore.ProtocolRecord(
                ServerControlStore.REVOCATION_AUDIT_PROJECTION, RECORD_ID, commitment, payload);
        Optional<String> expected = prior.map(Loaded::recordCommitment);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record, expected)));
        return new Loaded(next, commitment);
    }

    /* default */ static RevocationAuditProjectionState initial(RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(head.sourceStoreId(), Optional.empty(), 0, Optional.empty(),
                head.globalRevision(), head.transitionCommitment());
    }

    /* default */ RevocationAuditProjectionState advance(RevocationTransitionFeed.Position position,
            RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(sourceStoreId, Optional.of(position), 0, Optional.empty(),
                head.globalRevision(), head.transitionCommitment());
    }

    /* default */ RevocationAuditProjectionState fail(Instant eligible,
            RevocationTransitionFeed.HighWatermark head) {
        int nextFailureCount = Math.min(MAXIMUM_FAILURE_COUNT, failureCount + 1);
        return new RevocationAuditProjectionState(sourceStoreId, lastPosition, nextFailureCount,
                Optional.of(eligible), head.globalRevision(), head.transitionCommitment());
    }

    /* default */ RevocationAuditProjectionState observe(RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(sourceStoreId, lastPosition, failureCount, nextEligible,
                head.globalRevision(), head.transitionCommitment());
    }

    /* default */ static byte[] encode(RevocationAuditProjectionState state) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(MAXIMUM_PAYLOAD_BYTES);
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                writeText(output, state.sourceStoreId().value());
                output.writeBoolean(state.lastPosition().isPresent());
                if (state.lastPosition().isPresent()) {
                    writeText(output, state.lastPosition().orElseThrow().value());
                }
                output.writeInt(state.failureCount());
                output.writeBoolean(state.nextEligible().isPresent());
                if (state.nextEligible().isPresent()) {
                    Instant eligible = state.nextEligible().orElseThrow();
                    output.writeLong(eligible.getEpochSecond());
                    output.writeInt(eligible.getNano());
                }
                output.writeLong(state.observedHighRevision());
                writeText(output, state.observedHighCommitment());
            }
            byte[] encoded = bytes.toByteArray();
            if (encoded.length > MAXIMUM_PAYLOAD_BYTES) {
                throw new IllegalArgumentException("Revocation audit projection state is too large");
            }
            return encoded;
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory revocation audit state encoding failed", impossible);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace") // persisted bytes are untrusted and causes are sanitized
    /* default */ static RevocationAuditProjectionState decode(byte[] payload) {
        byte[] source = Objects.requireNonNull(payload, "payload").clone();
        if (source.length == 0 || source.length > MAXIMUM_PAYLOAD_BYTES) {
            throw invalidState();
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(source))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw invalidState();
            }
            MetadataStoreId storeId = new MetadataStoreId(readText(input));
            Optional<RevocationTransitionFeed.Position> position = input.readBoolean()
                    ? Optional.of(new RevocationTransitionFeed.Position(readText(input))) : Optional.empty();
            int failures = input.readInt();
            Optional<Instant> eligible = input.readBoolean()
                    ? Optional.of(Instant.ofEpochSecond(input.readLong(), input.readInt())) : Optional.empty();
            long observedRevision = input.readLong();
            String observedCommitment = readText(input);
            RevocationAuditProjectionState decoded = new RevocationAuditProjectionState(storeId, position,
                    failures, eligible, observedRevision, observedCommitment);
            if (input.read() != -1 || !Arrays.equals(source, encode(decoded))) {
                throw invalidState();
            }
            return decoded;
        } catch (IOException | IllegalArgumentException | DateTimeException invalid) {
            throw invalidState();
        }
    }

    private static void writeText(DataOutputStream output, String value) throws IOException {
        byte[] encoded = Objects.requireNonNull(value, "value").getBytes(StandardCharsets.UTF_8);
        if (encoded.length == 0 || encoded.length > MAXIMUM_TEXT_BYTES) {
            throw new IllegalArgumentException("Revocation audit projection text is invalid");
        }
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    @SuppressWarnings("PMD.PreserveStackTrace") // malformed UTF-8 content must not escape through causes
    private static String readText(DataInputStream input) throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > MAXIMUM_TEXT_BYTES) {
            throw invalidState();
        }
        byte[] encoded = input.readNBytes(length);
        if (encoded.length != length) {
            throw invalidState();
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(encoded)).toString();
        } catch (CharacterCodingException invalid) {
            throw invalidState();
        }
    }

    private static String digest(byte[] payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Required SHA-256 digest is unavailable", impossible);
        }
    }

    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Revocation audit projection commitment is invalid");
        }
    }

    private static IllegalStateException invalidState() {
        return new IllegalStateException("Persisted revocation audit projection state is invalid");
    }
}
