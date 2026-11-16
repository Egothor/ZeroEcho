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

/**
 * Non-authoritative revocation-audit delivery cursor bound to one transition source.
 *
 * @param sourceStoreId stable identity of the authoritative transition source
 * @param lastPosition last projected transition position, or empty before first delivery
 * @param failureCount consecutive delivery failure count, from zero through 31
 * @param nextEligible retry instant, present exactly when the failure count is positive
 * @param observedHighRevision latest observed nonnegative source revision
 * @param observedHighCommitment lowercase SHA-256 of the observed source high watermark
 */
record RevocationAuditProjectionState(MetadataStoreId sourceStoreId,
        Optional<RevocationTransitionFeed.Position> lastPosition, int failureCount,
        Optional<Instant> nextEligible, long observedHighRevision, String observedHighCommitment) {

    /**
     * Stable control-record identity for the version-one revocation delivery cursor.
     */
    /* default */ static final String RECORD_ID = "revocation-v1";
    /**
     * Maximum consecutive delivery failure count before backoff counting saturates.
     */
    /* default */ static final int MAXIMUM_FAILURE_COUNT = 31;

    private static final int MAGIC = 0x5A455241;
    private static final int VERSION = 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 1_024;
    private static final int MAXIMUM_TEXT_BYTES = 256;

    /**
     * Validates the source-bound delivery cursor and retry/high-watermark invariants.
     *
     * @param sourceStoreId stable identity of the authoritative transition source
     * @param lastPosition last projected transition position, or empty before first delivery
     * @param failureCount consecutive delivery failure count, from zero through 31
     * @param nextEligible retry instant, present exactly when the failure count is positive
     * @param observedHighRevision latest observed nonnegative source revision
     * @param observedHighCommitment lowercase SHA-256 of the observed source high watermark
     * @throws NullPointerException if the source identity or optional container is null
     * @throws IllegalArgumentException if retry or high-watermark coordinates are invalid
     */
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

    /**
     * Decoded delivery state paired with its exact compare-and-set payload commitment.
     *
     * @param state validated revocation delivery cursor
     * @param recordCommitment lowercase SHA-256 of the retained cursor payload
     */
    /* default */
    record Loaded(RevocationAuditProjectionState state, String recordCommitment) {
        /**
         * Validates the decoded state and compare-and-set commitment.
         *
         * @param state decoded delivery cursor; must not be null
         * @param recordCommitment canonical lowercase payload SHA-256
         * @throws NullPointerException if state is null
         * @throws IllegalArgumentException if the commitment is invalid
         */
        Loaded {
            Objects.requireNonNull(state, "state");
            requireDigest(recordCommitment);
        }
    }

    /**
     * Loads and verifies the retained revocation-delivery cursor.
     *
     * @param control realm-owned durable control store
     * @return verified cursor and CAS commitment, or empty before initial persistence
     * @throws NullPointerException if control is null
     * @throws IllegalArgumentException if retained bytes, identity or commitment are invalid
     */
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

    /**
     * Persists a replacement cursor guarded by the exact previously observed commitment.
     *
     * @param control realm-owned durable control store
     * @param current previous loaded state, or empty for initial creation
     * @param next replacement delivery state
     * @return persisted replacement state and its CAS commitment
     * @throws NullPointerException if a required argument is null
     */
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

    /**
     * Creates an undelivered cursor bound to the observed authoritative source head.
     *
     * @param head authoritative transition-feed high watermark
     * @return source-bound cursor without a delivery position or retry delay
     */
    /* default */ static RevocationAuditProjectionState initial(RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(head.sourceStoreId(), Optional.empty(), 0, Optional.empty(),
                head.globalRevision(), head.transitionCommitment());
    }

    /**
     * Records a delivered transition position and clears failure/backoff state.
     *
     * @param position newly delivered transition position
     * @param head latest observed source high watermark
     * @return replacement cursor retaining this source identity
     */
    /* default */ RevocationAuditProjectionState advance(RevocationTransitionFeed.Position position,
            RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(sourceStoreId, Optional.of(position), 0, Optional.empty(),
                head.globalRevision(), head.transitionCommitment());
    }

    /**
     * Retains the delivery position while recording a failed attempt and retry instant.
     *
     * @param eligible absolute retry eligibility instant
     * @param head latest observed source high watermark
     * @return replacement cursor with a saturating increment of failure count
     */
    /* default */ RevocationAuditProjectionState fail(Instant eligible,
            RevocationTransitionFeed.HighWatermark head) {
        int nextFailureCount = Math.min(MAXIMUM_FAILURE_COUNT, failureCount + 1);
        return new RevocationAuditProjectionState(sourceStoreId, lastPosition, nextFailureCount,
                Optional.of(eligible), head.globalRevision(), head.transitionCommitment());
    }

    /**
     * Updates only the observed source high watermark.
     *
     * @param head latest authoritative source high watermark
     * @return replacement preserving delivery position and retry state
     */
    /* default */ RevocationAuditProjectionState observe(RevocationTransitionFeed.HighWatermark head) {
        return new RevocationAuditProjectionState(sourceStoreId, lastPosition, failureCount, nextEligible,
                head.globalRevision(), head.transitionCommitment());
    }

    /**
     * Encodes bounded canonical version-one delivery state.
     *
     * @param state validated source-bound delivery cursor
     * @return newly allocated canonical binary payload
     * @throws IllegalArgumentException if a text field or the payload exceeds its byte bound
     * @throws NullPointerException if state is null
     * @throws IllegalStateException if in-memory state encoding unexpectedly fails
     */
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

    /**
     * Decodes a complete bounded payload and requires byte-for-byte canonical re-encoding.
     *
     * @param payload retained binary cursor bytes; copied
     * @return validated canonical delivery state
     * @throws NullPointerException if payload is null
     * @throws IllegalArgumentException if bytes are empty, oversized, malformed, noncanonical or unsupported
     */
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
