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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Strict non-authoritative delivery cursor for one family's success-evidence audit projection.
 *
 * <p>Generic over any {@link zeroecho.pki.spi.store.AuditEvidenceFeed}: it stores the last projected
 * append sequence and a bounded exponential-backoff failure state, persisted as a per-family
 * compare-and-replace protocol record in {@link ServerControlStore}. It is the sequence-cursor analogue
 * of {@code RevocationAuditProjectionState}, which remains unchanged.</p>
 *
 * @param lastSequence last durably projected sequence, {@code -1} before the first entry
 * @param failureCount consecutive failure count for backoff
 * @param nextEligible next eligible retry time, present exactly when {@code failureCount > 0}
 */
record AuditEvidenceProjectionState(long lastSequence, int failureCount, Optional<Instant> nextEligible) {

    /**
     * Maximum retained consecutive failure count before retry-backoff counting saturates.
     */
    /* default */ static final int MAXIMUM_FAILURE_COUNT = 31;

    private static final int MAGIC = 0x5A454150;
    private static final int VERSION = 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 256;

    /**
     * Validates one immutable cursor snapshot.
     * @param lastSequence last durably projected sequence, {@code -1} before the first entry
     * @param failureCount consecutive failure count for backoff
     * @param nextEligible next eligible retry time, present exactly when {@code failureCount > 0}
     * @throws NullPointerException if {@code nextEligible} is null
     * @throws IllegalArgumentException if the cursor or retry-count/eligibility invariant is invalid
     */
    /* default */ AuditEvidenceProjectionState {
        nextEligible = Objects.requireNonNull(nextEligible, "nextEligible");
        if (lastSequence < -1L || failureCount < 0 || failureCount > MAXIMUM_FAILURE_COUNT
                || failureCount == 0 != nextEligible.isEmpty()) {
            throw new IllegalArgumentException("Audit evidence projection state is invalid");
        }
    }

    /**
     * Decoded evidence-delivery cursor paired with its exact compare-and-set commitment.
     *
     * @param state validated non-authoritative delivery cursor
     * @param recordCommitment lowercase SHA-256 of the retained cursor payload
     */
    /* default */ record Loaded(AuditEvidenceProjectionState state, String recordCommitment) {
        /**
         * Validates the loaded cursor and compare-and-set commitment.
         *
         * @param state decoded delivery cursor; must not be null
         * @param recordCommitment canonical lowercase SHA-256 of the retained payload
         * @throws NullPointerException if state is null
         * @throws IllegalArgumentException if the commitment is invalid
         */
        /* default */ Loaded {
            Objects.requireNonNull(state, "state");
            requireDigest(recordCommitment);
        }
    }

    /**
     * Creates the cursor before any success evidence has been projected.
     *
     * @return sequence minus one with no failure or retry delay
     */
    /* default */ static AuditEvidenceProjectionState initial() {
        return new AuditEvidenceProjectionState(-1L, 0, Optional.empty());
    }

    /**
     * Loads and verifies the exact retained cursor for one evidence family.
     *
     * @param control realm-owned durable control store
     * @param recordId stable family cursor identity
     * @return verified cursor and CAS commitment, or empty before initial persistence
     * @throws NullPointerException if control or record identity is null
     * @throws IllegalArgumentException if retained payload, identity or commitment is invalid
     */
    /* default */ static Optional<Loaded> load(ServerControlStore control, String recordId) {
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(recordId, "recordId");
        return control.protocolRecord(ServerControlStore.AUDIT_EVIDENCE_PROJECTION, recordId)
                .map(record -> {
                    byte[] payload = record.payload();
                    if (!recordId.equals(record.recordId()) || !digest(payload).equals(record.commitment())) {
                        throw invalidState();
                    }
                    return new Loaded(decode(payload), record.commitment());
                });
    }

    /**
     * Publishes replacement cursor state guarded by the exact previous payload commitment.
     *
     * @param control realm-owned durable control store
     * @param recordId stable family cursor identity
     * @param current previously loaded cursor, or empty for initial creation
     * @param next replacement cursor state
     * @return replacement state paired with its persisted CAS commitment
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static Loaded persist(ServerControlStore control, String recordId, Optional<Loaded> current,
            AuditEvidenceProjectionState next) {
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(recordId, "recordId");
        Optional<Loaded> prior = Objects.requireNonNull(current, "current");
        byte[] payload = encode(Objects.requireNonNull(next, "next"));
        String commitment = digest(payload);
        ServerControlStore.ProtocolRecord record = new ServerControlStore.ProtocolRecord(
                ServerControlStore.AUDIT_EVIDENCE_PROJECTION, recordId, commitment, payload);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record,
                prior.map(Loaded::recordCommitment))));
        return new Loaded(next, commitment);
    }

    /**
     * Advances to a strictly later projected sequence and clears retry-backoff state.
     *
     * @param sequence newly projected sequence, strictly greater than the retained sequence
     * @return replacement cursor without failures or retry delay
     * @throws IllegalArgumentException if the sequence does not advance
     */
    /* default */ AuditEvidenceProjectionState advance(long sequence) {
        if (sequence <= lastSequence) {
            throw new IllegalArgumentException("Audit evidence projection cursor must advance");
        }
        return new AuditEvidenceProjectionState(sequence, 0, Optional.empty());
    }

    /**
     * Retains the delivery position while recording the next eligible retry time.
     *
     * @param eligible absolute retry eligibility instant
     * @return replacement cursor with a saturating increment of the failure count
     * @throws NullPointerException if the retry instant is null
     */
    /* default */ AuditEvidenceProjectionState fail(Instant eligible) {
        int nextFailureCount = Math.min(MAXIMUM_FAILURE_COUNT, failureCount + 1);
        return new AuditEvidenceProjectionState(lastSequence, nextFailureCount,
                Optional.of(Objects.requireNonNull(eligible, "eligible")));
    }

    private static byte[] encode(AuditEvidenceProjectionState state) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream(MAXIMUM_PAYLOAD_BYTES);
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(MAGIC);
                output.writeInt(VERSION);
                output.writeLong(state.lastSequence());
                output.writeInt(state.failureCount());
                output.writeBoolean(state.nextEligible().isPresent());
                if (state.nextEligible().isPresent()) {
                    Instant eligible = state.nextEligible().orElseThrow();
                    output.writeLong(eligible.getEpochSecond());
                    output.writeInt(eligible.getNano());
                }
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory audit evidence state encoding failed", impossible);
        }
    }

    @SuppressWarnings("PMD.PreserveStackTrace") // persisted bytes are untrusted and causes are sanitized
    private static AuditEvidenceProjectionState decode(byte[] payload) {
        byte[] source = Objects.requireNonNull(payload, "payload").clone();
        if (source.length == 0 || source.length > MAXIMUM_PAYLOAD_BYTES) {
            throw invalidState();
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(source))) {
            if (input.readInt() != MAGIC || input.readInt() != VERSION) {
                throw invalidState();
            }
            long lastSequence = input.readLong();
            int failures = input.readInt();
            Optional<Instant> eligible = input.readBoolean()
                    ? Optional.of(Instant.ofEpochSecond(input.readLong(), input.readInt())) : Optional.empty();
            AuditEvidenceProjectionState decoded =
                    new AuditEvidenceProjectionState(lastSequence, failures, eligible);
            if (input.read() != -1 || !Arrays.equals(source, encode(decoded))) {
                throw invalidState();
            }
            return decoded;
        } catch (IOException | IllegalArgumentException | DateTimeException invalid) {
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
            throw new IllegalArgumentException("Audit evidence projection commitment is invalid");
        }
    }

    private static IllegalStateException invalidState() {
        return new IllegalStateException("Persisted audit evidence projection state is invalid");
    }
}
