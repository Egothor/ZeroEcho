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
package zeroecho.pki.spi.store;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;

/**
 * Domain-owned durable continuation paired with one signing operation.
 *
 * <p>The continuation is stored in the segmented metadata ledger under the
 * same private {@link PkiId} as the signing record. It contains only immutable,
 * bounded command data and durable content references; it never contains a
 * framework builder, callback, thread, lease, or resident workflow handle.</p>
 */
public interface DomainContinuationStore {

    /** Domain operation reconstructed after signing completes. */
    enum Kind {
        /** Root or intermediate CA command. */
        CA,
        /** End-entity or intermediate credential issuance. */
        ISSUANCE,
        /** CRL or another persisted status object. */
        STATUS
    }

    /** Durable outer lifecycle. */
    enum State {
        /** Exact command and signing input are durably linked to live signing. */
        SIGNING,
        /** Signature is terminal and publication is being reconciled. */
        PUBLISHING,
        /** Domain result was published and committed exactly once. */
        COMPLETED,
        /** Terminal signing or frozen-postcondition failure. */
        FAILED,
        /** Original signing deadline elapsed before trustworthy completion. */
        EXPIRED
    }

    /**
     * Complete versioned durable outer continuation.
     *
     * @param operationId same private identifier as the signing record
     * @param version clean current payload version
     * @param kind owning domain
     * @param correlationId optional domain idempotency identity for O(1) restart lookup
     * @param state lifecycle state
     * @param revision monotonic CAS revision
     * @param createdAt operation creation time
     * @param deadline original absolute signing deadline
     * @param command exact bounded versioned domain command
     * @param commandCommitment immutable canonical command commitment
     * @param signingContent exact durable to-be-signed content while publication is live
     * @param result optional exact bounded domain result or publication identity
     * @param detailCode optional safe terminal detail
     */
    record Record(PkiId operationId, int version, Kind kind, Optional<String> correlationId,
            State state, long revision,
            Instant createdAt, Instant deadline, EncodedObject command, String commandCommitment,
            Optional<DurableContentReference> signingContent, Optional<EncodedObject> result,
            Optional<String> detailCode) {
        /** Validates and snapshots one continuation. */
        public Record {
            Objects.requireNonNull(operationId, "operationId");
            Objects.requireNonNull(kind, "kind");
            correlationId = Objects.requireNonNull(correlationId, "correlationId");
            correlationId.ifPresent(value -> {
                if (!value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
                    throw new IllegalArgumentException("Domain correlation identity is invalid");
                }
            });
            Objects.requireNonNull(state, "state");
            Objects.requireNonNull(createdAt, "createdAt");
            Objects.requireNonNull(deadline, "deadline");
            EncodedObject exactCommand = Objects.requireNonNull(command, "command");
            command = new EncodedObject(exactCommand.encoding(), exactCommand.bytes());
            signingContent = Objects.requireNonNull(signingContent, "signingContent");
            result = Objects.requireNonNull(result, "result").map(value ->
                    new EncodedObject(value.encoding(), value.bytes()));
            detailCode = Objects.requireNonNull(detailCode, "detailCode");
            if (version != 2 || revision < 0L || deadline.isBefore(createdAt)
                    || commandCommitment == null || !commandCommitment.matches("domain:v1:[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Domain continuation metadata is invalid");
            }
            if (command.encoding() != zeroecho.pki.api.Encoding.BINARY
                    || command.bytes().length == 0 || command.bytes().length > 1_048_576
                    || result.map(value -> value.bytes().length == 0
                            || value.bytes().length > 1_048_576).orElse(false)
                    || detailCode.filter(value -> !value.matches("[A-Z][A-Z0-9_]{0,127}")).isPresent()) {
                throw new IllegalArgumentException("Domain continuation bounded data is invalid");
            }
            boolean lifecycleValid = switch (state) {
                case SIGNING, PUBLISHING -> signingContent.isPresent()
                        && result.isEmpty() && detailCode.isEmpty();
                case COMPLETED -> signingContent.isEmpty()
                        && result.isPresent() && detailCode.filter("COMPLETED"::equals).isPresent();
                case FAILED -> signingContent.isEmpty() && result.isEmpty() && detailCode.isPresent();
                case EXPIRED -> signingContent.isEmpty()
                        && result.isEmpty() && detailCode.filter("EXPIRED"::equals).isPresent();
            };
            if (!lifecycleValid) {
                throw new IllegalArgumentException("Domain continuation terminal data is inconsistent");
            }
        }

    }

    /**
     * Returns one continuation through its bounded domain idempotency identity.
     *
     * @param kind outer-operation kind
     * @param correlationId stable correlation identity
     * @return record, or empty
     */
    default Optional<Record> getDomainContinuation(Kind kind, String correlationId) {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(correlationId, "correlationId");
        return Optional.empty();
    }

    /**
     * Returns one authoritative continuation by the shared operation id.
     *
     * @param operationId private durable identifier
     * @return record, or empty
     */
    default Optional<Record> getDomainContinuation(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return Optional.empty();
    }

    /**
     * Replaces one continuation using its exact revision as the fence.
     *
     * @param operationId private durable operation identifier
     * @param expectedRevision exact current revision
     * @param target legal next lifecycle state
     * @param result optional terminal result
     * @param detailCode optional stable non-sensitive detail code
     * @return committed replacement, or empty when the CAS lost
     */
    default Optional<Record> transitionDomainContinuation(PkiId operationId, long expectedRevision,
            State target, Optional<EncodedObject> result, Optional<String> detailCode) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(detailCode, "detailCode");
        throw new UnsupportedOperationException("Domain continuations are unsupported");
    }
}
