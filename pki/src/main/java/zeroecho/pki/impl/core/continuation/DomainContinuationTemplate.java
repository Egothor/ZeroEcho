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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.spi.store.DomainContinuationStore;

/**
 * Immutable bounded domain input attached atomically to a signing intent.
 *
 * @param kind durable outer-operation kind
 * @param correlationId optional stable restart idempotency identity
 * @param command nonempty bounded encoded command, defensively copied
 * @param commandCommitment canonical versioned SHA-256 command commitment
 */
public record DomainContinuationTemplate(DomainContinuationStore.Kind kind,
        Optional<String> correlationId, EncodedObject command, String commandCommitment) {

    /** Validates and defensively snapshots the exact command. */
    public DomainContinuationTemplate {
        Objects.requireNonNull(kind, "kind");
        correlationId = Objects.requireNonNull(correlationId, "correlationId");
        correlationId.ifPresent(value -> {
            if (!value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
                throw new IllegalArgumentException("Domain correlation identity is invalid");
            }
        });
        EncodedObject exact = Objects.requireNonNull(command, "command");
        command = new EncodedObject(exact.encoding(), exact.bytes());
        if (command.bytes().length == 0 || command.bytes().length > 1_048_576
                || commandCommitment == null || !commandCommitment.equals(commitment(command))) {
            throw new IllegalArgumentException("Domain continuation command is invalid");
        }
    }

    /**
     * Creates a template with its canonical SHA-256 commitment.
     * @param kind durable outer-operation kind
     * @param command nonempty bounded encoded command
     * @return immutable uncorrelated template
     */
    public static DomainContinuationTemplate create(DomainContinuationStore.Kind kind,
            EncodedObject command) {
        return new DomainContinuationTemplate(kind, Optional.empty(), command, commitment(command));
    }

    /**
     * Creates a template with an O(1) restart correlation identity.
     * @param kind durable outer-operation kind
     * @param correlationId stable bounded idempotency identity
     * @param command nonempty bounded encoded command
     * @return immutable correlated template
     */
    public static DomainContinuationTemplate createCorrelated(DomainContinuationStore.Kind kind,
            String correlationId, EncodedObject command) {
        return new DomainContinuationTemplate(kind, Optional.of(correlationId), command, commitment(command));
    }

    /**
     * Returns the canonical versioned commitment for exact command bytes.
     * @param command exact encoded command
     * @return {@code domain:v1:} followed by lowercase SHA-256 hexadecimal
     */
    public static String commitment(EncodedObject command) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update((byte) command.encoding().ordinal());
            return "domain:v1:" + HexFormat.of().formatHex(digest.digest(command.bytes()));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
