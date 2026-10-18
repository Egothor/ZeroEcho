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

package zeroecho.pki.server.enrollment;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Durable server-keygen reservation and encrypted delivery lifecycle. The original
 * template is retained by the domain request store; no raw key or ciphertext is
 * embedded in this record. Descriptor count remains charged after terminal cleanup.
 * @param id stable replay-derived artifact identity
 * @param revision positive mutation revision
 * @param template exact original verified template and complete frozen policy
 * @param algorithm selected permitted key-generation algorithm
 * @param maximumKeySizeBits original endpoint generation bound
 * @param maximumCiphertextBytes reserved ciphertext capacity
 * @param maximumGeneratedRequestBytes reserved generated CSR capacity
 * @param deliveryDeadline fixed recipient-validity-capped delivery deadline
 * @param state authoritative generation/delivery phase
 * @param artifact exact attached ciphertext, absent until atomic enrollment attachment
 * @param bytesReleased true only after durable deletion permits releasing byte capacity
 */
public record EnrollmentKeygenArtifact(String id, long revision, EnrollmentTransaction.Intent template,
        String algorithm, int maximumKeySizeBits, long maximumCiphertextBytes, int maximumGeneratedRequestBytes,
        Instant deliveryDeadline, State state, Optional<EnrollmentTransaction.ArtifactBinding> artifact, boolean bytesReleased) {
    /** Durable phases distinguish an interrupted generation from an attached enrollment. */
    public enum State {
        /** Capacity and exact template are retained; no signing is authorized. */ GENERATING,
        /** Exact generated request, encrypted body and enrollment are atomically linked. */ ATTACHED,
        /** Attached delivery ended durably; original enrollment replay remains authoritative. */ EXPIRED,
        /** Unattached generation ended durably and will never be regenerated. */ FAILED
    }
    /** Validates the closed persistent grammar and all immutable linkage fields. */
    public EnrollmentKeygenArtifact {
        EnrollmentTransaction.digest(id);
        Objects.requireNonNull(template, "template"); Objects.requireNonNull(deliveryDeadline, "deliveryDeadline");
        Objects.requireNonNull(state, "state"); Objects.requireNonNull(artifact, "artifact");
        if (revision < 1 || template.operation() != EnrollmentTransaction.Operation.SERVER_KEYGEN || template.artifact().isPresent()
                || template.source().protocol() != EnrollmentTransaction.Protocol.EST
                || !("RSA".equals(algorithm) || "EC".equals(algorithm)) || maximumKeySizeBits < 256
                || maximumCiphertextBytes < 1 || maximumCiphertextBytes > 16_777_216
                || maximumGeneratedRequestBytes < 1 || maximumGeneratedRequestBytes > 1_048_576
                || !deliveryDeadline.isAfter(template.createdAt()) || template.expiresAt().isAfter(deliveryDeadline)
                || (state == State.ATTACHED || state == State.EXPIRED) != artifact.isPresent()
                || bytesReleased && state != State.EXPIRED && state != State.FAILED) {
            throw EnrollmentTransaction.invalid();
        }
        String expected = EnrollmentTransactionCodec.replayId(template.realmId(), template.source(), template.requester(),
                template.transactionId(), template.operation()).substring("enrollment:".length());
        if (!id.equals(expected)) {
            throw EnrollmentTransaction.invalid();
        }
        if (artifact.isPresent()) {
            EnrollmentTransaction.ArtifactBinding binding = artifact.orElseThrow();
            if (!binding.artifactId().equals(id) || binding.ciphertextBytes() > maximumCiphertextBytes
                    || !binding.generationCommitment().equals(EnrollmentKeygenCodec.generationCommitment(template, algorithm,
                            maximumKeySizeBits, maximumCiphertextBytes, maximumGeneratedRequestBytes, deliveryDeadline))) {
                throw EnrollmentTransaction.invalid();
            }
        }
    }
    /** {@return complete revision-sensitive record commitment} */
    public String commitment() { return EnrollmentKeygenCodec.record(this).commitment(); }
    /** {@return immutable reservation commitment included in the generated issuance intent} */
    public String generationCommitment() {
        return EnrollmentKeygenCodec.generationCommitment(template, algorithm, maximumKeySizeBits,
                maximumCiphertextBytes, maximumGeneratedRequestBytes, deliveryDeadline);
    }
    /** {@return exact linked enrollment identity, whether delivery remains available or expired} */
    public String enrollmentId() { return "enrollment:" + id; }
    /** @return redacted descriptor description */
    @Override public String toString() { return "EnrollmentKeygenArtifact[redacted]"; }
}
