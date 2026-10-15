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
package zeroecho.pki.server.enrollment;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.RealmId;

/**
 * Immutable CMP wire continuation, independent of signing acceptance. An unlinked
 * reservation contains no domain request reference and may survive a crash before
 * admission. Only the coordinator writes records or accounts for their capacity.
 * This value asserts no authentication or authorization.
 * @param id stable realm, endpoint and transaction identity
 * @param revision positive compare-and-set revision
 * @param frozen immutable authenticated original request coordinates
 * @param enrollmentId atomically attached enrollment, absent before admission or for non-issuance
 * @param response latest durably published response metadata
 */
public record CmpTransaction(String id, long revision, Frozen frozen, Optional<String> enrollmentId,
        Optional<Response> response) {
    /** Validates identity, state and allocation bounds without trusting persisted data. */
    public CmpTransaction {
        EnrollmentTransaction.id(id); Objects.requireNonNull(frozen, "frozen");
        Objects.requireNonNull(enrollmentId, "enrollmentId").ifPresent(EnrollmentTransaction::id);
        Objects.requireNonNull(response, "response");
        if (revision < 1 || !id.equals(CmpTransactionCodec.id(frozen.realmId(), frozen.source().label(), frozen.transactionSha256()))
                || enrollmentId.isPresent() && !frozen.enrollment()
                || response.filter(value -> value.length() > frozen.maximumResponseBytes()
                        || value.confirmation() != Confirmation.NONE && enrollmentId.isEmpty()).isPresent()) {
            throw invalid();
        }
    }

    /** Durable protocol confirmation, independent of domain credential confirmation. */
    public enum Confirmation {
        /** No certificate confirmation is outstanding. */ NONE,
        /** The returned certificate awaits authenticated certConf. */ AWAITING,
        /** Explicit or requested implicit confirmation accepted the certificate. */ ACCEPTED,
        /** The authenticated requester rejected the certificate. */ REJECTED,
        /** The explicit confirmation deadline elapsed. */ EXPIRED
    }

    /**
     * Authenticated immutable reservation. Hashes commit to exact wire and CRMF
     * bytes; no CSR, shared secret or private key is stored here.
     * @param realmId owning realm
     * @param source exact endpoint and credential selection
     * @param requester authenticated original actor and frozen alias exclusions
     * @param authorityId logical authority
     * @param profile exact frozen certificate profile version and commitment
     * @param issuerId selected issuer generation
     * @param pathId selected issuer path
     * @param pathCommitment exact path commitment
     * @param transactionSha256 transaction identifier commitment
     * @param originalWireSha256 exact authenticated original message commitment
     * @param originalType original ir, cr, kur, rr or genm body tag
     * @param requestId original nonnegative certificate request identifier
     * @param requestSha256 exact original CRMF digest for issuance, otherwise absent
     * @param implicitConfirmation whether the original protected request asked for implicit confirmation
     * @param createdAt reservation time
     * @param expiresAt latest unclaimed admission time
     * @param maximumResponseBytes conservative complete protected-response bound, reserved before side effects
     */
    public record Frozen(RealmId realmId, EnrollmentTransaction.Source source, EnrollmentTransaction.Requester requester,
            PkiId authorityId, CertificateProfileRef profile, PkiId issuerId, PkiId pathId, String pathCommitment, String transactionSha256,
            String originalWireSha256, int originalType, BigInteger requestId, Optional<String> requestSha256,
            boolean implicitConfirmation, Instant createdAt, Instant expiresAt, int maximumResponseBytes) {
        /** Rejects mechanism, authority, request and response-capacity inconsistencies. */
        public Frozen {
            Objects.requireNonNull(realmId, "realmId"); Objects.requireNonNull(source, "source");
            Objects.requireNonNull(requester, "requester"); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profile, "profile"); EnrollmentTransaction.id(profile.profileId());
            Objects.requireNonNull(issuerId, "issuerId"); Objects.requireNonNull(pathId, "pathId");
            EnrollmentTransaction.id(authorityId.value()); EnrollmentTransaction.id(issuerId.value()); EnrollmentTransaction.id(pathId.value());
            EnrollmentTransaction.digest(pathCommitment); EnrollmentTransaction.digest(transactionSha256);
            EnrollmentTransaction.digest(originalWireSha256); Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(requestSha256, "requestSha256").ifPresent(EnrollmentTransaction::digest);
            Objects.requireNonNull(createdAt, "createdAt"); Objects.requireNonNull(expiresAt, "expiresAt");
            boolean enrollment = originalType == 0 || originalType == 2 || originalType == 7;
            if (source.protocol() != EnrollmentTransaction.Protocol.CMP || !realmId.equals(requester.aliases().realmId())
                    || requester.type() != IssuanceExecutionEvidence.ActorType.CMP_SIGNER
                        && requester.type() != IssuanceExecutionEvidence.ActorType.CMP_PBM
                    || !enrollment && originalType != 11 && originalType != 21
                    || !enrollment && (implicitConfirmation || requestId.signum() != 0)
                    || enrollment != requestSha256.isPresent() || requestId.signum() < 0 || requestId.bitLength() > 64
                    || (originalType == 7 || originalType == 11) && requester.type() != IssuanceExecutionEvidence.ActorType.CMP_SIGNER
                    || !expiresAt.isAfter(createdAt) || maximumResponseBytes < 1
                    || maximumResponseBytes > CmpTransactionCodec.SLOT_BYTES * CmpTransactionCodec.MAXIMUM_SLOTS) {
                throw invalid();
            }
        }
        /** {@return whether the transaction requires an attached issuance workflow} */
        public boolean enrollment() { return originalType == 0 || originalType == 2 || originalType == 7; }
        /** {@return a redacted description} */
        @Override public String toString() { return "CmpTransaction.Frozen[redacted]"; }
    }

    /**
     * Metadata committed atomically with every fixed response slot.
     * @param requestSha256 exact authenticated triggering wire request
     * @param responseSha256 exact complete protected response
     * @param length complete response length in bytes
     * @param senderNonce lowercase hexadecimal response nonce, 16 to 32 bytes
     * @param recipientNonce lowercase hexadecimal triggering request nonce, 16 to 32 bytes
     * @param confirmationDeadline explicit certificate confirmation deadline, if awaiting confirmation
     * @param confirmation durable protocol confirmation status and final verdict
     * @param terminal whether further state changes are forbidden
     */
    public record Response(String requestSha256, String responseSha256, int length, String senderNonce,
            String recipientNonce, Optional<Instant> confirmationDeadline, Confirmation confirmation, boolean terminal) {
        /** Validates bounded metadata without exposing wire bytes in diagnostics. */
        public Response {
            EnrollmentTransaction.digest(requestSha256); EnrollmentTransaction.digest(responseSha256);
            nonce(senderNonce); nonce(recipientNonce); Objects.requireNonNull(confirmationDeadline, "confirmationDeadline");
            Objects.requireNonNull(confirmation, "confirmation");
            if (length < 1 || confirmation == Confirmation.AWAITING != confirmationDeadline.isPresent()
                    || terminal && confirmation == Confirmation.AWAITING
                    || confirmation != Confirmation.NONE && confirmation != Confirmation.AWAITING && !terminal) {
                throw invalid();
            }
        }
        /** {@return a redacted description} */
        @Override public String toString() { return "CmpTransaction.Response[redacted]"; }
    }

    /** {@return the complete versioned manifest commitment} */
    public String commitment() { return EnrollmentTransactionCodec.sha256(CmpTransactionCodec.encode(this)); }
    /** {@return a redacted description} */
    @Override public String toString() { return "CmpTransaction[redacted]"; }

    private static void nonce(String value) {
        Objects.requireNonNull(value, "nonce");
        if (value.length() < 32 || value.length() > 64 || value.length() % 2 != 0) {
            throw invalid();
        }
        for (int index = 0; index < value.length(); index++) {
            char c = value.charAt(index);
            if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) {
                throw invalid();
            }
        }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("CMP continuation is invalid"); }
}
