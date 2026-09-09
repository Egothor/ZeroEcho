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
package zeroecho.pki.api;

import java.util.Objects;

/**
 * Closed set of stable, typed machine reason codes for internal PKI operation
 * failures.
 *
 * <p>
 * A reason is attached structurally to a {@link PkiException} through
 * {@link PkiException#failureReason()} so that application logic and trust
 * boundaries classify a failure from this typed value rather than by parsing the
 * human-readable exception message. Each reason has exactly one
 * protocol-independent {@link PkiFailureClassification}; lookup and classification
 * require constant time and auxiliary memory. New reasons are added only when a
 * repository contract defines their meaning, so a failure code can never be
 * arbitrary text.
 * </p>
 *
 * <p>
 * Security note: a reason that is not {@linkplain #externalSafe() external-safe}
 * describes internal authoritative state and must never be surfaced verbatim to
 * an external client. A trust boundary exposes only the coarse
 * {@link #classification() classification} (or a classification-derived external
 * {@link PkiFailureCode}) for such a reason, never the reason token itself.
 * </p>
 */
// Enum names are stable wire and diagnostic identifiers exposed by the PKI API.
@SuppressWarnings("PMD.LongVariable")
public enum PkiFailureReason {

    /**
     * A store mutation's durable outcome is unknown, so authoritative recovery
     * must complete before processing continues. This describes internal storage
     * state and is therefore not external-safe.
     */
    STORE_DURABILITY_UNCONFIRMED(PkiFailureClassification.RECOVERY_REQUIRED, false),

    /** The credential targeted by a revocation transition does not exist. */
    REVOCATION_CREDENTIAL_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** The credential is already permanently revoked, so no further transition applies. */
    REVOCATION_TERMINAL(PkiFailureClassification.POLICY_REJECTION, false),

    /** The requested revocation transition is not permitted from the current state. */
    REVOCATION_TRANSITION_ILLEGAL(PkiFailureClassification.POLICY_REJECTION, false),

    /** The revocation transition conflicts with a later committed transition. */
    REVOCATION_TRANSITION_CONFLICT(PkiFailureClassification.CONFLICT, false),

    /** A revocation append outcome is unknown, so authoritative recovery is required. */
    REVOCATION_RECOVERY_REQUIRED(PkiFailureClassification.RECOVERY_REQUIRED, false),

    /** The persisted revocation state is structurally invalid and requires recovery. */
    REVOCATION_STATE_CORRUPT(PkiFailureClassification.RECOVERY_REQUIRED, false),

    /** Persisting a revocation transition failed against the underlying storage. */
    REVOCATION_PERSIST_FAILED(PkiFailureClassification.RESOURCE_FAILURE, false),

    /** The authoritative signing time source was unavailable for the revocation. */
    REVOCATION_TIME_UNAVAILABLE(PkiFailureClassification.RESOURCE_FAILURE, false),

    /** A revocation failed for an unenumerated store reason; details are withheld. */
    REVOCATION_STATE_UPDATE_FAILED(PkiFailureClassification.RESOURCE_FAILURE, false),

    /** A pending-confirmation revocation cleanup outcome is unknown and requires recovery. */
    CONFIRMATION_REVOCATION_RECOVERY_REQUIRED(PkiFailureClassification.RECOVERY_REQUIRED, false),

    /** The pending confirmation is not in a revocable state. */
    CONFIRMATION_REVOCATION_CONFLICT(PkiFailureClassification.CONFLICT, false),

    /** A publication attempt counter overflowed and cannot be advanced. */
    PUBLICATION_ATTEMPT_EXHAUSTED(PkiFailureClassification.RESOURCE_FAILURE, false),

    /** A publication record changed concurrently and the transition no longer applies. */
    PUBLICATION_CONCURRENT_MODIFICATION(PkiFailureClassification.CONFLICT, false),

    /** A publication result outcome is unknown, so authoritative recovery is required. */
    PUBLICATION_RESULT_UNCONFIRMED(PkiFailureClassification.EXTERNAL_OUTCOME_UNKNOWN, false),

    /** The content submitted for publication is invalid. */
    PUBLICATION_CONTENT_INVALID(PkiFailureClassification.VALIDATION_FAILURE, false),

    /** The referenced publication operation does not exist. */
    PUBLICATION_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A publication operation requires authoritative recovery before continuing. */
    PUBLICATION_RECOVERY_FAILED(PkiFailureClassification.RECOVERY_REQUIRED, false),

    /** A referenced issuing authority (CA) does not exist. */
    ISSUER_CA_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A referenced issuing authority (CA) exists but is not in an active state. */
    ISSUER_CA_NOT_ACTIVE(PkiFailureClassification.POLICY_REJECTION, false),

    /** A referenced issuer generation does not exist. */
    ISSUER_GENERATION_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A referenced issuer chain path does not exist. */
    ISSUER_CHAIN_PATH_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A referenced issuer credential does not exist. */
    ISSUER_CREDENTIAL_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A referenced end-entity credential does not exist. */
    CREDENTIAL_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false),

    /** A referenced status-generation target does not exist. */
    STATUS_TARGET_NOT_FOUND(PkiFailureClassification.NOT_FOUND, false);

    private final PkiFailureClassification classification;
    private final boolean externalSafe;

    PkiFailureReason(PkiFailureClassification classification, boolean externalSafe) {
        this.classification = Objects.requireNonNull(classification, "classification");
        this.externalSafe = externalSafe;
    }

    /**
     * Returns the only classification valid for this reason.
     *
     * @return protocol-independent failure classification
     */
    public PkiFailureClassification classification() {
        return classification;
    }

    /**
     * Returns whether this reason code may itself be exposed to an external client.
     *
     * @return {@code true} if the reason token is safe to surface externally;
     *         {@code false} if only its classification may cross the boundary
     */
    public boolean externalSafe() {
        return externalSafe;
    }
}
