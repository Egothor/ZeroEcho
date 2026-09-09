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
 * Closed set of stable, non-sensitive PKI failure codes.
 *
 * <p>
 * Each code has exactly one protocol-independent classification. New codes are
 * added only when a repository contract defines their meaning; callers cannot
 * introduce arbitrary text as a failure code. Lookup and classification require
 * constant time and auxiliary memory.
 * </p>
 */
public enum PkiFailureCode {

    /** Generic invalid-input failure. */
    VALIDATION_FAILURE(PkiFailureClassification.VALIDATION_FAILURE),

    /** Generic failure to establish the caller's identity. */
    AUTHENTICATION_FAILURE(PkiFailureClassification.AUTHENTICATION_FAILURE),

    /** Generic denial of an operation to an authenticated caller. */
    AUTHORIZATION_DENIED(PkiFailureClassification.AUTHORIZATION_DENIED),

    /** Generic rejection by an applicable PKI policy. */
    POLICY_REJECTION(PkiFailureClassification.POLICY_REJECTION),

    /** Generic absence of a requested authoritative object. */
    NOT_FOUND(PkiFailureClassification.NOT_FOUND),

    /** Generic conflict with authoritative state. */
    CONFLICT(PkiFailureClassification.CONFLICT),

    /** Authoritative recovery is required before processing may continue. */
    RECOVERY_REQUIRED(PkiFailureClassification.RECOVERY_REQUIRED),

    /** An external operation has no safely established authoritative outcome. */
    EXTERNAL_OUTCOME_UNKNOWN(PkiFailureClassification.EXTERNAL_OUTCOME_UNKNOWN),

    /** Generic failure of a required finite or system resource. */
    RESOURCE_FAILURE(PkiFailureClassification.RESOURCE_FAILURE),

    /** Generic cooperative cancellation outcome. */
    CANCELLED(PkiFailureClassification.CANCELLED),

    /** Generic failure to establish success before the operation deadline. */
    DEADLINE_EXCEEDED(PkiFailureClassification.DEADLINE_EXCEEDED),

    /** Generic temporary admission or processing-capacity exhaustion. */
    OVERLOADED(PkiFailureClassification.OVERLOADED),

    /** Generic internal implementation failure. */
    INTERNAL_FAILURE(PkiFailureClassification.INTERNAL_FAILURE),

    /**
     * The selected operation requires a capability absent from the active
     * configuration. This is a validation failure because the requested operation
     * is not executable under that configuration.
     */
    CAPABILITY_NOT_CONFIGURED(PkiFailureClassification.VALIDATION_FAILURE);

    private final PkiFailureClassification classification;

    PkiFailureCode(PkiFailureClassification classification) {
        this.classification = Objects.requireNonNull(classification, "classification");
    }

    /**
     * Returns the only classification valid for this code.
     *
     * @return protocol-independent failure classification
     */
    public PkiFailureClassification classification() {
        return classification;
    }
}
