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
package zeroecho.pki.api;

/**
 * Stable, protocol-independent classification of a PKI failure.
 *
 * <p>
 * A transport or protocol adapter translates these classifications into its own
 * externally defined error model. The classification does not itself prescribe
 * an HTTP status, ACME problem type, OCSP response status, or retry policy.
 * </p>
 */
public enum PkiFailureClassification {

    /** Caller-controlled input is malformed, incomplete, or otherwise invalid. */
    VALIDATION_FAILURE,

    /** The caller's identity or presented authentication evidence could not be established. */
    AUTHENTICATION_FAILURE,

    /** The authenticated caller is not authorized to perform the requested operation. */
    AUTHORIZATION_DENIED,

    /** Valid input was rejected by an applicable PKI policy. */
    POLICY_REJECTION,

    /** The requested PKI entity or operation does not exist in the authoritative state. */
    NOT_FOUND,

    /** The request conflicts with the current authoritative state or another committed operation. */
    CONFLICT,

    /** Processing cannot safely continue until authoritative state recovery is completed. */
    RECOVERY_REQUIRED,

    /** An external operation may have completed, but its authoritative outcome is not known. */
    EXTERNAL_OUTCOME_UNKNOWN,

    /** A required storage, memory, file, or other finite resource was unavailable. */
    RESOURCE_FAILURE,

    /** Processing was cancelled before a successful outcome was established. */
    CANCELLED,

    /** The operation did not establish a successful outcome before its deadline. */
    DEADLINE_EXCEEDED,

    /** The system temporarily lacks admission or processing capacity for the request. */
    OVERLOADED,

    /** An internal defect or otherwise unclassified internal failure prevented completion. */
    INTERNAL_FAILURE
}
