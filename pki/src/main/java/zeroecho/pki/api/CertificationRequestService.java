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

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.RequestQuery;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.request.X509EnrollmentPayload;

/**
 * Processes certification requests (CSR-like objects) into a normalized
 * representation.
 *
 * <p>
 * This service provides request fingerprinting, parsing, proof-of-possession
 * verification, and optional persistence for correlation and auditing. Request
 * transport protocols such as ACME are expected to use this service as the core
 * processing layer.
 * </p>
 */
public interface CertificationRequestService {

    /**
     * Computes a stable identifier (fingerprint) for the given request payload.
     *
     * @param request certification request
     * @return stable request identifier
     * @throws IllegalArgumentException if {@code request} is null
     * @throws PkiException             if fingerprinting fails
     */
    PkiId fingerprint(CertificationRequest request);

    /**
     * Parses and normalizes a certification request.
     *
     * @param request certification request
     * @return parsed request
     * @throws IllegalArgumentException if {@code request} is null
     * @throws PkiException             if parsing fails (invalid request,
     *                                  unsupported format, backend failure)
     */
    ParsedCertificationRequest parse(CertificationRequest request);

    /**
     * Parses an explicitly typed X.509 PKCS#10 or CRMF enrollment payload.
     * @param request immutable bounded original payload
     * @return normalized request retaining the exact original syntax and bytes
     * @throws RuntimeException if parsing fails or the active framework does not support the syntax
     */
    ParsedCertificationRequest parseX509(X509EnrollmentPayload request);

    /**
     * Restores the exact typed X.509 enrollment payload from a stored parse result.
     * Requires one canonical byte attribute and the matching syntax-specific digest identity.
     * Performs no proof verification or authorization.
     * @param parsed parsed request retaining the original payload
     * @return immutable independently owned original payload
     * @throws IllegalArgumentException if syntax, attribute, size, or identity is invalid
     */
    X509EnrollmentPayload encodedX509Request(ParsedCertificationRequest parsed);

    /**
     * Requires an original X.509 request to describe the exact authoritative
     * renewal predecessor subject, ordered RDNs, SAN presence/entries and DER
     * public key. Re-parses the retained original payload and rejects fabricated
     * normalized fields. Resolves and validates bounded predecessor content and
     * leaf metadata from this service's store. This equality check grants no
     * authentication, proof verification, approval or predecessor status validity;
     * correlated renewal independently performs those applicable domain checks.
     * @param parsed request retaining its exact original typed payload
     * @param predecessorId exact stored end-entity credential identity
     * @throws IllegalArgumentException if either input or its identity is inconsistent
     * @throws PkiException if the predecessor is missing or content cannot be validated
     */
    void requireRenewalIdentity(ParsedCertificationRequest parsed, PkiId predecessorId);

    /**
     * Verifies the exact retained original proof and its CSR-signature binding
     * against an immutable imported profile version. Re-extracts and reparses the
     * original typed payload; caller-supplied normalized fields confer no trust.
     * Uses this session's configured algorithm authority and binding registry.
     * Performs no writes, serial allocation, signing preparation or authorization;
     * subject, issuer, validity and other issuance policies remain separate checks.
     * @param parsed request retaining the exact original typed payload
     * @param profile exact imported profile identity, version and commitment
     * @throws RuntimeException if the profile, proof, binding or configured verifier is unavailable or invalid
     */
    void requireProfileProof(ParsedCertificationRequest parsed, zeroecho.pki.api.profile.CertificateProfileRef profile);

    /**
     * Restores the exact bounded X.509 CSR DER snapshot retained in a parsed request.
     * Requires one byte-valued CSR attribute, between one byte and one MiB, and
     * the exact {@code csr:} SHA-256 identity of the returned snapshot. The snapshot
     * is captured before hashing, so subsequent attribute mutations cannot change it.
     * This performs no parsing, proof verification, persistence or admission and
     * does not make the parsed request an authorization credential.
     * @param parsed parsed request containing its original CSR bytes
     * @return independently owned DER request with the same X.509 format
     * @throws IllegalArgumentException if the input, format, attribute or identity is invalid,
     *         or the request carries CRMF; use {@link #encodedX509Request} for typed recovery
     * @throws PkiException if SHA-256 is unavailable
     */
    CertificationRequest encodedRequest(ParsedCertificationRequest parsed);


    /**
     * Verifies proof-of-possession (PoP) for the private key corresponding to the
     * requested public key.
     *
     * <p>
     * This operation is diagnostic and may be used by request-processing workflows
     * before issuance. A successful result does not grant issuance authority:
     * {@link IssuanceService#issueEndEntity} independently reparses the original
     * request payload and requires proof of possession immediately before invoking
     * a privileged issuer backend.
     * </p>
     *
     * @param parsed parsed request
     * @param policy verification policy
     * @return PoP verification result
     * @throws IllegalArgumentException if inputs are null
     * @throws PkiException             if verification fails due to backend failure
     */
    ProofOfPossessionResult verifyProofOfPossession(ParsedCertificationRequest parsed, VerificationPolicy policy);

    /**
     * Stores a parsed request for later correlation and audit.
     *
     * @param parsed parsed request
     * @param policy storage policy
     * @return stored request id
     * @throws IllegalArgumentException if inputs are null
     * @throws PkiException             if persistence fails
     */
    PkiId store(ParsedCertificationRequest parsed, RequestStorePolicy policy);

    /**
     * Retrieves a stored request.
     *
     * @param requestId request id
     * @return parsed request if present
     * @throws IllegalArgumentException if {@code requestId} is null
     * @throws PkiException             if retrieval fails
     */
    Optional<ParsedCertificationRequest> get(PkiId requestId);

    /**
     * Searches stored requests.
     *
     * @param query request query
     * @return matching requests
     * @throws IllegalArgumentException if {@code query} is null
     * @throws PkiException             if searching fails
     */
    List<ParsedCertificationRequest> search(RequestQuery query);
}
