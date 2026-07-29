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
