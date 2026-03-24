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
package zeroecho.pki.impl.core;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.RequestQuery;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link CertificationRequestService}.
 *
 * <p>
 * This service provides the standard runtime path for certification request
 * handling within the PKI core. It combines format-aware request processing
 * delegated to the configured {@link CredentialFramework} with optional
 * persistence performed through the configured {@link PkiStore}.
 * </p>
 *
 * <p>
 * The responsibilities of this class are intentionally narrow:
 * </p>
 * <ul>
 * <li>compute a deterministic request fingerprint from the encoded request
 * payload,</li>
 * <li>delegate parsing of the request to the active framework,</li>
 * <li>delegate proof-of-possession verification to the active framework,</li>
 * <li>persist parsed requests only when the selected {@link RequestStorePolicy}
 * requires it,</li>
 * <li>resolve previously stored requests by identifier.</li>
 * </ul>
 *
 * <p>
 * Request search is intentionally not implemented because the current
 * {@link PkiStore} SPI does not expose request enumeration or request search
 * capabilities.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not interpret request contents on its own beyond
 * fingerprinting the encoded payload.</li>
 * <li>Request parsing and proof-of-possession verification semantics depend on
 * the configured {@link CredentialFramework} implementation.</li>
 * <li>The fingerprint produced by this class is an identifier for PKI request
 * tracking and deduplication support; it does not by itself assert trust,
 * approval, or issuance eligibility.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless apart from its immutable collaborators. It is safe
 * for concurrent use provided that the supplied {@link PkiStore} and
 * {@link CredentialFramework} implementations are safe for the intended
 * concurrency model.
 * </p>
 */
public final class DefaultCertificationRequestService implements CertificationRequestService {

    private final PkiStore store;
    private final CredentialFramework framework;

    /**
     * Creates a certification request service bound to the supplied persistence and
     * framework collaborators.
     *
     * @param store     PKI store used for optional request persistence and lookup;
     *                  must not be {@code null}
     * @param framework credential framework that provides request parsing and
     *                  proof-of-possession verification services; must not be
     *                  {@code null}
     * @throws NullPointerException if {@code store} or {@code framework} is
     *                              {@code null}
     */
    public DefaultCertificationRequestService(PkiStore store, CredentialFramework framework) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
    }

    /**
     * Computes a deterministic identifier for the supplied certification request.
     *
     * <p>
     * The identifier is derived as the SHA-256 digest of the encoded request bytes
     * and returned as a {@link PkiId} with the {@code req:} prefix. The result is
     * stable for byte-identical request payloads.
     * </p>
     *
     * <p>
     * This operation does not validate the request structure, does not parse its
     * semantic content, and does not verify proof of possession.
     * </p>
     *
     * @param request certification request to fingerprint; must not be {@code null}
     * @return deterministic request identifier derived from the encoded request
     *         bytes
     * @throws IllegalArgumentException if {@code request} is {@code null}
     * @throws PkiException             if fingerprint computation fails
     *                                  unexpectedly
     */
    @Override
    public PkiId fingerprint(CertificationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(request.encoded().bytes());
            return new PkiId("req:" + HexFormat.of().formatHex(d));
        } catch (Exception ex) {
            throw new PkiException("Fingerprinting failed", ex);
        }
    }

    /**
     * Parses the supplied certification request using the active credential
     * framework.
     *
     * <p>
     * The parsing rules, supported request formats, and extracted request metadata
     * are defined by the configured framework implementation rather than by this
     * service itself.
     * </p>
     *
     * @param request certification request to parse; must not be {@code null}
     * @return parsed certification request representation produced by the active
     *         framework
     * @throws IllegalArgumentException if {@code request} is {@code null}
     * @throws PkiException             if the framework rejects the request or
     *                                  parsing fails
     */
    @Override
    public ParsedCertificationRequest parse(CertificationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        return framework.requestParser().parse(request);
    }

    /**
     * Verifies proof of possession for a previously parsed certification request.
     *
     * <p>
     * Verification behavior is delegated to the active framework and is governed by
     * the supplied {@link VerificationPolicy}. The exact verification depth,
     * acceptance criteria, and handling of structural versus cryptographic proof of
     * possession depend on the configured framework implementation and on the
     * selected policy.
     * </p>
     *
     * @param parsed parsed certification request to verify; must not be
     *               {@code null}
     * @param policy verification policy controlling the strength and acceptance
     *               rules of proof-of-possession verification; must not be
     *               {@code null}
     * @return proof-of-possession verification result returned by the active
     *         framework
     * @throws IllegalArgumentException if {@code parsed} or {@code policy} is
     *                                  {@code null}
     * @throws PkiException             if verification fails unexpectedly in the
     *                                  underlying framework
     */
    @Override
    public ProofOfPossessionResult verifyProofOfPossession(ParsedCertificationRequest parsed,
            VerificationPolicy policy) {
        if (parsed == null) {
            throw new IllegalArgumentException("parsed must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        return framework.proofOfPossessionVerifier().verify(parsed, policy);
    }

    /**
     * Persists a parsed certification request according to the supplied storage
     * policy.
     *
     * <p>
     * When the policy is {@link RequestStorePolicy#STORE_ALWAYS}, the parsed
     * request is written to the configured {@link PkiStore}. For other policies,
     * this method may act as a no-op with respect to persistence while still
     * returning the request identifier.
     * </p>
     *
     * <p>
     * This method does not re-parse the request and does not perform proof-of-
     * possession verification on its own. Callers are responsible for invoking
     * those operations in the correct workflow order when required by policy.
     * </p>
     *
     * @param parsed parsed certification request to store; must not be {@code null}
     * @param policy storage policy controlling whether the request is persisted;
     *               must not be {@code null}
     * @return identifier of the parsed request, regardless of whether the request
     *         was persisted
     * @throws IllegalArgumentException if {@code parsed} or {@code policy} is
     *                                  {@code null}
     * @throws PkiException             if persistence is required and the store
     *                                  operation fails
     */
    @Override
    public PkiId store(ParsedCertificationRequest parsed, RequestStorePolicy policy) {
        if (parsed == null) {
            throw new IllegalArgumentException("parsed must not be null");
        }
        if (policy == null) {
            throw new IllegalArgumentException("policy must not be null");
        }
        if (policy == RequestStorePolicy.STORE_ALWAYS) {
            store.putRequest(parsed);
        }
        return parsed.requestId();
    }

    /**
     * Resolves a previously stored parsed certification request by its identifier.
     *
     * @param requestId identifier of the stored request; must not be {@code null}
     * @return optional containing the stored parsed request when present, or an
     *         empty optional when no matching request exists
     * @throws IllegalArgumentException if {@code requestId} is {@code null}
     */
    @Override
    public Optional<ParsedCertificationRequest> get(PkiId requestId) {
        if (requestId == null) {
            throw new IllegalArgumentException("requestId must not be null");
        }
        return store.getRequest(requestId);
    }

    /**
     * Searches stored certification requests matching the supplied query.
     *
     * <p>
     * This operation is currently unsupported because the active {@link PkiStore}
     * SPI does not expose request listing or request search capabilities. Callers
     * must therefore resolve requests directly by identifier through
     * {@link #get(PkiId)}.
     * </p>
     *
     * @param query request query constraints; must not be {@code null}
     * @return never returns normally
     * @throws IllegalArgumentException if {@code query} is {@code null}
     * @throws PkiException             always, because request search is not
     *                                  supported by the current store SPI contract
     */
    @Override
    public List<ParsedCertificationRequest> search(RequestQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }
        throw new PkiException(
                "Request search is not supported by the PkiStore SPI (no request listing); use get(requestId) instead");
    }
}
