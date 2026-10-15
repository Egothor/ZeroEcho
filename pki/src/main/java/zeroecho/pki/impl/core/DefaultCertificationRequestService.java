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
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.RequestQuery;
import zeroecho.pki.api.request.RequestStorePolicy;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.impl.framework.x509.bc.BcX509CertificationRequestParser;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pkix.Pkix;

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
 * <li>Renewal identity checks reparse the original request and compare it with
 * the authoritative predecessor; caller-supplied normalized fields are not
 * trusted as proof of identity.</li>
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

    /** Bounded maximum number of certification requests returned by one search. */
    private static final int MAX_SEARCH_RESULTS = 1000;

    private final PkiStore store;
    private final CredentialFramework framework;
    private final Optional<X509ProfileBindingMatcher> bindingMatcher;

    /** {@inheritDoc} */
    @Override public void requireRenewalIdentity(ParsedCertificationRequest parsed, PkiId predecessorId) {
        Objects.requireNonNull(parsed, "parsed"); Objects.requireNonNull(predecessorId, "predecessorId");
        ParsedCertificationRequest original = parseX509(encodedX509Request(parsed));
        requireSameRenewalIdentity(original, parsed);
        try {
            Credential credential = store.getCredential(predecessorId).orElseThrow(() -> new PkiException("Renewal predecessor is unavailable"));
            if (!credential.credentialId().equals(predecessorId) || !credential.formatId().equals(BcX509CredentialFramework.FORMAT_ID)
                    || !(credential.profileBinding() instanceof EndEntityProfileBinding)) {
                throw new IllegalArgumentException("Renewal predecessor is invalid");
            }
            byte[] der = CredentialContent.materializeForBc(store, credential.content());
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(der));
            X509Certificate certificate = Pkix.parseCertificate(der);
            ParsedCertificationRequest expected = BcX509CertificationRequestParser.reconstructForRenewal(certificate, credential.formatId());
            if (certificate.getBasicConstraints() >= 0 || !predecessorId.value().equals("x509:" + digest)
                    || !credential.content().sha256().equals(digest) || !credential.subjectRef().equals(expected.subjectRef())
                    || !credential.publicKeyId().value().equals("spki:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(expected.publicKeyInfo().bytes())))
                    || !credential.serialOrUniqueId().equals(certificate.getSerialNumber().toString())
                    || !credential.validity().notBefore().equals(certificate.getNotBefore().toInstant())
                    || !credential.validity().notAfter().equals(certificate.getNotAfter().toInstant())) {
                throw new IllegalArgumentException("Renewal predecessor is invalid");
            }
            requireSameRenewalIdentity(expected, original);
        } catch (java.security.NoSuchAlgorithmException failure) {
            throw new PkiException("Renewal predecessor cannot be validated"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private static void requireSameRenewalIdentity(ParsedCertificationRequest expected, ParsedCertificationRequest actual) {
        if (!expected.subjectRef().equals(actual.subjectRef()) || !expected.subjectRdns().equals(actual.subjectRdns())
                || !expected.subjectAlternativeNames().equals(actual.subjectAlternativeNames())
                || expected.subjectAlternativeNamePresent() != actual.subjectAlternativeNamePresent()
                || !Arrays.equals(expected.publicKeyInfo().bytes(), actual.publicKeyInfo().bytes())) {
            throw new IllegalArgumentException("Renewal request identity differs from authoritative content");
        }
    }

    /**
     * Creates a certification request service bound to the supplied persistence and
     * framework collaborators.
     * This constructor does not configure frozen profile-proof validation;
     * {@link #requireProfileProof} fails closed until the explicit registry
     * constructor is used.
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
        this.bindingMatcher = Optional.empty();
    }

    /**
     * Creates a request service with the same explicit binding registry used by
     * session issuance. The framework must carry the session's X.509 authority.
     * @param store authoritative request and imported-profile store
     * @param framework configured X.509 parsing and verification framework
     * @param bindings immutable session binding registry
     */
    public DefaultCertificationRequestService(PkiStore store, BcX509CredentialFramework framework,
            zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry bindings) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.bindingMatcher = Optional.of(new X509ProfileBindingMatcher(framework.authority(), bindings));
    }

    /** {@inheritDoc} */
    @Override public void requireProfileProof(ParsedCertificationRequest parsed, zeroecho.pki.api.profile.CertificateProfileRef profile) {
        Objects.requireNonNull(profile, "profile");
        X509ProfileBindingMatcher matcher = bindingMatcher.orElseThrow(() -> new IllegalStateException("Profile proof validation is not configured"));
        zeroecho.pki.api.profile.ImportedCertificateProfileVersion imported = store.getProfileVersion(profile.profileId(), profile.profileVersion())
                .orElseThrow(() -> new IllegalArgumentException("Frozen request profile is unavailable"));
        if (!profile.equals(imported.reference()) || !imported.definition().formatId().equals(BcX509CredentialFramework.FORMAT_ID)) {
            throw new IllegalArgumentException("Frozen request profile is inconsistent");
        }
        X509EnrollmentPayload payload = encodedX509Request(parsed);
        ParsedCertificationRequest original = parseX509(payload);
        if (verifyProofOfPossession(original, new VerificationPolicy(true, Optional.empty())).status()
                != zeroecho.pki.api.request.ProofOfPossessionStatus.VERIFIED) {
            throw new IllegalArgumentException("Request proof is invalid");
        }
        try {
            zeroecho.pkix.AlgorithmIdentifier signature = payload.kind() == X509EnrollmentPayload.Kind.PKCS10
                    ? Pkix.parseCertificationRequest(payload.der()).signatureAlgorithm()
                    : zeroecho.pkix.cmp.CrmfRequest.parse(payload.der()).signatureAlgorithm();
            matcher.require(signature, zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role.CSR_SIGNATURE,
                    imported.definition().algorithmBindingPolicy().csrSignature());
        } catch (IllegalArgumentException failure) {
            throw new IllegalArgumentException("Request proof binding differs from frozen profile"); // NOPMD PreserveStackTrace, AvoidThrowingNewInstanceOfSameException - Expose the policy rejection without retaining request or provider diagnostics.
        }
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

    /** {@inheritDoc} */
    @Override
    public ParsedCertificationRequest parseX509(X509EnrollmentPayload request) {
        return framework.requestParser().parseX509(Objects.requireNonNull(request, "request"));
    }

    /** {@inheritDoc} */
    @Override
    public X509EnrollmentPayload encodedX509Request(ParsedCertificationRequest parsed) {
        return zeroecho.pki.impl.framework.x509.bc.BcX509RequestPayloads.extract(parsed);
    }

    /**
     * Returns a bounded, fingerprint-checked copy of the retained X.509 CSR.
     * Attribute lookup is O(A) for the current list-backed attribute set; copying
     * and hashing D bytes take O(D) time and transient memory. No collaborator is invoked.
     * @param parsed parsed request retaining one original DER byte attribute
     * @return independently owned exact request bytes
     * @throws IllegalArgumentException if the input or retained binding is invalid
     * @throws PkiException if SHA-256 is unavailable
     */
    @Override
    public CertificationRequest encodedRequest(ParsedCertificationRequest parsed) {
        X509EnrollmentPayload payload = encodedX509Request(parsed);
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10) {
            throw new IllegalArgumentException("CRMF requires the typed enrollment recovery API");
        }
        return new CertificationRequest(parsed.formatId(), new EncodedObject(Encoding.DER, payload.der()));
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
     * Requests are filtered on the enterprise-standard axes carried by
     * {@link RequestQuery}: framework format, subject, requested profile, and
     * creation-time range. The result is bounded to at most
     * {@value #MAX_SEARCH_RESULTS} entries. Resolve an exact request by identifier
     * through {@link #get(PkiId)}.
     * </p>
     *
     * @param query request query constraints; must not be {@code null}
     * @return bounded list of matching requests
     * @throws IllegalArgumentException if {@code query} is {@code null}
     * @throws PkiException             if the active store cannot list requests
     */
    @Override
    public List<ParsedCertificationRequest> search(RequestQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }
        try {
            return store.searchRequests(query, MAX_SEARCH_RESULTS);
        } catch (UnsupportedOperationException unsupported) {
            throw new PkiException("Request search is not supported by the active store", unsupported);
        }
    }
}
