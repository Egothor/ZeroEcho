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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Map;
import java.util.Set;

import zeroecho.pkix.Pkix;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepository;

/** Durable exact responder-binding authority over the server control store. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ControlStatementBraces",
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.AvoidLiteralsInIfCondition",
        "PMD.LinguisticNaming", "PMD.UseObjectForClearerAPI", "PMD.ExcessiveParameterList",
        "PMD.PreserveStackTrace", "PMD.AvoidCatchingGenericException", "PMD.UseEnumCollections",
        "PMD.ExceptionAsFlowControl" })
public final class OcspResponderService {
    /** {@code id-kp-OCSPSigning} extended-key-usage OID (RFC 6960). */
    private static final String OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    /** Closed signed-request authentication policy. */
    @SuppressWarnings("PMD.LongVariable")
    public enum RequestAuthenticationMode {
        /** Accepts only unsigned OCSP requests. */ UNSIGNED_ONLY(1),
        /** Accepts unsigned or successfully authorized signed requests. */ UNSIGNED_OR_AUTHORIZED_SIGNED(2),
        /** Requires every request to carry an authorized signature. */ AUTHORIZED_SIGNED_REQUIRED(3);
        private final int code;
        RequestAuthenticationMode(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted authentication-mode code
         * @return corresponding authentication mode
         */
        public static RequestAuthenticationMode fromCode(int code) {
            return switch (code) { case 1 -> UNSIGNED_ONLY; case 2 -> UNSIGNED_OR_AUTHORIZED_SIGNED;
                case 3 -> AUTHORIZED_SIGNED_REQUIRED;
                default -> throw new IllegalArgumentException("Unknown OCSP request-authentication mode code"); };
        }
    }

    /** Closed local requester-certificate revocation behavior. */
    @SuppressWarnings("PMD.LongVariable")
    public enum RequesterRevocationPolicy {
        /** Requires authoritative local revocation state for every requester. */ LOCAL_AUTHORITATIVE_REQUIRED(1),
        /** Requires local revocation state only for managed requesters. */ LOCAL_AUTHORITATIVE_IF_MANAGED(2),
        /** Relies on certificate validity and trust without local revocation state. */ VALIDITY_AND_TRUST_ONLY(3);
        private final int code;
        RequesterRevocationPolicy(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted requester-revocation code
         * @return corresponding requester-revocation policy
         */
        public static RequesterRevocationPolicy fromCode(int code) {
            return switch (code) { case 1 -> LOCAL_AUTHORITATIVE_REQUIRED;
                case 2 -> LOCAL_AUTHORITATIVE_IF_MANAGED; case 3 -> VALIDITY_AND_TRUST_ONLY;
                default -> throw new IllegalArgumentException("Unknown OCSP requester revocation policy code"); };
        }
    }

    /** Repository-backed requester trust selector. */
    @SuppressWarnings("PMD.LongVariable")
    public enum TrustSelectorType {
        /** Selects managed issuer generations. */ MANAGED_ISSUER_GENERATIONS(1),
        /** Selects explicitly configured trust-anchor credentials. */ CONFIGURED_TRUST_ANCHORS(2),
        /** Selects exact requester certificate commitments. */ EXACT_REQUESTER_CERTIFICATE_COMMITMENTS(3);
        private final int code;
        TrustSelectorType(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted selector-type code
         * @return corresponding trust-selector type
         */
        public static TrustSelectorType fromCode(int code) {
            return switch (code) { case 1 -> MANAGED_ISSUER_GENERATIONS; case 2 -> CONFIGURED_TRUST_ANCHORS;
                case 3 -> EXACT_REQUESTER_CERTIFICATE_COMMITMENTS;
                default -> throw new IllegalArgumentException("Unknown OCSP requester trust-selector code"); };
        }
    }

    /** Cryptographic requester-to-principal mapping type. */
    @SuppressWarnings("PMD.LongVariable")
    public enum PrincipalMappingType {
        /** Maps the SHA-256 commitment of the requester certificate. */ SHA256_CERTIFICATE_COMMITMENT(1),
        /** Maps the SHA-256 commitment of requester subject-public-key information. */ SHA256_SPKI_COMMITMENT(2),
        /** Maps a commitment to the requester issuer and serial number. */ ISSUER_AND_SERIAL_COMMITMENT(3);
        private final int code;
        PrincipalMappingType(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted mapping-type code
         * @return corresponding mapping type
         */
        public static PrincipalMappingType fromCode(int code) {
            return switch (code) { case 1 -> SHA256_CERTIFICATE_COMMITMENT;
                case 2 -> SHA256_SPKI_COMMITMENT; case 3 -> ISSUER_AND_SERIAL_COMMITMENT;
                default -> throw new IllegalArgumentException("Unknown OCSP requester mapping code"); };
        }
    }

    /**
     * One explicit repository-backed trust selector.
     *
     * @param type selector interpretation
     * @param identities finite exact identities selected under that interpretation
     */
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    public record TrustSelector(TrustSelectorType type, Set<String> identities) {
        /** Validates and snapshots finite identities. */
        public TrustSelector {
            Objects.requireNonNull(type, "type"); identities = Set.copyOf(Objects.requireNonNull(identities));
            if (identities.isEmpty() || identities.size() > 64) {
                throw new IllegalArgumentException("OCSP requester trust selector is empty or oversized");
            }
            for (String identity : identities) {
                if (type == TrustSelectorType.EXACT_REQUESTER_CERTIFICATE_COMMITMENTS) requireDigest(identity);
                else new PkiId(identity);
            }
        }
    }

    /**
     * One exact active request-signature binding reference.
     *
     * @param bindingId active binding identifier
     * @param commitment expected immutable binding commitment
     */
    public record RequestSignatureBinding(String bindingId, String commitment) {
        /** Validates stable binding identity and commitment. */
        public RequestSignatureBinding {
            Permission.requireId(bindingId, "OCSP request-signature binding");
            Permission.requireBounded(commitment, 512, "OCSP request-signature commitment");
        }
    }

    /**
     * One cryptographic requester-certificate mapping.
     *
     * @param mappingId stable mapping identifier
     * @param principalId security principal selected by a match
     * @param type cryptographic value represented by the commitment
     * @param commitment lowercase SHA-256 commitment
     */
    public record PrincipalMapping(String mappingId, String principalId, PrincipalMappingType type,
            String commitment) {
        /** Validates stable mapping metadata and fixed commitment. */
        public PrincipalMapping {
            Permission.requireId(mappingId, "OCSP requester mapping"); Permission.requirePrincipal(principalId);
            Objects.requireNonNull(type, "type"); requireDigest(commitment);
        }
    }

    /**
     * Finite immutable requester trust, mapping, signature and chain policy.
     *
     * @param trustSelectors repository-backed trust selectors
     * @param principalMappings cryptographic requester-to-principal mappings
     * @param signatureBindings permitted OCSP request-signature bindings
     * @param revocationPolicy requester revocation validation policy
     * @param maximumSignerCertificates maximum certificates accepted in a requester chain
     * @param maximumSignerChainBytes maximum encoded requester-chain size in bytes
     */
    public record RequesterTrustPolicy(List<TrustSelector> trustSelectors,
            List<PrincipalMapping> principalMappings, List<RequestSignatureBinding> signatureBindings,
            RequesterRevocationPolicy revocationPolicy, int maximumSignerCertificates,
            int maximumSignerChainBytes) {
        /** Validates and snapshots the complete closed policy. */
        public RequesterTrustPolicy {
            trustSelectors = List.copyOf(Objects.requireNonNull(trustSelectors));
            principalMappings = List.copyOf(Objects.requireNonNull(principalMappings));
            signatureBindings = List.copyOf(Objects.requireNonNull(signatureBindings));
            Objects.requireNonNull(revocationPolicy, "revocationPolicy");
            if (trustSelectors.isEmpty() || trustSelectors.size() > 16 || principalMappings.isEmpty()
                    || principalMappings.size() > 256 || signatureBindings.isEmpty() || signatureBindings.size() > 16
                    || maximumSignerCertificates < 1 || maximumSignerCertificates > 16
                    || maximumSignerChainBytes < 1024 || maximumSignerChainBytes > 1_048_576) {
                throw new IllegalArgumentException("OCSP requester trust policy bounds are invalid");
            }
            if (principalMappings.stream().map(PrincipalMapping::mappingId).distinct().count()
                    != principalMappings.size()
                    || signatureBindings.stream().map(RequestSignatureBinding::bindingId).distinct().count()
                    != signatureBindings.size()) {
                throw new IllegalArgumentException("OCSP requester policy identities are duplicated");
            }
        }
    }
    /** Exact signing authority. */
    public enum SigningMode {
        /** Uses the issuer certificate and key directly. */ ISSUER_SIGNED(1),
        /** Uses an issuer-authorized delegated responder certificate and key. */ DELEGATED_RESPONDER(2);
        private final int code;
        SigningMode(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted signing-mode code
         * @return corresponding signing mode
         */
        public static SigningMode fromCode(int code) {
            return switch (code) { case 1 -> ISSUER_SIGNED; case 2 -> DELEGATED_RESPONDER;
                default -> throw new IllegalArgumentException("Unknown OCSP signing mode code"); };
        }
    }
    /** Closed nonce behavior. */
    public enum NoncePolicy {
        /** Rejects requests containing a nonce. */ REJECT(1),
        /** Accepts and echoes an optional nonce. */ OPTIONAL_ECHO(2),
        /** Requires and echoes a nonce. */ REQUIRED(3);
        private final int code;
        NoncePolicy(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted nonce-policy code
         * @return corresponding nonce policy
         */
        public static NoncePolicy fromCode(int code) {
            return switch (code) { case 1 -> REJECT; case 2 -> OPTIONAL_ECHO; case 3 -> REQUIRED;
                default -> throw new IllegalArgumentException("Unknown OCSP nonce policy code"); };
        }
    }
    /** Durable activation state. */
    public enum State {
        /** Responder configuration exists but cannot serve requests. */ INACTIVE(1),
        /** Responder is eligible to serve requests. */ ACTIVE(2);
        private final int code;
        State(int code) { this.code = code; }
        /**
         * Returns the stable persistence code.
         *
         * @return encoded value
         */
        public int code() { return code; }
        /**
         * Resolves an exact stable code.
         *
         * @param code persisted state code
         * @return corresponding responder state
         */
        public static State fromCode(int code) {
            return switch (code) { case 1 -> INACTIVE; case 2 -> ACTIVE;
                default -> throw new IllegalArgumentException("Unknown OCSP responder state code"); };
        }
    }

    /**
     * Closed administrator input without server-authoritative timestamps, state, or record commitments.
     *
     * @param responderId stable responder identifier
     * @param alias unique public responder alias
     * @param authorityId logical authority identifier
     * @param issuerId exact issuer generation identifier
     * @param signingMode issuer or delegated signing mode
     * @param responderCredentialId exact responder certificate identifier
     * @param signingKeyRef exact signing-key reference
     * @param chainPathId responder certificate-chain path identifier
     * @param signatureAlgorithm signature algorithm identifier
     * @param signatureBindingId optional explicit signature binding
     * @param signatureBindingCommitment expected binding or registry commitment
     * @param responderIdForm OCSP responder-identifier representation
     * @param responseValidity positive response validity
     * @param noncePolicy request nonce policy
     * @param maximumNonceBytes maximum accepted nonce size in bytes
     * @param acceptedHashes accepted certificate-identifier hash algorithms
     * @param maximumRequestBytes maximum encoded request size in bytes
     * @param maximumEntries maximum certificate identifiers per request
     * @param cacheLifetime positive response-cache lifetime
     * @param requestAuthenticationMode signed-request authentication policy
     * @param requesterTrustPolicy requester trust policy required by signed modes
     */
    public record Registration(String responderId, String alias, PkiId authorityId, PkiId issuerId,
            SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
            String signatureAlgorithm, Optional<String> signatureBindingId, String signatureBindingCommitment,
            OcspResponseService.ResponderId responderIdForm, Duration responseValidity, NoncePolicy noncePolicy,
            int maximumNonceBytes, Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime, RequestAuthenticationMode requestAuthenticationMode,
            Optional<RequesterTrustPolicy> requesterTrustPolicy) {
        /** Snapshots the typed finite registration input. */
        public Registration {
            Permission.requireId(responderId, "OCSP responder"); Permission.requireId(alias, "OCSP alias");
            Objects.requireNonNull(authorityId); Objects.requireNonNull(issuerId); Objects.requireNonNull(signingMode);
            Objects.requireNonNull(responderCredentialId); Objects.requireNonNull(signingKeyRef);
            Objects.requireNonNull(chainPathId); Permission.requireBounded(signatureAlgorithm, 128,
                    "OCSP signature algorithm");
            signatureBindingId = Objects.requireNonNull(signatureBindingId);
            requireDigest(signatureBindingCommitment); Objects.requireNonNull(responderIdForm);
            Objects.requireNonNull(responseValidity); Objects.requireNonNull(noncePolicy);
            acceptedHashes = Set.copyOf(Objects.requireNonNull(acceptedHashes));
            Objects.requireNonNull(cacheLifetime);
            Objects.requireNonNull(requestAuthenticationMode, "requestAuthenticationMode");
            requesterTrustPolicy = Objects.requireNonNull(requesterTrustPolicy, "requesterTrustPolicy");
            requirePolicyShape(requestAuthenticationMode, requesterTrustPolicy);
        }

        /**
         * Creates the default public unsigned-only registration.
         *
         * @param responderId stable responder identifier
         * @param alias unique public responder alias
         * @param authorityId logical authority identifier
         * @param issuerId exact issuer generation identifier
         * @param signingMode issuer or delegated signing mode
         * @param responderCredentialId exact responder certificate identifier
         * @param signingKeyRef exact signing-key reference
         * @param chainPathId responder certificate-chain path identifier
         * @param signatureAlgorithm signature algorithm identifier
         * @param signatureBindingId optional explicit signature binding
         * @param signatureBindingCommitment expected binding or registry commitment
         * @param responderIdForm OCSP responder-identifier representation
         * @param responseValidity positive response validity
         * @param noncePolicy request nonce policy
         * @param maximumNonceBytes maximum accepted nonce size in bytes
         * @param acceptedHashes accepted certificate-identifier hash algorithms
         * @param maximumRequestBytes maximum encoded request size in bytes
         * @param maximumEntries maximum certificate identifiers per request
         * @param cacheLifetime positive response-cache lifetime
         */
        public Registration(String responderId, String alias, PkiId authorityId, PkiId issuerId,
                SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
                String signatureAlgorithm, Optional<String> signatureBindingId, String signatureBindingCommitment,
                OcspResponseService.ResponderId responderIdForm, Duration responseValidity, NoncePolicy noncePolicy,
                int maximumNonceBytes, Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumRequestBytes,
                int maximumEntries, Duration cacheLifetime) {
            this(responderId, alias, authorityId, issuerId, signingMode, responderCredentialId, signingKeyRef,
                    chainPathId, signatureAlgorithm, signatureBindingId, signatureBindingCommitment, responderIdForm,
                    responseValidity, noncePolicy, maximumNonceBytes, acceptedHashes, maximumRequestBytes,
                    maximumEntries, cacheLifetime, RequestAuthenticationMode.UNSIGNED_ONLY, Optional.empty());
        }
    }

    /**
     * Strict versioned responder binding.
     *
     * @param responderId stable responder identifier
     * @param alias unique public responder alias
     * @param realmId owning security realm
     * @param authorityId logical authority identifier
     * @param issuerId exact issuer generation identifier
     * @param signingMode issuer or delegated signing mode
     * @param responderCredentialId exact responder certificate identifier
     * @param signingKeyRef exact signing-key reference
     * @param chainPathId responder certificate-chain path identifier
     * @param signatureAlgorithm signature algorithm identifier
     * @param signatureBindingId optional explicit signature binding
     * @param signatureBindingCommitment expected binding or registry commitment
     * @param responderIdForm OCSP responder-identifier representation
     * @param responseValidity positive response validity
     * @param noncePolicy request nonce policy
     * @param maximumNonceBytes maximum accepted nonce size in bytes
     * @param acceptedHashes accepted certificate-identifier hash algorithms
     * @param maximumRequestBytes maximum encoded request size in bytes
     * @param maximumEntries maximum certificate identifiers per request
     * @param cacheLifetime positive response-cache lifetime
     * @param requestAuthenticationMode signed-request authentication policy
     * @param requesterTrustPolicy requester trust policy required by signed modes
     * @param state durable activation state
     * @param createdAt server-authoritative creation time
     * @param configurationCommitment SHA-256 commitment to the complete configuration
     */
    public record Responder(String responderId, String alias, RealmId realmId, PkiId authorityId,
            PkiId issuerId, SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef,
            PkiId chainPathId, String signatureAlgorithm, Optional<String> signatureBindingId,
            String signatureBindingCommitment, OcspResponseService.ResponderId responderIdForm,
            Duration responseValidity, NoncePolicy noncePolicy, int maximumNonceBytes,
            Set<OcspResponseService.CertIdHash> acceptedHashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime, RequestAuthenticationMode requestAuthenticationMode,
            Optional<RequesterTrustPolicy> requesterTrustPolicy, State state, Instant createdAt,
            String configurationCommitment) {
        /** Validates all finite immutable dependencies and the record commitment. */
        public Responder {
            Permission.requireId(responderId, "OCSP responder"); Permission.requireId(alias, "OCSP alias");
            Objects.requireNonNull(realmId); Objects.requireNonNull(authorityId); Objects.requireNonNull(issuerId);
            Objects.requireNonNull(signingMode); Objects.requireNonNull(responderCredentialId);
            Objects.requireNonNull(signingKeyRef); Objects.requireNonNull(chainPathId);
            Permission.requireBounded(signatureAlgorithm, 128, "OCSP signature algorithm");
            signatureBindingId = Objects.requireNonNull(signatureBindingId);
            requireDigest(signatureBindingCommitment); Objects.requireNonNull(responderIdForm);
            positive(responseValidity, Duration.ofDays(7), "response validity"); Objects.requireNonNull(noncePolicy);
            if (maximumNonceBytes < 8 || maximumNonceBytes > 4096 || maximumRequestBytes < 256
                    || maximumRequestBytes > 1_048_576 || maximumEntries < 1 || maximumEntries > 4096) {
                throw new IllegalArgumentException("OCSP responder bounds are invalid");
            }
            acceptedHashes = Set.copyOf(Objects.requireNonNull(acceptedHashes));
            if (acceptedHashes.isEmpty()) throw new IllegalArgumentException("OCSP CertID hashes are empty");
            positive(cacheLifetime, responseValidity, "cache lifetime"); Objects.requireNonNull(state);
            Objects.requireNonNull(requestAuthenticationMode, "requestAuthenticationMode");
            requesterTrustPolicy = Objects.requireNonNull(requesterTrustPolicy, "requesterTrustPolicy");
            requirePolicyShape(requestAuthenticationMode, requesterTrustPolicy);
            Objects.requireNonNull(createdAt); requireDigest(configurationCommitment);
        }
    }

    private final RealmId realmId;
    private final ServerControlStore control;
    private final PkiRepository repository;
    private final X509AlgorithmBindingRegistry bindings;
    private final Optional<OcspResponseService> signing;
    private final Clock clock;
    private final Map<String, Responder> aliasIndex = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * Binds responder control to one realm and one authoritative PKI repository.
     *
     * @param realmId owning security realm
     * @param control durable server-control store
     * @param repository authoritative PKI repository
     * @param bindings active X.509 algorithm-binding registry
     * @param signing optional status-object signing service
     * @param clock authoritative server clock
     */
    public OcspResponderService(RealmId realmId, ServerControlStore control, PkiRepository repository,
            X509AlgorithmBindingRegistry bindings, Optional<OcspResponseService> signing, Clock clock) {
        this.realmId = Objects.requireNonNull(realmId); this.control = Objects.requireNonNull(control);
        this.repository = Objects.requireNonNull(repository); this.bindings = Objects.requireNonNull(bindings);
        this.signing = Objects.requireNonNull(signing);
        this.clock = Objects.requireNonNull(clock);
    }

    /**
     * Creates authoritative metadata and durably registers one inactive responder.
     *
     * @param supplied validated administrator input
     * @return durably sealed inactive responder
     */
    public Responder register(Registration supplied) {
        Objects.requireNonNull(supplied, "supplied");
        return register(create(supplied.responderId(), supplied.alias(), supplied.authorityId(), supplied.issuerId(),
                supplied.signingMode(), supplied.responderCredentialId(), supplied.signingKeyRef(),
                supplied.chainPathId(), supplied.signatureAlgorithm(), supplied.signatureBindingId(),
                supplied.signatureBindingCommitment(), supplied.responderIdForm(), supplied.responseValidity(),
                supplied.noncePolicy(), supplied.maximumNonceBytes(), supplied.acceptedHashes(),
                supplied.maximumRequestBytes(), supplied.maximumEntries(), supplied.cacheLifetime(),
                supplied.requestAuthenticationMode(), supplied.requesterTrustPolicy()));
    }

    /** Canonically seals an already constructed internal draft. */
    /* default */ Responder register(Responder supplied) {
        if (!supplied.realmId().equals(realmId) || supplied.state() != State.INACTIVE) {
            throw new IllegalArgumentException("OCSP responder realm or initial state is invalid");
        }
        if (!supplied.configurationCommitment().equals(commitment(supplied, true))) {
            throw new IllegalArgumentException("OCSP responder commitment differs");
        }
        if (aliasIndex.containsKey(supplied.alias())) {
            throw new IllegalStateException("OCSP responder alias already exists");
        }
        validateDependencies(supplied, true);
        Responder sealed = seal(supplied, State.INACTIVE);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record(sealed), Optional.empty())));
        aliasIndex.put(sealed.alias(), sealed);
        return sealed;
    }

    /**
     * Returns one exact responder.
     *
     * @param responderId stable responder identifier
     * @return durable responder configuration
     */
    public Responder require(String responderId) {
        return control.protocolRecord(ServerControlStore.OCSP_RESPONDER, responderId)
                .map(this::decode).orElseThrow(() -> new IllegalArgumentException("OCSP responder is unavailable"));
    }

    /**
     * Resolves one unique active public alias.
     *
     * @param alias public responder alias
     * @return active responder configuration
     */
    public Responder requireActiveAlias(String alias) {
        Responder result = requireAlias(alias);
        if (result.state() != State.ACTIVE) {
            throw new IllegalStateException("OCSP responder is inactive");
        }
        return result;
    }

    /**
     * Resolves one unique durable alias regardless of activation state.
     *
     * @param alias public responder alias
     * @return durable responder configuration
     */
    public Responder requireAlias(String alias) {
        Permission.requireId(alias, "OCSP alias");
        Responder indexed = aliasIndex.get(alias);
        if (indexed == null) throw new IllegalArgumentException("OCSP responder alias is unavailable");
        return indexed;
    }

    /**
     * Lists one bounded deterministic responder page.
     *
     * @param offset zero-based record offset
     * @param limit positive maximum page size
     * @return deterministic bounded responder page
     */
    public ServerControlStore.Page<Responder> list(int offset, int limit) {
        ServerControlStore.Page<ServerControlStore.ProtocolRecord> page =
                control.protocolRecords(ServerControlStore.OCSP_RESPONDER, offset, limit);
        return new ServerControlStore.Page<>(page.values().stream().map(this::decode).toList(),
                page.nextOffset(), page.hasMore());
    }

    /**
     * Atomically changes only responder activation after dependency revalidation.
     *
     * @param responderId stable responder identifier
     * @param active desired activation state
     * @return durably updated responder
     */
    public Responder setActive(String responderId, boolean active) {
        Responder prior = require(responderId); validateDependencies(prior, true);
        Responder next = seal(prior, active ? State.ACTIVE : State.INACTIVE);
        control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(record(next),
                Optional.of(record(prior).commitment()))));
        aliasIndex.put(next.alias(), next);
        return next;
    }

    /** Revalidates every durable binding during realm recovery. */
    public void validateAll() {
        Map<String, Responder> recovered = new java.util.HashMap<>();
        int offset = 0;
        while (true) {
            ServerControlStore.Page<Responder> page = list(offset, 256);
            page.values().forEach(value -> {
                validateDependencies(value, true);
                if (recovered.putIfAbsent(value.alias(), value) != null) {
                    throw new IllegalStateException("OCSP responder alias is duplicated");
                }
            });
            if (!page.hasMore()) {
                aliasIndex.clear(); aliasIndex.putAll(recovered); return;
            }
            offset = page.nextOffset();
        }
    }

    /**
     * Creates a canonical unsigned-only unsealed record before registration.
     *
     * @param responderId stable responder identifier
     * @param alias unique public responder alias
     * @param authorityId logical authority identifier
     * @param issuerId exact issuer generation identifier
     * @param signingMode issuer or delegated signing mode
     * @param responderCredentialId exact responder certificate identifier
     * @param signingKeyRef exact signing-key reference
     * @param chainPathId responder certificate-chain path identifier
     * @param signatureAlgorithm signature algorithm identifier
     * @param signatureBindingId optional explicit signature binding
     * @param bindingCommitment expected binding or registry commitment
     * @param responderIdForm OCSP responder-identifier representation
     * @param validity positive response validity
     * @param noncePolicy request nonce policy
     * @param maximumNonceBytes maximum accepted nonce size in bytes
     * @param hashes accepted certificate-identifier hash algorithms
     * @param maximumRequestBytes maximum encoded request size in bytes
     * @param maximumEntries maximum certificate identifiers per request
     * @param cacheLifetime positive response-cache lifetime
     * @return canonical unsealed inactive responder draft
     */
    public Responder create(String responderId, String alias, PkiId authorityId, PkiId issuerId,
            SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
            String signatureAlgorithm, Optional<String> signatureBindingId, String bindingCommitment,
            OcspResponseService.ResponderId responderIdForm, Duration validity, NoncePolicy noncePolicy,
            int maximumNonceBytes, Set<OcspResponseService.CertIdHash> hashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime) {
        return create(responderId, alias, authorityId, issuerId, signingMode, responderCredentialId,
                signingKeyRef, chainPathId, signatureAlgorithm, signatureBindingId, bindingCommitment,
                responderIdForm, validity, noncePolicy, maximumNonceBytes, hashes, maximumRequestBytes,
                maximumEntries, cacheLifetime, RequestAuthenticationMode.UNSIGNED_ONLY, Optional.empty());
    }

    /**
     * Creates a canonical unsealed record with explicit signed-request policy.
     *
     * @param responderId stable responder identifier
     * @param alias unique public responder alias
     * @param authorityId logical authority identifier
     * @param issuerId exact issuer generation identifier
     * @param signingMode issuer or delegated signing mode
     * @param responderCredentialId exact responder certificate identifier
     * @param signingKeyRef exact signing-key reference
     * @param chainPathId responder certificate-chain path identifier
     * @param signatureAlgorithm signature algorithm identifier
     * @param signatureBindingId optional explicit signature binding
     * @param bindingCommitment expected binding or registry commitment
     * @param responderIdForm OCSP responder-identifier representation
     * @param validity positive response validity
     * @param noncePolicy request nonce policy
     * @param maximumNonceBytes maximum accepted nonce size in bytes
     * @param hashes accepted certificate-identifier hash algorithms
     * @param maximumRequestBytes maximum encoded request size in bytes
     * @param maximumEntries maximum certificate identifiers per request
     * @param cacheLifetime positive response-cache lifetime
     * @param requestAuthenticationMode signed-request authentication policy
     * @param requesterTrustPolicy requester trust policy required by signed modes
     * @return canonical unsealed inactive responder draft
     */
    public Responder create(String responderId, String alias, PkiId authorityId, PkiId issuerId,
            SigningMode signingMode, PkiId responderCredentialId, KeyRef signingKeyRef, PkiId chainPathId,
            String signatureAlgorithm, Optional<String> signatureBindingId, String bindingCommitment,
            OcspResponseService.ResponderId responderIdForm, Duration validity, NoncePolicy noncePolicy,
            int maximumNonceBytes, Set<OcspResponseService.CertIdHash> hashes, int maximumRequestBytes,
            int maximumEntries, Duration cacheLifetime, RequestAuthenticationMode requestAuthenticationMode,
            Optional<RequesterTrustPolicy> requesterTrustPolicy) {
        Responder draft = new Responder(responderId, alias, realmId, authorityId, issuerId, signingMode,
                responderCredentialId, signingKeyRef, chainPathId, signatureAlgorithm, signatureBindingId,
                bindingCommitment, responderIdForm, validity, noncePolicy, maximumNonceBytes, hashes,
                maximumRequestBytes, maximumEntries, cacheLifetime, requestAuthenticationMode,
                requesterTrustPolicy, State.INACTIVE, clock.instant(), "0".repeat(64));
        return new Responder(draft.responderId(), draft.alias(), draft.realmId(), draft.authorityId(), draft.issuerId(),
                draft.signingMode(), draft.responderCredentialId(), draft.signingKeyRef(), draft.chainPathId(),
                draft.signatureAlgorithm(), draft.signatureBindingId(), draft.signatureBindingCommitment(),
                draft.responderIdForm(), draft.responseValidity(), draft.noncePolicy(), draft.maximumNonceBytes(),
                draft.acceptedHashes(), draft.maximumRequestBytes(), draft.maximumEntries(), draft.cacheLifetime(),
                draft.requestAuthenticationMode(), draft.requesterTrustPolicy(), draft.state(), draft.createdAt(),
                commitment(draft, true));
    }

    private Responder seal(Responder value, State state) {
        Responder draft = new Responder(value.responderId(), value.alias(), value.realmId(), value.authorityId(),
                value.issuerId(), value.signingMode(), value.responderCredentialId(), value.signingKeyRef(),
                value.chainPathId(), value.signatureAlgorithm(), value.signatureBindingId(),
                value.signatureBindingCommitment(), value.responderIdForm(), value.responseValidity(),
                value.noncePolicy(), value.maximumNonceBytes(), value.acceptedHashes(), value.maximumRequestBytes(),
                value.maximumEntries(), value.cacheLifetime(), value.requestAuthenticationMode(),
                value.requesterTrustPolicy(), state, value.createdAt(), value.configurationCommitment());
        return new Responder(draft.responderId(), draft.alias(), draft.realmId(), draft.authorityId(), draft.issuerId(),
                draft.signingMode(), draft.responderCredentialId(), draft.signingKeyRef(), draft.chainPathId(),
                draft.signatureAlgorithm(), draft.signatureBindingId(), draft.signatureBindingCommitment(),
                draft.responderIdForm(), draft.responseValidity(), draft.noncePolicy(), draft.maximumNonceBytes(),
                draft.acceptedHashes(), draft.maximumRequestBytes(), draft.maximumEntries(), draft.cacheLifetime(),
                draft.requestAuthenticationMode(), draft.requesterTrustPolicy(), draft.state(), draft.createdAt(),
                commitment(draft, true));
    }

    private void validateDependencies(Responder value, boolean proveSigning) {
        value.signatureBindingId().ifPresentOrElse(
                bindingId -> bindings.require(bindingId, value.signatureBindingCommitment()),
                () -> {
                    if (!bindings.commitment().equals(value.signatureBindingCommitment())) {
                        throw new IllegalStateException("OCSP algorithm registry commitment differs");
                    }
                });
        value.requesterTrustPolicy().ifPresent(policy -> {
            for (RequestSignatureBinding reference : policy.signatureBindings()) {
                X509AlgorithmBinding binding = bindings.require(reference.bindingId(), reference.commitment());
                if (binding.role() != X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE) {
                    throw new IllegalStateException("OCSP requester signature binding has the wrong role");
                }
            }
            for (TrustSelector selector : policy.trustSelectors()) {
                if (selector.type() == TrustSelectorType.MANAGED_ISSUER_GENERATIONS) {
                    selector.identities().forEach(identity -> repository.issuer(new PkiId(identity)).orElseThrow(
                            () -> new IllegalStateException("OCSP requester issuer trust is unavailable")));
                } else if (selector.type() == TrustSelectorType.CONFIGURED_TRUST_ANCHORS) {
                    selector.identities().forEach(identity -> {
                        try { certificate(new PkiId(identity)); }
                        catch (IOException failure) { throw new IllegalStateException("OCSP requester trust anchor is unavailable"); }
                    });
                }
            }
            policy.principalMappings().forEach(mapping -> control.requirePrincipal(mapping.principalId()));
        });
        IssuerGeneration issuer = repository.issuer(value.issuerId()).orElseThrow();
        IssuerChainPath path = repository.chainPath(value.chainPathId()).orElseThrow();
        if (!issuer.authorityId().equals(value.authorityId()) || !path.authorityId().equals(value.authorityId())
                || !path.issuerId().equals(value.issuerId()) || !path.orderedCredentialIds().getFirst()
                        .equals(issuer.credentialId())) {
            throw new IllegalStateException("OCSP responder issuer/path binding differs");
        }
        try {
            X509Certificate issuerCertificate = certificate(issuer.credentialId());
            X509Certificate responderCertificate = certificate(value.responderCredentialId());
            try {
                responderCertificate.checkValidity(Date.from(clock.instant()));
            } catch (CertificateExpiredException | CertificateNotYetValidException failure) {
                throw new IllegalStateException("OCSP responder certificate is outside its validity interval");
            }
            if (value.signingMode() == SigningMode.ISSUER_SIGNED) {
                if (!value.responderCredentialId().equals(issuer.credentialId())
                        || !value.signingKeyRef().equals(issuer.signingKeyRef())) {
                    throw new IllegalStateException("Issuer-signed responder binding differs");
                }
            } else {
                boolean signatureValid;
                try {
                    responderCertificate.verify(issuerCertificate.getPublicKey());
                    signatureValid = true;
                } catch (GeneralSecurityException failure) {
                    signatureValid = false;
                }
                List<String> extendedKeyUsage;
                try {
                    extendedKeyUsage = responderCertificate.getExtendedKeyUsage();
                } catch (CertificateParsingException failure) {
                    extendedKeyUsage = null;
                }
                if (!signatureValid || extendedKeyUsage == null
                        || !extendedKeyUsage.contains(OID_KP_OCSP_SIGNING)) {
                    throw new IllegalStateException("Delegated OCSP responder certificate is unauthorized");
                }
                boolean[] keyUsage = responderCertificate.getKeyUsage();
                if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
                    throw new IllegalStateException("Delegated OCSP responder key usage is invalid");
                }
            }
        } catch (IllegalStateException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new IllegalStateException("OCSP responder certificate validation failed");
        }
        if (proveSigning) {
            try {
                signing.orElseThrow(() -> new IllegalStateException("OCSP signing service is unavailable"))
                        .validateSigningBinding(value.authorityId(), value.responderCredentialId(), value.signingKeyRef(),
                                value.signatureAlgorithm(), value.signatureBindingId());
            } catch (IllegalStateException failure) {
                throw failure;
            } catch (RuntimeException failure) {
                throw new IllegalStateException("OCSP signing capability proof failed");
            }
        }
    }

    private X509Certificate certificate(PkiId credentialId) throws IOException {
        try (zeroecho.pki.application.PkiRepositoryContent content = repository.openCredential(credentialId);
                java.io.InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(1_048_577);
            if (encoded.length == 1_048_577 || input.read() != -1) {
                throw new IOException("OCSP responder certificate exceeds its finite bound");
            }
            try {
                X509Certificate certificate = Pkix.parseCertificate(encoded);
                if (!java.util.Arrays.equals(encoded, certificate.getEncoded())) {
                    throw new IOException("OCSP responder certificate is not canonical DER");
                }
                return certificate;
            } catch (CertificateException | RuntimeException failure) {
                throw new IOException("OCSP responder certificate is invalid", failure);
            }
        }
    }

    private ServerControlStore.ProtocolRecord record(Responder value) {
        byte[] payload = encode(value);
        return new ServerControlStore.ProtocolRecord(ServerControlStore.OCSP_RESPONDER,
                value.responderId(), sha256(payload), payload);
    }

    private Responder decode(ServerControlStore.ProtocolRecord stored) {
        Responder value = decode(stored.payload());
        if (!stored.recordId().equals(value.responderId()) || !stored.commitment().equals(sha256(stored.payload()))) {
            throw new IllegalStateException("OCSP responder record commitment differs");
        }
        if (value.configurationCommitment().equals("0".repeat(64))) {
            throw new IllegalStateException("OCSP responder commitment is unsealed");
        }
        if (!value.configurationCommitment().equals(commitment(value, true))) {
            throw new IllegalStateException("OCSP responder commitment differs");
        }
        return value;
    }

    private static String commitment(Responder value, boolean ignoreStored) {
        return sha256(encode(value, ignoreStored));
    }

    /**
     * Returns a safe deterministic commitment to one request-authentication policy.
     *
     * @param value responder registration containing the policy
     * @return lowercase SHA-256 policy commitment
     */
    public static String requestPolicyCommitment(Registration value) {
        Objects.requireNonNull(value, "value");
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(512);
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(value.requestAuthenticationMode().code());
            output.writeBoolean(value.requesterTrustPolicy().isPresent());
            if (value.requesterTrustPolicy().isPresent()) writePolicy(output, value.requesterTrustPolicy().orElseThrow());
            output.flush(); return sha256(bytes.toByteArray());
        } catch (IOException impossible) {
            throw new IllegalStateException("OCSP requester policy encoding failed", impossible);
        }
    }

    private static byte[] encode(Responder value) { return encode(value, false); }
    private static byte[] encode(Responder value, boolean ignoreCommitment) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(1024);
                DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(2); write(output, value.responderId()); write(output, value.alias());
            write(output, value.realmId().value()); write(output, value.authorityId().value());
            write(output, value.issuerId().value()); output.writeInt(value.signingMode().code());
            write(output, value.responderCredentialId().value()); write(output, value.signingKeyRef().value());
            write(output, value.chainPathId().value()); write(output, value.signatureAlgorithm());
            output.writeBoolean(value.signatureBindingId().isPresent());
            if (value.signatureBindingId().isPresent()) write(output, value.signatureBindingId().orElseThrow());
            write(output, value.signatureBindingCommitment()); output.writeInt(value.responderIdForm().code());
            output.writeLong(value.responseValidity().toSeconds()); output.writeInt(value.noncePolicy().code());
            output.writeInt(value.maximumNonceBytes()); output.writeInt(value.acceptedHashes().size());
            for (OcspResponseService.CertIdHash hash : value.acceptedHashes().stream().sorted().toList()) {
                output.writeInt(hash.code());
            }
            output.writeInt(value.maximumRequestBytes()); output.writeInt(value.maximumEntries());
            output.writeLong(value.cacheLifetime().toSeconds());
            output.writeInt(value.requestAuthenticationMode().code());
            output.writeBoolean(value.requesterTrustPolicy().isPresent());
            if (value.requesterTrustPolicy().isPresent()) writePolicy(output, value.requesterTrustPolicy().orElseThrow());
            output.writeInt(value.state().code());
            output.writeLong(value.createdAt().toEpochMilli());
            write(output, ignoreCommitment ? "0".repeat(64) : value.configurationCommitment()); output.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) { throw new IllegalStateException("OCSP encoding failed", impossible); }
    }

    private static Responder decode(byte[] payload) {
        if (payload.length == 0 || payload.length > 65_536) throw new IllegalStateException("OCSP record bound differs");
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            if (input.readInt() != 2) throw new IOException("OCSP record schema is obsolete");
            String id = read(input); String alias = read(input); RealmId realm = new RealmId(read(input));
            PkiId authority = new PkiId(read(input)); PkiId issuer = new PkiId(read(input));
            SigningMode mode = SigningMode.fromCode(input.readInt()); PkiId credential = new PkiId(read(input));
            KeyRef key = new KeyRef(read(input)); PkiId path = new PkiId(read(input)); String algorithm = read(input);
            Optional<String> binding = input.readBoolean() ? Optional.of(read(input)) : Optional.empty();
            String bindingCommitment = read(input);
            OcspResponseService.ResponderId form = OcspResponseService.ResponderId.fromCode(input.readInt());
            Duration validity = Duration.ofSeconds(input.readLong()); NoncePolicy nonce = NoncePolicy.fromCode(input.readInt());
            int nonceBytes = input.readInt(); int count = input.readInt();
            if (count < 1 || count > 2) throw new IOException("OCSP hash count differs");
            Set<OcspResponseService.CertIdHash> hashes = new java.util.HashSet<>();
            for (int index = 0; index < count; index++) {
                hashes.add(OcspResponseService.CertIdHash.fromCode(input.readInt()));
            }
            int requestBytes = input.readInt(); int entries = input.readInt(); Duration cache = Duration.ofSeconds(input.readLong());
            RequestAuthenticationMode authenticationMode = RequestAuthenticationMode.fromCode(input.readInt());
            Optional<RequesterTrustPolicy> trustPolicy = input.readBoolean()
                    ? Optional.of(readPolicy(input)) : Optional.empty();
            State state = State.fromCode(input.readInt()); Instant created = Instant.ofEpochMilli(input.readLong());
            String commitment = read(input); if (input.read() != -1) throw new IOException("Trailing OCSP record data");
            return new Responder(id, alias, realm, authority, issuer, mode, credential, key, path, algorithm,
                    binding, bindingCommitment, form, validity, nonce, nonceBytes, hashes, requestBytes,
                    entries, cache, authenticationMode, trustPolicy, state, created, commitment);
        } catch (IOException | RuntimeException failure) {
            throw new IllegalStateException("OCSP responder record is invalid");
        }
    }

    private static void write(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (encoded.length > 16_384) throw new IOException("OCSP string bound differs");
        output.writeInt(encoded.length); output.write(encoded);
    }

    private static void writePolicy(DataOutputStream output, RequesterTrustPolicy policy) throws IOException {
        output.writeInt(policy.trustSelectors().size());
        for (TrustSelector selector : policy.trustSelectors()) {
            output.writeInt(selector.type().code()); output.writeInt(selector.identities().size());
            for (String identity : selector.identities().stream().sorted().toList()) write(output, identity);
        }
        output.writeInt(policy.principalMappings().size());
        for (PrincipalMapping mapping : policy.principalMappings().stream()
                .sorted(java.util.Comparator.comparing(PrincipalMapping::mappingId)).toList()) {
            write(output, mapping.mappingId()); write(output, mapping.principalId());
            output.writeInt(mapping.type().code()); write(output, mapping.commitment());
        }
        output.writeInt(policy.signatureBindings().size());
        for (RequestSignatureBinding binding : policy.signatureBindings().stream()
                .sorted(java.util.Comparator.comparing(RequestSignatureBinding::bindingId)).toList()) {
            write(output, binding.bindingId()); write(output, binding.commitment());
        }
        output.writeInt(policy.revocationPolicy().code()); output.writeInt(policy.maximumSignerCertificates());
        output.writeInt(policy.maximumSignerChainBytes());
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private static RequesterTrustPolicy readPolicy(DataInputStream input) throws IOException {
        int selectorCount = boundedCount(input.readInt(), 16, "trust selector");
        List<TrustSelector> selectors = new ArrayList<>(selectorCount);
        for (int index = 0; index < selectorCount; index++) {
            TrustSelectorType type = TrustSelectorType.fromCode(input.readInt());
            int identityCount = boundedCount(input.readInt(), 64, "trust identity");
            Set<String> identities = new java.util.HashSet<>();
            for (int identity = 0; identity < identityCount; identity++) {
                if (!identities.add(read(input))) throw new IOException("Duplicate OCSP trust identity");
            }
            selectors.add(new TrustSelector(type, identities));
        }
        int mappingCount = boundedCount(input.readInt(), 256, "principal mapping");
        List<PrincipalMapping> mappings = new ArrayList<>(mappingCount);
        for (int index = 0; index < mappingCount; index++) {
            mappings.add(new PrincipalMapping(read(input), read(input),
                    PrincipalMappingType.fromCode(input.readInt()), read(input)));
        }
        int bindingCount = boundedCount(input.readInt(), 16, "signature binding");
        List<RequestSignatureBinding> bindings = new ArrayList<>(bindingCount);
        for (int index = 0; index < bindingCount; index++) {
            bindings.add(new RequestSignatureBinding(read(input), read(input)));
        }
        return new RequesterTrustPolicy(selectors, mappings, bindings,
                RequesterRevocationPolicy.fromCode(input.readInt()), input.readInt(), input.readInt());
    }

    private static int boundedCount(int value, int maximum, String label) throws IOException {
        if (value < 1 || value > maximum) throw new IOException("OCSP " + label + " count differs");
        return value;
    }
    private static String read(DataInputStream input) throws IOException {
        int length = input.readInt(); if (length < 0 || length > 16_384) throw new IOException("OCSP string bound differs");
        byte[] encoded = input.readNBytes(length); if (encoded.length != length) throw new IOException("OCSP record is truncated");
        String value = new String(encoded, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(encoded, value.getBytes(StandardCharsets.UTF_8))) throw new IOException("OCSP UTF-8 differs");
        return value;
    }
    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("OCSP commitment is invalid");
    }
    private static void requirePolicyShape(RequestAuthenticationMode mode,
            Optional<RequesterTrustPolicy> policy) {
        if (mode == RequestAuthenticationMode.UNSIGNED_ONLY && policy.isPresent()
                || mode != RequestAuthenticationMode.UNSIGNED_ONLY && policy.isEmpty()) {
            throw new IllegalArgumentException("OCSP requester trust policy does not match authentication mode");
        }
    }
    private static void positive(Duration value, Duration maximum, String name) {
        if (value == null || value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException("OCSP " + name + " is invalid");
        }
    }
}
