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
package zeroecho.pki.server.acme;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.CredentialPublicationGate;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.server.jfr.AcmeChallengeEvent;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Transport-neutral durable ACME state machine and constrained PKI integration.
 *
 * <p>Account identity is protocol-scoped. No method accepts an administrative
 * principal or permission as issuance authority. Directory activation freezes
 * one exact authority, profile, issuer generation, chain path, provider set, and
 * profile-owned confirmation policy. External validators return evidence only.</p>
 */
@SuppressWarnings("PMD")
public final class AcmeService {
    private static final String ZERO = "0".repeat(64);
    private static final CredentialPublicationGate.AuditActor PUBLICATION_AUDIT_ACTOR =
            new CredentialPublicationGate.AuditActor("acme-service");
    private static final ThreadLocal<FinalizeFaultInjector> FINALIZE_FAULTS = new ThreadLocal<>();
    private final ServerRealmContext realm;
    private final AcmeControlStore store;
    private final Clock clock;
    private final SecureRandom random;
    private final Map<String, AcmeChallengeProvider> providers;
    private final Map<String, ProviderConfig> providerConfigurations;
    private final Map<String, AcmeExternalAccountBindingProvider> eabProviders;
    private final Map<String, ProviderConfig> eabProviderConfigurations;
    private final Runnable reconciliationWake;

    /**
     * Returns configured challenge-provider identities and supported challenge types without options.
     * @return immutable map of non-secret configured provider metadata
     */
    public Map<String, Set<AcmeState.ChallengeType>> configuredChallengeProviders() {
        Map<String, Set<AcmeState.ChallengeType>> result = new java.util.TreeMap<>();
        providers.forEach((id, provider) -> result.put(id, Set.copyOf(provider.challengeTypes())));
        return Map.copyOf(result);
    }

    /**
     * Returns explicitly configured external-account-binding provider identifiers without options.
     * @return immutable configured provider identifiers
     */
    public Set<String> configuredEabProviders() { return Set.copyOf(eabProviders.keySet()); }

    /**
     * Creates a realm-bound ACME service from explicitly enabled providers.
     *
     * @param realm realm context owning all ACME state
     * @param clock authoritative server clock
     * @param random cryptographically secure identifier source
     * @param providers explicitly enabled challenge providers keyed by identifier
     * @param providerConfigurations validated configuration for each challenge provider
     * @param eabProviders explicitly enabled external-account-binding providers
     * @param eabProviderConfigurations validated configuration for each EAB provider
     * @param reconciliationWake callback that promptly wakes durable signing reconciliation
     */
    public AcmeService(ServerRealmContext realm, Clock clock, SecureRandom random,
            Map<String, AcmeChallengeProvider> providers,
            Map<String, ProviderConfig> providerConfigurations,
            Map<String, AcmeExternalAccountBindingProvider> eabProviders,
            Map<String, ProviderConfig> eabProviderConfigurations, Runnable reconciliationWake) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.store = realm.acmeControl(); this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.providers = Map.copyOf(Objects.requireNonNull(providers, "providers"));
        this.providerConfigurations = Map.copyOf(Objects.requireNonNull(providerConfigurations,
                "providerConfigurations"));
        this.eabProviders = Map.copyOf(Objects.requireNonNull(eabProviders, "eabProviders"));
        this.eabProviderConfigurations = Map.copyOf(Objects.requireNonNull(eabProviderConfigurations,
                "eabProviderConfigurations"));
        this.reconciliationWake = Objects.requireNonNull(reconciliationWake, "reconciliationWake");
        if (!this.providers.keySet().equals(this.providerConfigurations.keySet())
                || this.providers.entrySet().stream().anyMatch(entry -> !entry.getKey().equals(entry.getValue().id()))) {
            throw new IllegalArgumentException("ACME provider composition is inconsistent");
        }
        if (!this.eabProviders.keySet().equals(this.eabProviderConfigurations.keySet())
                || this.eabProviders.entrySet().stream()
                        .anyMatch(entry -> !entry.getKey().equals(entry.getValue().id()))) {
            throw new IllegalArgumentException("ACME EAB provider composition is inconsistent");
        }
        validateRecoveredState();
    }

    /**
     * Creates a realm-bound ACME service with periodic-only reconciliation compatibility.
     *
     * @param realm realm context owning all ACME state
     * @param clock authoritative server clock
     * @param random cryptographically secure identifier source
     * @param providers explicitly enabled challenge providers keyed by identifier
     * @param providerConfigurations validated configuration for each challenge provider
     * @param eabProviders explicitly enabled external-account-binding providers
     * @param eabProviderConfigurations validated configuration for each EAB provider
     */
    public AcmeService(ServerRealmContext realm, Clock clock, SecureRandom random,
            Map<String, AcmeChallengeProvider> providers,
            Map<String, ProviderConfig> providerConfigurations,
            Map<String, AcmeExternalAccountBindingProvider> eabProviders,
            Map<String, ProviderConfig> eabProviderConfigurations) {
        this(realm, clock, random, providers, providerConfigurations, eabProviders, eabProviderConfigurations,
                () -> { });
    }

    /**
     * Creates an ACME service without EAB providers.
     *
     * @param realm realm context owning all ACME state
     * @param clock authoritative server clock
     * @param random cryptographically secure identifier source
     * @param providers explicitly enabled challenge providers keyed by identifier
     * @param providerConfigurations validated configuration for each challenge provider
     */
    public AcmeService(ServerRealmContext realm, Clock clock, SecureRandom random,
            Map<String, AcmeChallengeProvider> providers,
            Map<String, ProviderConfig> providerConfigurations) {
        this(realm, clock, random, providers, providerConfigurations, Map.of(), Map.of());
    }

    private void validateRecoveredState() {
        int offset = 0;
        do {
            ServerControlStore.Page<AcmeState.Directory> page = store.page(AcmeState.Directory.class, offset, 256);
            for (AcmeState.Directory directory : page.values()) {
                validateFrozenDirectory(directory);
            }
            if (!page.hasMore()) {
                return;
            }
            offset = page.nextOffset();
        } while (true);
    }

    /**
     * Safe immutable directory-registration input.
     *
     * @param alias unique public directory alias
     * @param authorityId exact logical authority identifier
     * @param profileId active end-entity profile identifier
     * @param enrollmentProfileId mandatory enrollment admission policy identity
     * @param dnsNamespaces permitted DNS namespace suffixes
     * @param maximumValidity maximum issued credential validity
     * @param publicKeyAlgorithms accepted public-key algorithm identifiers
     * @param x509BindingPolicies accepted X.509 binding-policy identifiers
     * @param challengeTypes enabled challenge types
     * @param challengeProviderIds enabled challenge-provider identifiers
     * @param eabProviderId optional external-account-binding provider
     * @param eabRequired whether external account binding is mandatory
     */
    public record DirectoryRegistration(String alias, PkiId authorityId, String profileId, String enrollmentProfileId,
            Set<String> dnsNamespaces, Duration maximumValidity, Set<String> publicKeyAlgorithms,
            Set<String> x509BindingPolicies, Set<AcmeState.ChallengeType> challengeTypes,
            Set<String> challengeProviderIds, Optional<String> eabProviderId, boolean eabRequired) {
        /** Validates required registration input before PKI resolution. */
        public DirectoryRegistration {
            Objects.requireNonNull(alias, "alias"); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profileId, "profileId"); dnsNamespaces = Set.copyOf(dnsNamespaces);
            zeroecho.pki.server.enrollment.EnrollmentEndpoint.requireProfileId(enrollmentProfileId);
            Objects.requireNonNull(maximumValidity, "maximumValidity");
            publicKeyAlgorithms = Set.copyOf(publicKeyAlgorithms); x509BindingPolicies = Set.copyOf(x509BindingPolicies);
            challengeTypes = Set.copyOf(challengeTypes); challengeProviderIds = Set.copyOf(challengeProviderIds);
            eabProviderId = Objects.requireNonNull(eabProviderId, "eabProviderId");
        }
    }

    /**
     * Resolves the active profile precondition that must be bound into approval.
     *
     * @param registration validated directory registration input
     * @return authoritative profile and policy precondition
     */
    public ServerControlOperation.AcmeDirectoryProfilePrecondition resolveDirectoryProfilePrecondition(
            DirectoryRegistration registration) {
        DirectoryRegistration exact = Objects.requireNonNull(registration, "registration");
        ActiveCertificateProfile active = realm.session().profiles().requireActiveProfile(exact.profileId());
        if (active.definition().certificateType() != CertificateProfileKind.END_ENTITY) {
            throw new IllegalArgumentException("ACME profile must be an active end-entity profile");
        }
        CredentialConfirmationPolicy confirmation = active.definition().confirmationPolicy()
                .orElseThrow(() -> new IllegalArgumentException("ACME profile confirmation policy is unavailable"));
        return new ServerControlOperation.AcmeDirectoryProfilePrecondition(active.reference(),
                confirmation.configurationCommitment());
    }

    /**
     * Registers one immutable inactive directory revision from an approval-bound profile precondition.
     *
     * @param registration validated directory registration input
     * @param profilePrecondition approval-bound authoritative profile precondition
     * @return durably registered inactive directory revision
     */
    public synchronized AcmeState.Directory registerDirectory(DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition) {
        Objects.requireNonNull(registration, "registration");
        ServerControlOperation.AcmeDirectoryProfilePrecondition expected =
                Objects.requireNonNull(profilePrecondition, "profilePrecondition");
        requireExposed(registration.authorityId());
        PkiSession session = realm.session();
        CaRecord authority = session.repository().authority(registration.authorityId())
                .orElseThrow(() -> new IllegalArgumentException("ACME authority is unavailable"));
        requireActiveAuthority(authority);
        ActiveCertificateProfile profile = session.profiles().requireActiveProfile(registration.profileId());
        CredentialConfirmationPolicy confirmationPolicy = profile.definition().confirmationPolicy()
                .orElseThrow(() -> new IllegalArgumentException("ACME profile confirmation policy is unavailable"));
        if (!profile.reference().equals(expected.expectedProfile())
                || !confirmationPolicy.configurationCommitment()
                        .equals(expected.expectedPolicyCommitment())) {
            throw new IllegalStateException("ACME approval-bound profile precondition changed");
        }
        if (profile.definition().certificateType() != CertificateProfileKind.END_ENTITY
                || registration.maximumValidity().compareTo(profile.definition().maximumValidity()) > 0) {
            throw new IllegalArgumentException("ACME profile or validity policy is invalid");
        }
        if (!registration.publicKeyAlgorithms().equals(
                profile.definition().leafPolicy().allowedSubjectKeyAlgorithmIds())
                || !registration.x509BindingPolicies().equals(bindingPolicy(profile))) {
            throw new IllegalArgumentException("ACME algorithm policy must exactly match the active profile");
        }
        IssuerChainPath path = requireCurrentPath(authority);
        requireProviders(registration.challengeTypes(), registration.challengeProviderIds());
        if (registration.eabRequired() && registration.eabProviderId().isEmpty()) {
            throw new IllegalArgumentException("ACME EAB policy is contradictory");
        }
        registration.eabProviderId().ifPresent(value -> {
            if (!eabProviders.containsKey(value)) throw new IllegalArgumentException("ACME EAB provider is unavailable");
        });
        int revision = nextDirectoryRevision(registration.alias());
        String directoryId = "directory:" + registration.alias() + ":r" + revision;
        String policy = directoryPolicyCommitment(registration, profile, confirmationPolicy, authority, path);
        AcmeState.Directory unsealed = new AcmeState.Directory(directoryId, registration.alias(), revision,
                realm.configuration().realmId(), authority.caId(), profile.reference(), registration.enrollmentProfileId(),
                authority.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment(),
                Set.of(AcmeState.IdentifierType.DNS), registration.dnsNamespaces(),
                registration.maximumValidity(), registration.publicKeyAlgorithms(),
                registration.x509BindingPolicies(), registration.challengeTypes(),
                registration.challengeProviderIds(), registration.eabProviderId(), registration.eabRequired(),
                confirmationPolicy, confirmationPolicy.configurationCommitment(),
                AcmeState.DirectoryStatus.INACTIVE, policy, clock.instant(), ZERO);
        return store.create(unsealed);
    }

    /**
     * Registers directly after resolving the same exact active-profile precondition.
     *
     * @param registration validated directory registration input
     * @return durably registered inactive directory revision
     */
    public synchronized AcmeState.Directory registerDirectory(DirectoryRegistration registration) {
        return registerDirectory(registration, resolveDirectoryProfilePrecondition(registration));
    }

    /**
     * Activates one exact directory revision after revalidating all frozen PKI authority.
     *
     * @param directoryId stable directory identifier
     * @return active directory revision
     */
    public synchronized AcmeState.Directory activateDirectory(String directoryId) {
        AcmeState.Directory current = requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.ACTIVE) return current;
        validateFrozenDirectory(current);
        requireAdmissionCapabilities(current);
        for (AcmeState.Directory other : directoriesForAlias(current.alias())) {
            if (other.status() == AcmeState.DirectoryStatus.ACTIVE) {
                throw new IllegalStateException("Another ACME directory revision is active");
            }
        }
        AcmeState.Directory updated = copyDirectory(current, AcmeState.DirectoryStatus.ACTIVE);
        return (AcmeState.Directory) store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /**
     * Deactivates new account/order admission while existing unexpired orders remain usable.
     *
     * @param directoryId stable directory identifier
     * @return inactive directory revision
     */
    public synchronized AcmeState.Directory deactivateDirectory(String directoryId) {
        AcmeState.Directory current = requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.INACTIVE) return current;
        AcmeState.Directory updated = copyDirectory(current, AcmeState.DirectoryStatus.INACTIVE);
        return (AcmeState.Directory) store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /**
     * Resolves the sole active directory revision for one public alias.
     *
     * @param alias public directory alias
     * @return sole active directory revision
     */
    public AcmeState.Directory activeDirectory(String alias) {
        List<AcmeState.Directory> active = directoriesForAlias(alias).stream()
                .filter(value -> value.status() == AcmeState.DirectoryStatus.ACTIVE).toList();
        if (active.size() != 1) throw new IllegalArgumentException("ACME directory is unavailable");
        return active.get(0);
    }

    /**
     * Returns the canonical nonce scope for one known directory alias.
     *
     * @param alias public directory alias
     * @return canonical nonce scope
     */
    public String nonceScope(String alias) {
        List<AcmeState.Directory> known = directoriesForAlias(alias);
        if (known.isEmpty()) {
            throw new IllegalArgumentException("ACME directory alias is unavailable");
        }
        return known.get(0).alias();
    }

    /**
     * Returns one exact directory revision for administrative and protocol inspection.
     *
     * @param directoryId stable directory identifier
     * @return exact directory revision
     */
    public AcmeState.Directory directory(String directoryId) { return requireDirectory(directoryId); }

    /**
     * Resolves the exact frozen directory for one existing account resource.
     *
     * @param accountId stable account identifier
     * @return account's frozen directory revision
     */
    public AcmeState.Directory accountDirectory(String accountId) {
        return requireDirectory(requireAccount(accountId).directoryId());
    }

    /**
     * Resolves the exact frozen directory for one existing order resource.
     *
     * @param orderId stable order identifier
     * @return order's frozen directory revision
     */
    public AcmeState.Directory orderDirectory(String orderId) {
        return requireDirectory(requireOrder(orderId).directoryId());
    }

    /**
     * Resolves the exact frozen directory for one existing authorization resource.
     *
     * @param authorizationId stable authorization identifier
     * @return authorization's frozen directory revision
     */
    public AcmeState.Directory authorizationDirectory(String authorizationId) {
        AcmeState.Authorization authorization = requireAuthorization(authorizationId);
        return orderDirectory(authorization.orderId());
    }

    /**
     * Resolves the exact frozen directory for one existing challenge resource.
     *
     * @param challengeId stable challenge identifier
     * @return challenge's frozen directory revision
     */
    public AcmeState.Directory challengeDirectory(String challengeId) {
        AcmeState.Challenge challenge = requireChallenge(challengeId);
        return authorizationDirectory(challenge.authorizationId());
    }

    /**
     * Returns a deterministic bounded page of directory revisions.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return deterministic bounded directory page
     */
    public ServerControlStore.Page<AcmeState.Directory> directories(int offset, int limit) {
        return store.page(AcmeState.Directory.class, offset, limit);
    }

    /**
     * Creates or returns an account under one exact active directory.
     *
     * @param directory exact frozen directory revision
     * @param keyThumbprint authenticated account-key thumbprint
     * @param publicKeySpki canonical subject-public-key information
     * @param contacts bounded account contact URIs
     * @param termsAgreed whether current terms were accepted
     * @param eabPolicyCommitment optional external-account-binding policy commitment
     * @param onlyReturnExisting whether account creation must be refused
     * @return existing or newly created account
     */
    public synchronized AcmeState.Account createAccount(AcmeState.Directory directory, String keyThumbprint,
            byte[] publicKeySpki, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, boolean onlyReturnExisting) {
        requireActiveAdmission(directory);
        Optional<AcmeState.Account> existing = accountByThumbprint(directory.directoryId(), keyThumbprint);
        if (existing.isPresent()) return existing.orElseThrow();
        if (onlyReturnExisting) throw new IllegalArgumentException("ACME account does not exist");
        if (directory.eabRequired() && eabPolicyCommitment.isEmpty()) {
            throw new IllegalArgumentException("ACME external account binding is required");
        }
        Instant now = clock.instant();
        AcmeState.Account account = new AcmeState.Account(id("account"), directory.directoryId(),
                directory.revision(), directory.policyCommitment(), keyThumbprint, publicKeySpki,
                AcmeState.AccountStatus.VALID, contacts, termsAgreed, eabPolicyCommitment, now, now, ZERO);
        AcmeState.Account created = enrollment().storeAcmeAccount(Optional.empty(), account);
        audit("ACME_ACCOUNT_CREATED", created.accountId(), Map.of("directory", created.directoryId()));
        return created;
    }

    /**
     * Resolves an account by its authenticated key identity within one directory.
     *
     * @param directoryId stable directory identifier
     * @param keyThumbprint authenticated account-key thumbprint
     * @return matching account, or empty when unknown
     */
    public Optional<AcmeState.Account> accountByKey(String directoryId, String keyThumbprint) {
        return accountByThumbprint(directoryId, keyThumbprint);
    }

    /**
     * Verifies EAB inside its explicit secret-confining provider and returns only a safe commitment.
     *
     * @param directory exact frozen directory revision
     * @param keyThumbprint authenticated account-key thumbprint
     * @param nestedJws optional nested EAB JWS document
     * @return safe policy commitment, or empty when EAB is unused
     */
    public Optional<String> verifyExternalAccountBinding(AcmeState.Directory directory, String keyThumbprint,
            Optional<byte[]> nestedJws) {
        Objects.requireNonNull(nestedJws, "nestedJws");
        if (directory.eabProviderId().isEmpty()) {
            if (nestedJws.isPresent()) throw new IllegalArgumentException("ACME EAB is not enabled");
            return Optional.empty();
        }
        if (nestedJws.isEmpty()) {
            if (directory.eabRequired()) {
                throw new IllegalArgumentException("ACME EAB is required");
            }
            return Optional.empty();
        }
        byte[] document = nestedJws.orElseThrow();
        String providerId = directory.eabProviderId().orElseThrow();
        AcmeExternalAccountBindingProvider provider = Optional.ofNullable(eabProviders.get(providerId))
                .orElseThrow(() -> new IllegalStateException("ACME EAB provider is unavailable"));
        AcmeExternalAccountBindingProvider.Binding binding = provider.verify(
                new AcmeExternalAccountBindingProvider.Request(directory.directoryId(), directory.authorityId(),
                        directory.profile().profileId(), keyThumbprint, document, clock.instant()),
                eabProviderConfigurations.get(providerId));
        if (!binding.consumed() || !binding.expiresAt().isAfter(clock.instant())
                || !binding.dnsNamespaces().containsAll(directory.dnsNamespaces())) {
            throw new SecurityException("ACME EAB policy is unavailable");
        }
        return Optional.of(binding.policyCommitment());
    }

    /**
     * Resolves one active account key for strict KID authentication.
     *
     * @param accountId stable account identifier
     * @param kid exact account key identifier
     * @return validated account key and record commitment
     */
    public AcmeJwsVerifier.AccountKey accountKey(String accountId, String kid) {
        AcmeState.Account account = requireAccount(accountId);
        if (account.status() != AcmeState.AccountStatus.VALID) throw new IllegalArgumentException("ACME account unavailable");
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(account.publicKeySpki()));
            return new AcmeJwsVerifier.AccountKey(account.accountId(), kid, account.keyThumbprint(), key,
                    account.commitment());
        } catch (Exception failure) {
            throw new IllegalStateException("ACME account key is invalid");
        }
    }

    /**
     * Returns one account record without exposing contact data through transport automatically.
     *
     * @param accountId stable account identifier
     * @return exact account record
     */
    public AcmeState.Account account(String accountId) { return requireAccount(accountId); }

    /**
     * Durably changes account status while preserving its key and history commitment.
     *
     * @param accountId stable account identifier
     * @return durably deactivated account
     */
    public synchronized AcmeState.Account deactivateAccount(String accountId) {
        return deactivateAccount(requireAccount(accountId));
    }

    /**
     * Durably changes account status after exact account-key authority revalidation.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @return durably deactivated account
     */
    public synchronized AcmeState.Account deactivateAccount(String accountId, String expectedCommitment) {
        return deactivateAccount(requireAuthenticatedAccount(accountId, expectedCommitment));
    }

    private AcmeState.Account deactivateAccount(AcmeState.Account current) {
        if (current.status() == AcmeState.AccountStatus.DEACTIVATED) return current;
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), AcmeState.AccountStatus.DEACTIVATED, current.contacts(),
                current.termsAgreed(), current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account deactivated = enrollment().storeAcmeAccount(Optional.of(current), updated);
        audit("ACME_ACCOUNT_DEACTIVATED", current.accountId(), Map.of("directory", current.directoryId()));
        return deactivated;
    }

    /**
     * Atomically replaces bounded account contact metadata without changing key authority.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @param contacts bounded account contact URIs
     * @return durably updated account
     */
    public synchronized AcmeState.Account updateAccountContacts(String accountId, String expectedCommitment,
            List<String> contacts) {
        AcmeState.Account current = requireAuthenticatedAccount(accountId, expectedCommitment);
        if (current.status() != AcmeState.AccountStatus.VALID) {
            throw new IllegalStateException("ACME account is unavailable");
        }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), current.status(), contacts, current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account replaced = enrollment().storeAcmeAccount(Optional.of(current), updated);
        audit("ACME_ACCOUNT_CONTACT_UPDATED", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /**
     * Atomically replaces one account key after exact old-record authentication.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @param replacementThumbprint replacement account-key thumbprint
     * @param replacementSpki canonical replacement public key
     * @return account with the replacement key
     */
    public synchronized AcmeState.Account rolloverAccount(String accountId, String expectedCommitment,
            String replacementThumbprint, byte[] replacementSpki) {
        AcmeState.Account current = requireAccount(accountId);
        if (current.status() != AcmeState.AccountStatus.VALID
                || !current.commitment().equals(expectedCommitment)
                || current.keyThumbprint().equals(replacementThumbprint)
                || accountByThumbprint(current.directoryId(), replacementThumbprint).isPresent()) {
            throw new SecurityException("ACME account key rollover is unavailable");
        }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), replacementThumbprint,
                replacementSpki, current.status(), current.contacts(), current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account replaced = enrollment().storeAcmeAccount(Optional.of(current), updated);
        audit("ACME_ACCOUNT_KEY_ROLLOVER", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /**
     * Returns a deterministic bounded page of accounts for administrative inspection.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return deterministic bounded account page
     */
    public ServerControlStore.Page<AcmeState.Account> accounts(int offset, int limit) {
        return store.page(AcmeState.Account.class, offset, limit);
    }

    /**
     * Atomically creates one account-owned order, authorization, and challenge graph.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param directory exact frozen directory revision
     * @param requested requested certificate identifiers
     * @param notBefore optional requested validity start
     * @param notAfter optional requested validity end
     * @param orderLifetime positive order lifetime
     * @return durably created order
     */
    public synchronized AcmeState.Order createOrder(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory,
            List<AcmeState.Identifier> requested, Optional<Instant> notBefore, Optional<Instant> notAfter,
            Duration orderLifetime) {
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        requireAccountDirectory(account, directory);
        requireActiveAdmission(directory);
        List<AcmeState.Identifier> identifiers = canonicalIdentifiers(requested, directory);
        Instant now = clock.instant(); Instant expires = now.plus(orderLifetime);
        List<AcmeState.Authorization> authorizations = new ArrayList<>();
        List<AcmeState.Challenge> challenges = new ArrayList<>();
        for (AcmeState.Identifier identifier : identifiers) {
            String authorizationId = id("authorization"); List<String> challengeIds = new ArrayList<>();
            for (AcmeState.ChallengeType type : directory.challengeTypes().stream().sorted().toList()) {
                if (identifier.wildcard() && type != AcmeState.ChallengeType.DNS_01) continue;
                String provider = providerFor(directory, type); String challengeId = id("challenge");
                challengeIds.add(challengeId);
                challenges.add(new AcmeState.Challenge(challengeId, authorizationId, type, token(),
                        AcmeState.ChallengeStatus.PENDING, provider, 0, Optional.empty(), Optional.empty(), now, now, ZERO));
            }
            if (challengeIds.isEmpty()) throw new IllegalArgumentException("No ACME challenge supports an identifier");
            authorizations.add(new AcmeState.Authorization(authorizationId, "order-pending", accountId, identifier,
                    AcmeState.AuthorizationStatus.PENDING, challengeIds, expires, Optional.empty(), ZERO));
        }
        String orderId = id("order");
        authorizations = authorizations.stream().map(value -> new AcmeState.Authorization(value.authorizationId(),
                orderId, value.accountId(), value.identifier(), value.status(), value.challengeIds(), value.expiresAt(),
                value.evidenceId(), ZERO)).toList();
        AcmeState.Order order = new AcmeState.Order(orderId, accountId, directory.directoryId(), directory.revision(),
                directory.policyCommitment(), directory.authorityId(), directory.profile(), directory.issuerId(),
                directory.issuancePathId(), directory.issuancePathCommitment(), identifiers, notBefore, notAfter,
                AcmeState.OrderStatus.PENDING, authorizations.stream().map(AcmeState.Authorization::authorizationId).toList(),
                Optional.empty(), Optional.empty(), Optional.empty(), now, expires, ZERO);
        AcmeState.Order created = store.createOrderGraph(order, authorizations, challenges).order();
        audit("ACME_ORDER_CREATED", accountId, Map.of("order", created.orderId(),
                "directory", created.directoryId()));
        return created;
    }

    /**
     * Counts pending nonterminal orders up to a caller-supplied finite bound.
     *
     * @param accountId stable account identifier
     * @param stopAt positive early-stop bound
     * @return number of pending orders, capped by the supplied bound
     */
    public int pendingOrderCount(String accountId, int stopAt) {
        if (stopAt <= 0) throw new IllegalArgumentException("ACME pending-order bound is invalid");
        int offset = 0; int count = 0;
        while (true) {
            ServerControlStore.Page<AcmeState.Order> page = store.page(AcmeState.Order.class, offset, 256);
            for (AcmeState.Order order : page.values()) {
                if (order.accountId().equals(accountId) && order.status() != AcmeState.OrderStatus.VALID
                        && order.status() != AcmeState.OrderStatus.INVALID && ++count >= stopAt) return count;
            }
            if (!page.hasMore()) return count;
            offset = page.nextOffset();
        }
    }

    /**
     * Revokes one certificate issued to the authenticated account through the bound directory.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param directory exact frozen directory revision
     * @param certificateDer canonical certificate DER
     * @param reason permanent revocation reason
     * @param requestId stable request correlation identifier
     * @return committed revocation record
     */
    public synchronized RevocationRecord revokeCertificate(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory, byte[] certificateDer, RevocationReason reason, String requestId) {
        Objects.requireNonNull(certificateDer, "certificateDer"); Objects.requireNonNull(reason, "reason");
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        String digest = digestBytes(certificateDer); AcmeState.Order owning = null; int offset = 0;
        while (owning == null) {
            ServerControlStore.Page<AcmeState.Order> page = store.page(AcmeState.Order.class, offset, 256);
            for (AcmeState.Order order : page.values()) {
                if (order.accountId().equals(accountId) && order.directoryId().equals(directory.directoryId())
                        && order.status() == AcmeState.OrderStatus.VALID && order.credentialId().isPresent()) {
                    zeroecho.pki.api.credential.Credential credential = realm.session().repository()
                            .credential(order.credentialId().orElseThrow()).orElseThrow();
                    if (credential.content().sha256().equals(digest)) { owning = order; break; }
                }
            }
            if (owning != null || !page.hasMore()) break;
            offset = page.nextOffset();
        }
        if (owning == null) throw new SecurityException("ACME certificate is unavailable");
        PkiId credentialId = owning.credentialId().orElseThrow();
        validatePublicationCorrelation(account, owning, directory, credentialId);
        PkiOperation.RevokeCredential operation = new PkiOperation.RevokeCredential(credentialId, reason);
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.acme(accountId,
                realm.configuration().realmId().value(), requestId);
        PkiOperationOutcome outcome = RevocationEvidenceExecutor.require(realm.session().operations())
                .executeRevocation(operation, evidence, CancellationSignal.NONE);
        if (!(outcome instanceof PkiOperationOutcome.Completed)) {
            throw new IllegalStateException("ACME revocation did not commit");
        }
        signalReconciliation();
        RevocationRecord revoked = realm.session().revocations().get(credentialId)
                .orElseThrow(() -> new IllegalStateException("Committed ACME revocation is unavailable"));
        audit("ACME_CERTIFICATE_REVOKED", accountId, Map.of("order", owning.orderId()));
        return revoked;
    }

    /**
     * Claims and performs one explicit challenge validation attempt.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param challengeId stable challenge identifier
     * @param accountKeyThumbprint authenticated account-key thumbprint
     * @param deadline absolute validation deadline
     * @param cancellation cooperative cancellation signal
     * @return durably completed challenge attempt
     */
    public AcmeState.Challenge validateChallenge(String accountId, String expectedAccountCommitment,
            String challengeId, String accountKeyThumbprint, Instant deadline, CancellationSignal cancellation) {
        AcmeState.Challenge current; AcmeState.Authorization authorization;
        synchronized (this) {
            requireAuthenticatedAccount(accountId, expectedAccountCommitment);
            current = requireChallenge(challengeId); authorization = requireAuthorization(current.authorizationId());
            if (!authorization.accountId().equals(accountId)) throw new IllegalArgumentException("ACME challenge unavailable");
            if (current.status() == AcmeState.ChallengeStatus.VALID) return current;
            if (current.status() == AcmeState.ChallengeStatus.PROCESSING) throw new IllegalStateException("ACME challenge is processing");
            current = (AcmeState.Challenge) store.replace(List.of(new AcmeControlStore.Replacement(current,
                    new AcmeState.Challenge(current.challengeId(), current.authorizationId(), current.type(),
                            current.token(), AcmeState.ChallengeStatus.PROCESSING, current.providerId(),
                            Math.addExact(current.attempt(), 1), Optional.empty(), Optional.empty(),
                            current.createdAt(), clock.instant(), ZERO)))).get(0);
        }
        AcmeState.Order order = requireOrder(authorization.orderId());
        AcmeState.Directory directory = requireDirectory(order.directoryId());
        validateFrozenOrder(order, directory);
        String keyAuthorization = current.token() + "." + accountKeyAuthorizationThumbprint(accountKeyThumbprint);
        AcmeChallengeProvider provider = providers.get(current.providerId());
        AcmeChallengeEvent jfrChallenge = new AcmeChallengeEvent();
        jfrChallenge.challengeType = current.type().name();
        jfrChallenge.identifier = authorization.identifier().value();
        jfrChallenge.begin();
        AcmeChallengeProvider.Result result = null;
        try {
            result = provider.validate(new AcmeChallengeProvider.Context(directory.directoryId(),
                    authorization.authorizationId(), authorization.identifier(), current.type(), current.token(),
                    keyAuthorization, current.attempt(), clock.instant(), deadline),
                    providerConfigurations.get(provider.id()), cancellation);
        } catch (RuntimeException failure) {
            result = new AcmeChallengeProvider.Result(false, "PROVIDER_FAILURE", clock.instant(), clock.instant().plus(Duration.ofMinutes(5)));
        } finally {
            if (jfrChallenge.shouldCommit() && result != null) {
                jfrChallenge.succeeded = result.valid();
                if (!result.valid()) {
                    jfrChallenge.failureReason = result.classification();
                }
                jfrChallenge.commit();
            }
        }
        if (cancellation.isCancelled()) throw new IllegalStateException("ACME validation was cancelled");
        return completeChallenge(current, authorization, order, directory, accountId, expectedAccountCommitment,
                accountKeyThumbprint, keyAuthorization, result);
    }

    /**
     * Finalizes a ready order through the existing strict CSR and issuance services.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @param csrDer canonical PKCS#10 request DER
     * @return current durable order after finalization processing
     */
    public synchronized AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer) {
        return finalizeOrder(accountId, expectedAccountCommitment, orderId, csrDer, CancellationSignal.NONE);
    }

    /**
     * Finalizes a ready order while propagating transport cancellation into signing.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @param csrDer canonical PKCS#10 request DER
     * @param cancellation cooperative cancellation signal
     * @return current durable order after finalization processing
     */
    public synchronized AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, "cancellation");
        byte[] frozenCsr = Objects.requireNonNull(csrDer, "csrDer").clone();
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = requireOrder(orderId);
        if (!order.accountId().equals(accountId)) throw new IllegalArgumentException("ACME order unavailable");
        if (order.status() != AcmeState.OrderStatus.READY && order.status() != AcmeState.OrderStatus.PROCESSING
                && order.status() != AcmeState.OrderStatus.VALID) throw new IllegalStateException("ACME order is not ready");
        AcmeState.Directory directory = requireDirectory(order.directoryId());
        validateFrozenOrder(order, directory);
        CertificationRequestService requests = realm.session().requests().orElseThrow();
        ParsedCertificationRequest parsed = requests.parseX509(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, frozenCsr));
        requireExactIdentifiers(parsed, order.identifiers());
        try { cancellation.throwIfCancelled(); }
        catch (java.io.InterruptedIOException cancelled) { throw new PkiException("ACME finalization was cancelled"); }
        Optional<EnrollmentTransaction> existing = enrollmentFor(order, directory);
        EnrollmentTransaction transaction;
        if (existing.isPresent()) {
            transaction = existing.orElseThrow();
            if (!transaction.intent().requestSha256().equals(digestBytes(frozenCsr))) throw new IllegalStateException("ACME finalized request differs");
        } else {
            if (order.issuanceCommitment().isPresent() || order.status() != AcmeState.OrderStatus.READY
                    || !order.expiresAt().isAfter(clock.instant())) throw new IllegalStateException("ACME enrollment reference is unavailable");
            requireActiveAdmission(directory);
            zeroecho.pkix.PublicKeyIdentity key = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(account.publicKeySpki());
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT,
                    account.accountId(), IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS, Optional.empty(),
                    Optional.of(key.canonicalSha256()), key.equivalentSubjectPublicKeyInfoSha256(),
                    new EnrollmentIdentityAliases.Snapshot(realm.configuration().realmId(), Set.of()));
            transaction = enrollment().admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.ACME, directory.directoryId(),
                    requester, digest(order.orderId()), EnrollmentTransaction.Operation.ISSUE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, frozenCsr), orderValidity(order), Optional.empty(), Optional.of(order.expiresAt())));
        }
        requireEnrollmentBinding(order, directory, transaction);
        return continueEnrollment(order, directory, account, transaction, cancellation);
    }

    /**
     * Polls an account-owned order using the exact current authentication snapshot.
     * Pending approvals remain processing; approved retained requests may dispatch.
     * @param accountId stable account identifier
     * @param expectedAccountCommitment current account commitment verified by JWS authentication
     * @param orderId stable order identifier
     * @return account-owned order after durable continuation
     */
    public synchronized AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId) {
        return order(accountId, expectedAccountCommitment, orderId, CancellationSignal.NONE);
    }

    /**
     * Continues an authenticated order with cancellation before durable admission.
     * @param accountId stable account identifier
     * @param expectedAccountCommitment current JWS-authenticated account commitment
     * @param orderId stable order identifier
     * @param cancellation transport cancellation signal
     * @return account-owned order after durable continuation
     */
    public synchronized AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId,
            CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, "cancellation");
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = requireOrder(orderId);
        if (!order.accountId().equals(accountId)) throw new IllegalArgumentException("ACME order unavailable");
        if (order.status() != AcmeState.OrderStatus.READY && order.status() != AcmeState.OrderStatus.PROCESSING
                && order.status() != AcmeState.OrderStatus.VALID) return order;
        AcmeState.Directory directory = requireDirectory(order.directoryId());
        Optional<EnrollmentTransaction> transaction = enrollmentFor(order, directory);
        if (transaction.isEmpty()) {
            if (order.issuanceCommitment().isPresent()) throw new IllegalStateException("ACME enrollment reference is unavailable");
            return order;
        }
        requireEnrollmentBinding(order, directory, transaction.orElseThrow());
        return continueEnrollment(order, directory, account, transaction.orElseThrow(), cancellation);
    }

    private EnrollmentCoordinator enrollment() {
        return realm.enrollmentCoordinator().orElseThrow(() -> new IllegalStateException("ACME enrollment coordinator is unavailable"));
    }

    private Optional<EnrollmentTransaction> enrollmentFor(AcmeState.Order order, AcmeState.Directory directory) {
        return enrollment().find(EnrollmentTransaction.Protocol.ACME, directory.alias(), IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT,
                order.accountId(), digest(order.orderId()), EnrollmentTransaction.Operation.ISSUE);
    }

    private static Optional<Validity> orderValidity(AcmeState.Order order) {
        return order.notBefore().map(start -> new Validity(start, order.notAfter().orElseThrow()));
    }

    private void requireEnrollmentBinding(AcmeState.Order order, AcmeState.Directory directory, EnrollmentTransaction transaction) {
        validateFrozenOrder(order, directory);
        EnrollmentTransaction.Intent intent = transaction.intent();
        EnrollmentTransaction.Source source = intent.source();
        if (!intent.realmId().equals(realm.configuration().realmId()) || source.protocol() != EnrollmentTransaction.Protocol.ACME
                || !source.label().equals(directory.alias()) || !source.recordId().equals(order.directoryId())
                || source.revision() != order.directoryRevision() || !source.commitment().equals(admittedDirectoryCommitment(directory))
                || !source.enrollmentProfileId().equals(directory.enrollmentProfileId())
                || intent.operation() != EnrollmentTransaction.Operation.ISSUE || !intent.transactionId().equals(digest(order.orderId()))
                || intent.requester().type() != IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT || !intent.requester().actorId().equals(order.accountId())
                || !intent.authorityId().equals(order.authorityId()) || !intent.profile().equals(order.profile())
                || !intent.issuerId().equals(order.issuerId()) || !intent.pathId().equals(order.issuancePathId())
                || !intent.pathCommitment().equals(order.issuancePathCommitment()) || !intent.validity().equals(orderValidity(order))
                || intent.requestKind() != X509EnrollmentPayload.Kind.PKCS10 || intent.expiresAt().isAfter(order.expiresAt())) {
            throw new IllegalStateException("ACME frozen enrollment binding differs");
        }
        requireExactIdentifiers(enrollment().inspectIdentity(transaction.id()), order.identifiers());
        RetainedIssuanceBinding binding = enrollment().issuanceBinding(transaction.id());
        if (order.issuanceCommitment().filter(value -> !value.equals(binding.effectiveCommitment())).isPresent()
                || order.signingOperationId().isPresent() && transaction.receipt().isPresent()
                        && !order.signingOperationId().orElseThrow().equals(transaction.receipt().orElseThrow().operationId())
                || order.credentialId().isPresent() && !order.credentialId().equals(transaction.credentialId())) {
            throw new IllegalStateException("ACME signing attachment differs");
        }
    }

    private String admittedDirectoryCommitment(AcmeState.Directory directory) {
        // Admission only accepts ACTIVE directories. Later administrative suspension
        // must not invalidate already admitted work or certificate publication.
        return directory.status() == AcmeState.DirectoryStatus.ACTIVE ? directory.commitment()
                : ((AcmeState.Directory) new AcmeStateCodec().seal(copyDirectory(directory, AcmeState.DirectoryStatus.ACTIVE))).commitment();
    }

    private AcmeState.Order continueEnrollment(AcmeState.Order order, AcmeState.Directory directory, AcmeState.Account account,
            EnrollmentTransaction transaction, CancellationSignal cancellation) {
        EnrollmentTransaction continued = enrollment().dispatch(transaction.id(), cancellation);
        requireEnrollmentBinding(order, directory, continued);
        RetainedIssuanceBinding binding = enrollment().issuanceBinding(continued.id());
        Optional<PkiId> operationId = switch (continued.state()) {
            case ACCEPTED, ISSUED, FAILED -> continued.receipt().map(zeroecho.pki.api.signing.SigningAcceptanceReceipt::operationId);
            default -> order.signingOperationId();
        };
        AcmeState.OrderStatus status = switch (continued.state()) {
            case REJECTED, EXPIRED, FAILED -> AcmeState.OrderStatus.INVALID;
            case ISSUED -> AcmeState.OrderStatus.VALID;
            default -> AcmeState.OrderStatus.PROCESSING;
        };
        if (continued.receipt().isPresent()) tripFinalizeFault(FinalizeFaultPoint.BEFORE_SIGNING_ATTACHMENT);
        if (status == AcmeState.OrderStatus.VALID) {
            if (order.status() == AcmeState.OrderStatus.VALID) {
                validatePublicationCorrelation(account, order, directory, continued.credentialId().orElseThrow());
                registerPublication(continued.credentialId().orElseThrow(), account.accountId());
                return order;
            }
            AcmeState.Order attached = copyOrder(order, AcmeState.OrderStatus.PROCESSING, Optional.empty(), operationId, Optional.of(binding.effectiveCommitment()));
            if (!order.issuanceCommitment().equals(attached.issuanceCommitment()) || !order.signingOperationId().equals(operationId)) {
                order = (AcmeState.Order) store.replace(List.of(new AcmeControlStore.Replacement(order, attached))).getFirst();
            }
            SemanticSigningOperation signed = realm.session().semanticSigning().orElseThrow().find(operationId.orElseThrow()).orElseThrow();
            return applySigningSnapshot(order, directory, account.accountId(), signed);
        }
        if (order.status() == status && order.issuanceCommitment().filter(binding.effectiveCommitment()::equals).isPresent()
                && order.signingOperationId().equals(operationId)) return order;
        AcmeState.Order updated = copyOrder(order, status, Optional.empty(), operationId, Optional.of(binding.effectiveCommitment()));
        return (AcmeState.Order) store.replace(List.of(new AcmeControlStore.Replacement(order, updated))).getFirst();
    }

    private AcmeState.Order applySigningSnapshot(AcmeState.Order order, AcmeState.Directory directory,
            String accountId, SemanticSigningOperation snapshot) {
        PkiId operationId = snapshot.submissionId().id();
        return switch (snapshot.state()) {
            case SIGNING, PUBLISHING -> {
                if (order.status() == AcmeState.OrderStatus.PROCESSING
                        && order.signingOperationId().filter(operationId::equals).isPresent()) yield order;
                AcmeState.Order processing = copyOrder(order, AcmeState.OrderStatus.PROCESSING,
                        Optional.empty(), Optional.of(operationId));
                yield (AcmeState.Order) store.replace(List.of(
                        new AcmeControlStore.Replacement(order, processing))).get(0);
            }
            case FAILED, EXPIRED -> {
                AcmeState.Order invalid = copyOrder(order, AcmeState.OrderStatus.INVALID,
                        Optional.empty(), Optional.of(operationId));
                yield (AcmeState.Order) store.replace(List.of(
                        new AcmeControlStore.Replacement(order, invalid))).get(0);
            }
            case COMPLETED -> completeRecoveredOrder(order, directory, accountId, operationId, snapshot);
        };
    }

    private AcmeState.Order completeRecoveredOrder(AcmeState.Order order, AcmeState.Directory directory,
            String accountId, PkiId operationId, SemanticSigningOperation completed) {
        PkiId credentialId = completed.completedCredentialId()
                .orElseThrow(() -> new IllegalStateException("Completed issuance lacks its publication identity"));
        zeroecho.pki.api.credential.Credential credential = realm.session().repository()
                .credential(credentialId)
                .orElseThrow(() -> new IllegalStateException("Completed issuance publication is unavailable"));
        if (!credential.issuerRef().caId().equals(order.authorityId())
                || !credential.issuerRef().issuerId().equals(order.issuerId())
                || !credential.issuerRef().chainPathId().equals(order.issuancePathId())) {
            throw new IllegalStateException("Completed ACME issuance selection differs");
        }
        AcmeState.Account account = requireAccount(accountId);
        validatePublicationCorrelation(account, order, directory, credentialId);
        registerPublication(credentialId, accountId);
        AcmeState.Order valid = copyOrder(order, AcmeState.OrderStatus.VALID,
                Optional.of(credentialId), Optional.of(operationId));
        AcmeState.Order committed = (AcmeState.Order) store.replace(List.of(
                new AcmeControlStore.Replacement(order, valid))).get(0);
        audit("ACME_CERTIFICATE_ISSUED", accountId,
                Map.of("order", order.orderId(), "credential", credentialId.value()));
        return committed;
    }

    /**
     * Returns one account-owned authorization without revealing another account's state.
     *
     * @param accountId stable account identifier
     * @param authorizationId stable authorization identifier
     * @return account-owned authorization
     */
    public AcmeState.Authorization authorization(String accountId, String authorizationId) {
        AcmeState.Authorization value = requireAuthorization(authorizationId);
        if (!value.accountId().equals(accountId)) throw new IllegalArgumentException("ACME authorization unavailable");
        return value;
    }

    /**
     * Returns one account-owned challenge without URL-derived authority.
     *
     * @param accountId stable account identifier
     * @param challengeId stable challenge identifier
     * @return account-owned challenge
     */
    public AcmeState.Challenge challenge(String accountId, String challengeId) {
        AcmeState.Challenge value = requireChallenge(challengeId);
        authorization(accountId, value.authorizationId());
        return value;
    }

    /**
     * Issues or exactly replays confirmation proof material for one valid account-owned order.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @return issued or replayed confirmation challenge
     */
    public CredentialConfirmationProofChallenge issueCredentialConfirmationChallenge(
            String accountId, String expectedAccountCommitment, String orderId) {
        ConfirmationOrder confirmation = requireConfirmationOrder(accountId, expectedAccountCommitment, orderId);
        CredentialConfirmationLifecycle lifecycle = realm.session().confirmations()
                .get(confirmation.credentialId())
                .orElseThrow(() -> new IllegalStateException("ACME credential confirmation is unavailable"));
        validateConfirmationLifecycle(confirmation, lifecycle);
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalStateException("ACME credential confirmation is not pending");
        }
        return realm.session().confirmations().issueProofChallenge(
                new CredentialConfirmationProofChallengeRequest(confirmation.credentialId(),
                        lifecycle.revision(), lifecycle.recordCommitment()));
    }

    /**
     * Completes or exactly replays confirmation proof processing for one valid account-owned order.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @param expectedLifecycleRevision expected confirmation lifecycle revision
     * @param expectedLifecycleRecordCommitment expected lifecycle-record commitment
     * @param expectedChallengeRecordCommitment expected proof-challenge record commitment
     * @param response suite-defined proof response bytes
     * @return durable confirmation result
     */
    public CredentialConfirmationProofResult completeCredentialConfirmation(
            String accountId, String expectedAccountCommitment, String orderId,
            long expectedLifecycleRevision, String expectedLifecycleRecordCommitment,
            String expectedChallengeRecordCommitment, byte[] response) {
        ConfirmationOrder confirmation = requireConfirmationOrder(accountId, expectedAccountCommitment, orderId);
        CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                confirmation.credentialId(), expectedLifecycleRevision,
                expectedLifecycleRecordCommitment, expectedChallengeRecordCommitment);
        return realm.session().confirmations().verifyAndComplete(
                new CredentialConfirmationProofSubmission(proofCas, response));
    }

    private ConfirmationOrder requireConfirmationOrder(String accountId,
            String expectedAccountCommitment, String orderId) {
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = requireOrder(orderId);
        if (!order.accountId().equals(accountId) || order.status() != AcmeState.OrderStatus.VALID
                || order.credentialId().isEmpty()) {
            throw new IllegalArgumentException("ACME credential confirmation is unavailable");
        }
        AcmeState.Directory directory = requireDirectory(order.directoryId());
        PkiId credentialId = order.credentialId().orElseThrow();
        validatePublicationCorrelation(account, order, directory, credentialId);
        if (directory.confirmationPolicy().disclosurePolicy() == ConfirmationDisclosurePolicy.PUBLIC) {
            throw new IllegalArgumentException("ACME credential confirmation is not required");
        }
        return new ConfirmationOrder(directory, credentialId);
    }

    private static void validateConfirmationLifecycle(ConfirmationOrder confirmation,
            CredentialConfirmationLifecycle lifecycle) {
        AcmeState.Directory directory = confirmation.directory();
        if (!lifecycle.credentialId().equals(confirmation.credentialId())
                || !lifecycle.initialPolicyCommitment().equals(directory.confirmationPolicyCommitment())
                || !lifecycle.proofSuite().equals(directory.confirmationPolicy().proofSuite())
                || !lifecycle.confirmationRequired()) {
            throw new IllegalStateException("ACME credential confirmation binding differs");
        }
    }

    private synchronized AcmeState.Challenge completeChallenge(AcmeState.Challenge claimed,
            AcmeState.Authorization authorization, AcmeState.Order order, AcmeState.Directory directory,
            String accountId, String expectedAccountCommitment, String accountKey, String keyAuthorization,
            AcmeChallengeProvider.Result result) {
        requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Challenge current = requireChallenge(claimed.challengeId());
        if (!current.commitment().equals(claimed.commitment()) || current.status() != AcmeState.ChallengeStatus.PROCESSING) {
            throw new IllegalStateException("ACME challenge attempt changed");
        }
        String evidenceId = id("evidence"); Instant observed = result.observedAt();
        AcmeState.AuthorizationEvidence evidence = new AcmeState.AuthorizationEvidence(evidenceId,
                authorization.authorizationId(), current.providerId(), current.type(), authorization.identifier(),
                digest(accountKey), digest(keyAuthorization), directory.policyCommitment(), current.attempt(), observed,
                result.expiresAt(), result.valid() ? AcmeState.EvidenceResult.VALID : AcmeState.EvidenceResult.INVALID,
                result.valid() ? Optional.empty() : Optional.of(result.classification()), ZERO);
        AcmeState.Challenge updatedChallenge = new AcmeState.Challenge(current.challengeId(), current.authorizationId(),
                current.type(), current.token(), result.valid() ? AcmeState.ChallengeStatus.VALID : AcmeState.ChallengeStatus.INVALID,
                current.providerId(), current.attempt(), result.valid() ? Optional.empty() : Optional.of(result.classification()),
                result.valid() ? Optional.of(evidence.evidenceId()) : Optional.empty(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Authorization updatedAuthorization = new AcmeState.Authorization(authorization.authorizationId(),
                authorization.orderId(), authorization.accountId(), authorization.identifier(),
                result.valid() ? AcmeState.AuthorizationStatus.VALID : AcmeState.AuthorizationStatus.INVALID,
                authorization.challengeIds(), authorization.expiresAt(),
                result.valid() ? Optional.of(evidence.evidenceId()) : Optional.empty(), ZERO);
        AcmeState.OrderStatus orderStatus = result.valid() && allOtherAuthorizationsValid(order, authorization.authorizationId())
                ? AcmeState.OrderStatus.READY : result.valid() ? AcmeState.OrderStatus.PENDING : AcmeState.OrderStatus.INVALID;
        AcmeState.Order updatedOrder = copyOrder(order, orderStatus, Optional.empty());
        AcmeControlStore.Transition transition = store.transition(List.of(new AcmeControlStore.Replacement(current, updatedChallenge),
                new AcmeControlStore.Replacement(authorization, updatedAuthorization),
                new AcmeControlStore.Replacement(order, updatedOrder)), List.of(evidence));
        audit("ACME_CHALLENGE_RESULT", authorization.accountId(), Map.of("challenge", current.challengeId(),
                "outcome", result.valid() ? "VALID" : "INVALID"));
        return (AcmeState.Challenge) transition.replaced().get(0);
    }

    private boolean allOtherAuthorizationsValid(AcmeState.Order order, String currentId) {
        return order.authorizationIds().stream().filter(id -> !id.equals(currentId))
                .map(this::requireAuthorization).allMatch(value -> value.status() == AcmeState.AuthorizationStatus.VALID);
    }
    private void validateFrozenDirectory(AcmeState.Directory directory) {
        if (!directory.realmId().equals(realm.configuration().realmId())) {
            throw new IllegalStateException("ACME directory realm binding differs");
        }
        requireExposed(directory.authorityId());
        realm.session().repository().authority(directory.authorityId())
                .orElseThrow(() -> new IllegalStateException("ACME directory authority is unavailable"));
        IssuerChainPath path = realm.session().repository().chainPath(directory.issuancePathId())
                .orElseThrow(() -> new IllegalStateException("ACME directory issuance path is unavailable"));
        ImportedCertificateProfileVersion imported = requireFrozenProfile(directory);
        if (!path.authorityId().equals(directory.authorityId())
                || !path.issuerId().equals(directory.issuerId())
                || !path.pathCommitment().equals(directory.issuancePathCommitment())) {
            throw new IllegalStateException("ACME directory frozen policy is unavailable");
        }
        CredentialConfirmationPolicy confirmation = imported.definition().confirmationPolicy()
                .orElseThrow(() -> new IllegalStateException("ACME directory confirmation policy is unavailable"));
        if (!confirmation.equals(directory.confirmationPolicy())
                || !confirmation.configurationCommitment().equals(directory.confirmationPolicyCommitment())) {
            throw new IllegalStateException("ACME directory confirmation policy changed");
        }
    }

    private ImportedCertificateProfileVersion requireFrozenProfile(AcmeState.Directory directory) {
        ImportedCertificateProfileVersion imported = realm.session().profiles()
                .getImportedVersion(directory.profile().profileId(), directory.profile().profileVersion())
                .orElseThrow(() -> new IllegalStateException("ACME directory frozen profile is unavailable"));
        if (!directory.profile().equals(imported.reference())) {
            throw new IllegalStateException("ACME directory frozen profile differs");
        }
        return imported;
    }
    private void validateFrozenOrder(AcmeState.Order order, AcmeState.Directory directory) {
        if (order.directoryRevision() != directory.revision()
                || !order.directoryId().equals(directory.directoryId())
                || !order.directoryPolicyCommitment().equals(directory.policyCommitment())
                || !order.authorityId().equals(directory.authorityId())
                || !order.profile().equals(directory.profile())
                || !order.issuerId().equals(directory.issuerId())
                || !order.issuancePathId().equals(directory.issuancePathId())
                || !order.issuancePathCommitment().equals(directory.issuancePathCommitment())) {
            throw new IllegalStateException("ACME order directory binding mismatch");
        }
        validateFrozenDirectory(directory);
    }

    private void validatePublicationCorrelation(AcmeState.Account account, AcmeState.Order order,
            AcmeState.Directory directory, PkiId credentialId) {
        requireAccountDirectory(account, directory);
        if (!account.accountId().equals(order.accountId())) {
            throw new IllegalStateException("ACME publication account binding mismatch");
        }
        validateFrozenOrder(order, directory);
        zeroecho.pki.api.credential.Credential credential = realm.session().repository()
                .credential(credentialId)
                .orElseThrow(() -> new IllegalStateException("ACME publication credential is unavailable"));
        if (!credential.credentialId().equals(credentialId)
                || !credential.issuerRef().caId().equals(order.authorityId())
                || !credential.issuerRef().issuerId().equals(order.issuerId())
                || !credential.issuerRef().chainPathId().equals(order.issuancePathId())
                || !(credential.profileBinding() instanceof EndEntityProfileBinding binding)
                || !binding.reference().equals(order.profile())) {
            throw new IllegalStateException("ACME publication credential correlation differs");
        }
    }

    private void registerPublication(PkiId credentialId, String accountId) {
        realm.credentialPublication().register(credentialId,
                Optional.of(DisclosureService.Owner.acmeAccount(accountId)), PUBLICATION_AUDIT_ACTOR);
    }
    private void requireActiveAdmission(AcmeState.Directory directory) {
        AcmeState.Directory exact = requireDirectory(directory.directoryId());
        if (exact.status() != AcmeState.DirectoryStatus.ACTIVE
                || !exact.commitment().equals(directory.commitment())) {
            throw new IllegalStateException("ACME directory is inactive or changed");
        }
        validateFrozenDirectory(exact);
        requireAdmissionCapabilities(exact);
    }
    private void requireAdmissionCapabilities(AcmeState.Directory directory) {
        realm.enrollmentProfiles().requireBinding(directory.enrollmentProfileId(), directory.profile().profileId(),
                directory.authorityId().value(), true);
        CaRecord authority = realm.session().repository().authority(directory.authorityId())
                .orElseThrow(() -> new IllegalStateException("ACME directory authority is unavailable"));
        requireActiveAuthority(authority);
        if (!authority.currentIssuanceIssuerId().equals(directory.issuerId())
                || !authority.issuanceChainPathId().equals(directory.issuancePathId())) {
            throw new IllegalStateException("ACME directory issuance selection is no longer current");
        }
        requireProviders(directory.challengeTypes(), directory.challengeProviderIds());
        if (directory.eabRequired() && directory.eabProviderId().isEmpty()) {
            throw new IllegalStateException("Required ACME EAB provider is unavailable");
        }
        directory.eabProviderId().ifPresent(id -> {
            if (!eabProviders.containsKey(id)) {
                throw new IllegalStateException("ACME EAB provider is unavailable");
            }
        });
    }
    private static void requireActiveAuthority(CaRecord authority) {
        if (authority.state() != CaState.ACTIVE) {
            throw new IllegalStateException("ACME authority is not active");
        }
    }
    private void requireAccountDirectory(AcmeState.Account account, AcmeState.Directory directory) {
        if (account.status() != AcmeState.AccountStatus.VALID || !account.directoryId().equals(directory.directoryId())
                || account.directoryRevision() != directory.revision()
                || !account.directoryPolicyCommitment().equals(directory.policyCommitment())) {
            throw new IllegalArgumentException("ACME account directory mismatch");
        }
    }
    private IssuerChainPath requireCurrentPath(CaRecord authority) {
        IssuerChainPath path = realm.session().repository().chainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new IllegalArgumentException("ACME issuance path is unavailable"));
        if (!path.authorityId().equals(authority.caId())
                || !path.issuerId().equals(authority.currentIssuanceIssuerId())) {
            throw new IllegalArgumentException("ACME issuance path authority mismatch");
        }
        return path;
    }
    private void requireProviders(Set<AcmeState.ChallengeType> types, Set<String> ids) {
        if (!providers.keySet().containsAll(ids)) throw new IllegalArgumentException("ACME challenge provider unavailable");
        for (AcmeState.ChallengeType type : types) {
            if (ids.stream().map(providers::get).noneMatch(provider -> provider.challengeTypes().contains(type))) {
                throw new IllegalArgumentException("ACME challenge type has no provider");
            }
        }
    }
    private String providerFor(AcmeState.Directory directory, AcmeState.ChallengeType type) {
        return directory.challengeProviderIds().stream().sorted().filter(id -> providers.get(id).challengeTypes().contains(type))
                .findFirst().orElseThrow(() -> new IllegalStateException("ACME challenge provider is unavailable"));
    }
    private List<AcmeState.Identifier> canonicalIdentifiers(List<AcmeState.Identifier> requested,
            AcmeState.Directory directory) {
        List<AcmeState.Identifier> values = requested.stream()
                .map(value -> new AcmeState.Identifier(value.type(), value.value(), value.wildcard()))
                .distinct().sorted(Comparator.comparing(AcmeState.Identifier::presentation)).toList();
        if (values.isEmpty()) throw new IllegalArgumentException("ACME identifier count is invalid");
        for (AcmeState.Identifier value : values) {
            if (directory.dnsNamespaces().stream().noneMatch(namespace -> value.value().equals(namespace)
                    || value.value().endsWith("." + namespace))) {
                throw new IllegalArgumentException("ACME identifier namespace is rejected");
            }
            if (value.wildcard() && !directory.challengeTypes().contains(AcmeState.ChallengeType.DNS_01)) {
                throw new IllegalArgumentException("Wildcard ACME identifier requires DNS-01");
            }
        }
        return values;
    }
    private static Set<String> bindingPolicy(ActiveCertificateProfile profile) {
        zeroecho.pki.api.profile.X509AlgorithmBindingPolicy policy = profile.definition().algorithmBindingPolicy();
        if (policy.mode() == zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY) {
            return Set.of("STANDARD_ONLY");
        }
        return java.util.stream.Stream.of(policy.subjectPublicKey(), policy.csrSignature(),
                policy.certificateSignature(), policy.crlSignature()).flatMap(Optional::stream)
                .map(zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference::bindingId)
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }
    private void requireExactIdentifiers(ParsedCertificationRequest parsed, List<AcmeState.Identifier> expected) {
        Set<AcmeState.Identifier> actual = new LinkedHashSet<>();
        for (SubjectAlternativeName name : parsed.subjectAlternativeNames()) {
            if (!(name instanceof SubjectAlternativeName.DnsName dns)) throw new PkiException("ACME CSR contains a non-DNS identifier");
            boolean wildcard = dns.value().startsWith("*."); String value = wildcard ? dns.value().substring(2) : dns.value();
            if (!actual.add(new AcmeState.Identifier(AcmeState.IdentifierType.DNS, value, wildcard))) {
                throw new PkiException("ACME CSR contains duplicate identifiers");
            }
        }
        if (!actual.equals(Set.copyOf(expected))) throw new PkiException("ACME CSR identifiers do not match the order");
    }
    private void requireExposed(PkiId authorityId) {
        if (!realm.configuration().authorityExposure().allows(authorityId)) throw new IllegalArgumentException("ACME authority is outside realm exposure");
    }
    private int nextDirectoryRevision(String alias) {
        return directoriesForAlias(alias).stream().mapToInt(AcmeState.Directory::revision).max().orElse(0) + 1;
    }
    private List<AcmeState.Directory> directoriesForAlias(String alias) {
        List<AcmeState.Directory> result = new ArrayList<>(); int offset = 0;
        do {
            ServerControlStore.Page<AcmeState.Directory> page = store.page(AcmeState.Directory.class, offset, 256);
            result.addAll(page.values().stream().filter(value -> value.alias().equals(alias)).toList());
            if (!page.hasMore()) break; offset = page.nextOffset();
        } while (true);
        return List.copyOf(result);
    }
    private Optional<AcmeState.Account> accountByThumbprint(String directoryId, String thumbprint) {
        int offset = 0;
        do {
            ServerControlStore.Page<AcmeState.Account> page = store.page(AcmeState.Account.class, offset, 256);
            Optional<AcmeState.Account> found = page.values().stream().filter(value -> value.directoryId().equals(directoryId)
                    && value.keyThumbprint().equals(thumbprint)).findFirst();
            if (found.isPresent() || !page.hasMore()) return found; offset = page.nextOffset();
        } while (true);
    }
    private AcmeState.Directory requireDirectory(String id) { return store.get(AcmeState.Directory.class, id).orElseThrow(() -> new IllegalArgumentException("ACME directory unavailable")); }
    private AcmeState.Account requireAccount(String id) { return store.get(AcmeState.Account.class, id).orElseThrow(() -> new IllegalArgumentException("ACME account unavailable")); }
    private AcmeState.Account requireAuthenticatedAccount(String id, String expectedCommitment) {
        AcmeState.Account account = requireAccount(id);
        if (account.status() != AcmeState.AccountStatus.VALID
                || !account.commitment().equals(Objects.requireNonNull(expectedCommitment,
                        "expectedCommitment"))) {
            throw new SecurityException("ACME account key authority changed");
        }
        return account;
    }
    private AcmeState.Order requireOrder(String id) { return store.get(AcmeState.Order.class, id).orElseThrow(() -> new IllegalArgumentException("ACME order unavailable")); }
    private AcmeState.Authorization requireAuthorization(String id) { return store.get(AcmeState.Authorization.class, id).orElseThrow(() -> new IllegalArgumentException("ACME authorization unavailable")); }
    private AcmeState.Challenge requireChallenge(String id) { return store.get(AcmeState.Challenge.class, id).orElseThrow(() -> new IllegalArgumentException("ACME challenge unavailable")); }
    private AcmeState.Directory copyDirectory(AcmeState.Directory v, AcmeState.DirectoryStatus status) { return new AcmeState.Directory(v.directoryId(), v.alias(), v.revision(), v.realmId(), v.authorityId(), v.profile(), v.enrollmentProfileId(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifierTypes(), v.dnsNamespaces(), v.maximumValidity(), v.publicKeyAlgorithms(), v.x509BindingPolicies(), v.challengeTypes(), v.challengeProviderIds(), v.eabProviderId(), v.eabRequired(), v.confirmationPolicy(), v.confirmationPolicyCommitment(), status, v.policyCommitment(), v.createdAt(), ZERO); }
    private AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential) {
        return copyOrder(v, status, credential, v.signingOperationId());
    }
    private AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential,
            Optional<PkiId> signingOperation) {
        return copyOrder(v, status, credential, signingOperation, v.issuanceCommitment());
    }
    private AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential,
            Optional<PkiId> signingOperation, Optional<String> issuanceCommitment) { return new AcmeState.Order(v.orderId(), v.accountId(), v.directoryId(), v.directoryRevision(), v.directoryPolicyCommitment(), v.authorityId(), v.profile(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifiers(), v.notBefore(), v.notAfter(), status, v.authorizationIds(), credential, issuanceCommitment, signingOperation, v.createdAt(), v.expiresAt(), ZERO); }
    private String id(String prefix) { byte[] value = new byte[16]; random.nextBytes(value); return prefix + ":" + java.util.HexFormat.of().formatHex(value); }
    private String token() { byte[] value = new byte[32]; random.nextBytes(value); String result = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value); java.util.Arrays.fill(value, (byte) 0); return result; }
    private static String directoryPolicyCommitment(DirectoryRegistration r, ActiveCertificateProfile profile,
            CredentialConfirmationPolicy confirmationPolicy, CaRecord ca, IssuerChainPath path) {
        return digest(r.alias() + '\n' + ca.caId().value() + '\n' + profile.reference() + '\n' + r.enrollmentProfileId() + '\n'
                + ca.currentIssuanceIssuerId().value() + '\n' + path.pathId().value() + '\n'
                + path.pathCommitment() + '\n' + r.dnsNamespaces().stream().sorted().toList() + '\n'
                + r.maximumValidity() + '\n' + r.publicKeyAlgorithms().stream().sorted().toList() + '\n'
                + r.x509BindingPolicies().stream().sorted().toList() + '\n'
                + r.challengeTypes().stream().sorted().toList() + '\n'
                + r.challengeProviderIds().stream().sorted().toList() + '\n'
                + r.eabProviderId().orElse("NONE") + '\n' + r.eabRequired() + '\n'
                + confirmationPolicy.configurationCommitment());
    }
    private void audit(String action, String actor, Map<String, String> details) {
        realm.auditTransport(action, actor, details);
    }
    private void signalReconciliation() {
        try {
            reconciliationWake.run();
        } catch (RuntimeException ignored) {
            // Periodic reconciliation remains authoritative after a failed advisory wake.
        }
    }

    /* default */ static void installFinalizeFault(FinalizeFaultInjector faults) {
        FINALIZE_FAULTS.set(Objects.requireNonNull(faults, "faults"));
    }

    /* default */ static void clearFinalizeFault() {
        FINALIZE_FAULTS.remove();
    }

    private static void tripFinalizeFault(FinalizeFaultPoint point) {
        FinalizeFaultInjector faults = FINALIZE_FAULTS.get();
        if (faults != null) {
            faults.fail(point);
        }
    }

    private record ConfirmationOrder(AcmeState.Directory directory, PkiId credentialId) { }

    /** Deterministic finalization crash boundary. */
    /* default */ enum FinalizeFaultPoint { BEFORE_SIGNING_ATTACHMENT }

    /** Package-local deterministic finalization failure seam. */
    @FunctionalInterface
    /* default */ interface FinalizeFaultInjector { void fail(FinalizeFaultPoint point); }
    private static String digest(String value) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }
    private static String digestBytes(byte[] value) { try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); } }
    private static String accountKeyAuthorizationThumbprint(String commitment) {
        byte[] digest = java.util.HexFormat.of().parseHex(commitment);
        try {
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } finally {
            java.util.Arrays.fill(digest, (byte) 0);
        }
    }
}
