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

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.server.CredentialPublicationGate;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Transport-neutral durable ACME state machine and constrained PKI integration.
 *
 * <p>Account identity is protocol-scoped. No method accepts an administrative
 * principal or permission as issuance authority. Directory activation freezes
 * one exact authority, profile, issuer generation, chain path, provider set, and
 * profile-owned confirmation policy. External validators return evidence only.</p>
 */
// Retains the existing finite public ACME service operation contract.
@SuppressWarnings({ "PMD.ExcessivePublicCount" })
public final class AcmeService {
    /* default */ final AcmeCollaborators operations = new AcmeCollaborators(this);
    /** Shared immutable protocol constant. */
    /* default */ static final String ZERO = "0".repeat(64);
    /** Shared immutable protocol constant. */
    /* default */ static final CredentialPublicationGate.AuditActor PUBLICATION_AUDIT_ACTOR =
            new CredentialPublicationGate.AuditActor("acme-service");
    private static final ThreadLocal<FinalizeFaultInjector> FINALIZE_FAULTS = new ThreadLocal<>();
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final ServerRealmContext realm;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final AcmeControlStore store;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Clock clock;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final SecureRandom random;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Map<String, AcmeChallengeProvider> providers;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Map<String, ProviderConfig> providerConfigurations;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Map<String, AcmeExternalAccountBindingProvider> eabProviders;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Map<String, ProviderConfig> eabProviderConfigurations;
    /** Borrowed immutable runtime collaborator for the package-local protocol implementation. */
    /* default */ final Runnable reconciliationWake;

    /**
     * Returns configured challenge-provider identities and supported challenge types without options.
     * @return immutable map of non-secret configured provider metadata
     */
    public Map<String, Set<AcmeState.ChallengeType>> configuredChallengeProviders() { return operations.directory.configuredChallengeProviders(); }

    /**
     * Returns explicitly configured external-account-binding provider identifiers without options.
     * @return immutable configured provider identifiers
     */
    public Set<String> configuredEabProviders() { return operations.directory.configuredEabProviders(); }

    /**
     * Creates a realm-bound ACME service from explicitly enabled provider capabilities.
     *
     * <p>Provider maps are copied and must match their configuration identities exactly.
     * Retained directory state is validated before this service becomes available.</p>
     *
     * @param realm realm context owning all ACME state
     * @param clock authoritative server clock
     * @param random cryptographically secure identifier source
     * @param providers explicitly enabled challenge providers keyed by stable identity
     * @param providerConfigurations exact configuration keyed by challenge-provider identity
     * @param eabProviders explicitly enabled external-account-binding providers
     * @param eabProviderConfigurations exact configuration keyed by EAB-provider identity
     * @param reconciliationWake callback that promptly wakes durable signing reconciliation
     * @throws NullPointerException if a required collaborator, provider map key or map value is null
     * @throws IllegalArgumentException if configured provider identities and configuration keys are inconsistent
     * @throws IllegalStateException if realm recovery or retained directory dependencies are unavailable
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
        operations.directory.validateRecoveredState();
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
     * @throws NullPointerException if a required collaborator, map key or map value is null
     * @throws IllegalArgumentException if configured provider identities and configuration keys are
     *         inconsistent
     * @throws IllegalStateException if realm recovery or retained directory dependencies are unavailable
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
     * @throws NullPointerException if a required collaborator, map key or map value is null
     * @throws IllegalArgumentException if configured provider identities and configuration keys are
     *         inconsistent
     * @throws IllegalStateException if realm recovery or retained directory dependencies are unavailable
     */
    public AcmeService(ServerRealmContext realm, Clock clock, SecureRandom random,
            Map<String, AcmeChallengeProvider> providers,
            Map<String, ProviderConfig> providerConfigurations) {
        this(realm, clock, random, providers, providerConfigurations, Map.of(), Map.of());
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
        /**
         * Validates required registration input before PKI resolution.
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
         * @throws NullPointerException if a required component, collection or collection element is null
         * @throws IllegalArgumentException if the enrollment-profile identity is noncanonical
         */
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
     * @throws NullPointerException if {@code registration} is null
     * @throws IllegalArgumentException if the selected certificate profile is not an active end-entity profile
     */
    public ServerControlOperation.AcmeDirectoryProfilePrecondition resolveDirectoryProfilePrecondition(
            DirectoryRegistration registration) { return operations.directory.resolveDirectoryProfilePrecondition(registration); }

    /**
     * Registers one immutable inactive directory revision from an approval-bound profile precondition.
     *
     * @param registration validated directory registration input
     * @param profilePrecondition approval-bound authoritative profile precondition
     * @return durably registered inactive directory revision
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Directory registerDirectory(DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition) { return operations.directory.registerDirectory(registration, profilePrecondition); }

    /**
     * Checks the complete registration against current PKI policy without creating a directory.
     * @param registration exact proposed directory
     * @param profilePrecondition frozen active profile and confirmation-policy commitments
     * @throws IllegalArgumentException if the proposed policy or dependencies are invalid
     * @throws IllegalStateException if a frozen profile commitment changed
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized void validateDirectoryRegistration(DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition) { operations.directory.validateDirectoryRegistration(registration, profilePrecondition); }


    /**
     * Registers directly after resolving the same exact active-profile precondition.
     *
     * @param registration validated directory registration input
     * @return durably registered inactive directory revision
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Directory registerDirectory(DirectoryRegistration registration) { return operations.directory.registerDirectory(registration); }

    /**
     * Activates one exact directory revision after revalidating all frozen PKI authority.
     *
     * @param directoryId stable directory identifier
     * @return active directory revision
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Directory activateDirectory(String directoryId) { return operations.directory.activateDirectory(directoryId); }

    /**
     * Validates a directory activation without changing directory state.
     * @param directoryId exact existing revision
     * @return current validated directory
     * @throws IllegalStateException if frozen dependencies or activation state reject admission
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Directory validateDirectoryActivation(String directoryId) { return operations.directory.validateDirectoryActivation(directoryId); }

    /**
     * Deactivates new account/order admission while existing unexpired orders remain usable.
     *
     * @param directoryId stable directory identifier
     * @return inactive directory revision
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Directory deactivateDirectory(String directoryId) { return operations.directory.deactivateDirectory(directoryId); }

    /**
     * Resolves the sole active directory revision for one public alias.
     *
     * @param alias public directory alias
     * @return sole active directory revision
     * @throws IllegalArgumentException if the selected directory is unavailable or inactive
     */
    public AcmeState.Directory activeDirectory(String alias) { return operations.directory.activeDirectory(alias); }

    /**
     * Returns the canonical nonce scope for one known directory alias.
     *
     * @param alias public directory alias
     * @return canonical nonce scope
     * @throws IllegalArgumentException if the selected directory alias is unavailable
     */
    public String nonceScope(String alias) { return operations.directory.nonceScope(alias); }

    /**
     * Returns one exact directory revision for administrative and protocol inspection.
     *
     * @param directoryId stable directory identifier
     * @return exact directory revision
     */
    public AcmeState.Directory directory(String directoryId) { return operations.directory.directory(directoryId); }

    /**
     * Resolves the exact frozen directory for one existing account resource.
     *
     * @param accountId stable account identifier
     * @return account's frozen directory revision
     */
    public AcmeState.Directory accountDirectory(String accountId) { return operations.directory.accountDirectory(accountId); }

    /**
     * Resolves the exact frozen directory for one existing order resource.
     *
     * @param orderId stable order identifier
     * @return order's frozen directory revision
     */
    public AcmeState.Directory orderDirectory(String orderId) { return operations.directory.orderDirectory(orderId); }

    /**
     * Resolves the exact frozen directory for one existing authorization resource.
     *
     * @param authorizationId stable authorization identifier
     * @return authorization's frozen directory revision
     */
    public AcmeState.Directory authorizationDirectory(String authorizationId) { return operations.directory.authorizationDirectory(authorizationId); }

    /**
     * Resolves the exact frozen directory for one existing challenge resource.
     *
     * @param challengeId stable challenge identifier
     * @return challenge's frozen directory revision
     */
    public AcmeState.Directory challengeDirectory(String challengeId) { return operations.directory.challengeDirectory(challengeId); }

    /**
     * Returns a deterministic bounded page of directory revisions.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return deterministic bounded directory page
     */
    public ServerControlStore.Page<AcmeState.Directory> directories(int offset, int limit) { return operations.directory.directories(offset, limit); }

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
     * @throws IllegalArgumentException if only-existing-account mode selects no retained account or directory
     *         policy requires an external-account binding that is absent
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Account createAccount(AcmeState.Directory directory, String keyThumbprint,
            byte[] publicKeySpki, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, boolean onlyReturnExisting) { return operations.accounts.createAccount(directory, keyThumbprint, publicKeySpki, contacts, termsAgreed, eabPolicyCommitment, onlyReturnExisting); }

    /**
     * Resolves an account by its authenticated key identity within one directory.
     *
     * @param directoryId stable directory identifier
     * @param keyThumbprint authenticated account-key thumbprint
     * @return matching account, or empty when unknown
     */
    public Optional<AcmeState.Account> accountByKey(String directoryId, String keyThumbprint) { return operations.accounts.accountByKey(directoryId, keyThumbprint); }

    /**
     * Verifies EAB inside its explicit secret-confining provider and returns only a safe commitment.
     *
     * @param directory exact frozen directory revision
     * @param keyThumbprint authenticated account-key thumbprint
     * @param nestedJws optional nested EAB JWS document
     * @return safe policy commitment, or empty when EAB is unused
     * @throws NullPointerException if {@code nestedJws} is null
     * @throws IllegalArgumentException if external-account binding is supplied for a directory without that
     *         capability or required external-account binding is absent
     * @throws SecurityException if the verified binding is unconsumed, expired or does not cover the directory
     *         namespaces
     * @throws IllegalStateException if the configured external-account provider is unavailable
     */
    public Optional<String> verifyExternalAccountBinding(AcmeState.Directory directory, String keyThumbprint,
            Optional<byte[]> nestedJws) { return operations.accounts.verifyExternalAccountBinding(directory, keyThumbprint, nestedJws); }

    /**
     * Resolves one active account key for strict KID authentication.
     *
     * @param accountId stable account identifier
     * @param kid exact account key identifier
     * @return validated account key and record commitment
     * @throws IllegalArgumentException if the selected account is unavailable
     * @throws IllegalStateException if the retained account public key cannot be reconstructed
     */
    // Protocol diagnostics intentionally exclude untrusted/internal causes while retaining the established safe error contract.
    public AcmeJwsVerifier.AccountKey accountKey(String accountId, String kid) { return operations.accounts.accountKey(accountId, kid); }

    /**
     * Returns one account record without exposing contact data through transport automatically.
     *
     * @param accountId stable account identifier
     * @return exact account record
     */
    public AcmeState.Account account(String accountId) { return operations.accounts.account(accountId); }

    /**
     * Durably changes account status while preserving its key and history commitment.
     *
     * @param accountId stable account identifier
     * @return durably deactivated account
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Account deactivateAccount(String accountId) { return operations.accounts.deactivateAccount(accountId); }

    /**
     * Durably changes account status after exact account-key authority revalidation.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @return durably deactivated account
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     * @throws NullPointerException if the expected account commitment is null
     * @throws IllegalArgumentException if the retained account identity is unavailable
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Account deactivateAccount(String accountId, String expectedCommitment) { return operations.accounts.deactivateAccount(accountId, expectedCommitment); }


    /**
     * Atomically replaces bounded account contact metadata without changing key authority.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @param contacts bounded account contact URIs
     * @return durably updated account
     * @throws IllegalStateException if the selected account is unavailable in its current lifecycle state
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     * @throws NullPointerException if the expected account commitment is null
     * @throws IllegalArgumentException if the retained account identity is unavailable
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Account updateAccountContacts(String accountId, String expectedCommitment,
            List<String> contacts) { return operations.accounts.updateAccountContacts(accountId, expectedCommitment, contacts); }

    /**
     * Atomically replaces one account key after exact old-record authentication.
     *
     * @param accountId stable account identifier
     * @param expectedCommitment expected current account-record commitment
     * @param replacementThumbprint replacement account-key thumbprint
     * @param replacementSpki canonical replacement public key
     * @return account with the replacement key
     * @throws SecurityException if the current account or replacement-key binding does not permit rollover
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Account rolloverAccount(String accountId, String expectedCommitment,
            String replacementThumbprint, byte[] replacementSpki) { return operations.accounts.rolloverAccount(accountId, expectedCommitment, replacementThumbprint, replacementSpki); }

    /**
     * Returns a deterministic bounded page of accounts for administrative inspection.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return deterministic bounded account page
     */
    public ServerControlStore.Page<AcmeState.Account> accounts(int offset, int limit) { return operations.accounts.accounts(offset, limit); }

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
     * @throws IllegalArgumentException if none of the configured challenge types supports a requested
     *         identifier
     * @throws NullPointerException if a required reference, identifier entry or expected account commitment is
     *         null
     * @throws SecurityException if the authenticated account snapshot has changed
     * @throws IllegalStateException if current issuer/profile/provider admission dependencies are unavailable
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Order createOrder(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory,
            List<AcmeState.Identifier> requested, Optional<Instant> notBefore, Optional<Instant> notAfter,
            Duration orderLifetime) { return operations.orders.createOrder(accountId, expectedAccountCommitment, directory, requested, notBefore, notAfter, orderLifetime); }

    /**
     * Counts pending nonterminal orders up to a caller-supplied finite bound.
     *
     * @param accountId stable account identifier
     * @param stopAt positive early-stop bound
     * @return number of pending orders, capped by the supplied bound
     * @throws IllegalArgumentException if the pending-order scan bound is outside the supported range
     */
    public int pendingOrderCount(String accountId, int stopAt) { return operations.orders.pendingOrderCount(accountId, stopAt); }

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
     * @throws NullPointerException if any of {@code certificateDer}, {@code reason} is null
     * @throws SecurityException if the certificate cannot be associated with the authenticated account and
     *         permitted revocation target
     * @throws IllegalStateException if the domain revocation outcome did not confirm a committed transition
     * @throws IllegalArgumentException if the retained account identity is unavailable
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized RevocationRecord revokeCertificate(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory, byte[] certificateDer, RevocationReason reason, String requestId) { return operations.orders.revokeCertificate(accountId, expectedAccountCommitment, directory, certificateDer, reason, requestId); }

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
     * @throws IllegalArgumentException if the selected challenge is unavailable
     * @throws IllegalStateException if the challenge already has an active validation attempt or challenge
     *         validation was cancelled before completion
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     * @throws NullPointerException if the expected account commitment is null
     */
    // Retains the existing public source and binary-compatible protocol contract.
    @SuppressWarnings({ "PMD.UseObjectForClearerAPI" })
    public AcmeState.Challenge validateChallenge(String accountId, String expectedAccountCommitment,
            String challengeId, String accountKeyThumbprint, Instant deadline, CancellationSignal cancellation) { return operations.challenges.validateChallenge(accountId, expectedAccountCommitment, challengeId, accountKeyThumbprint, deadline, cancellation); }

    /**
     * Finalizes a ready order through the existing strict CSR and issuance services.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @param csrDer canonical PKCS#10 request DER
     * @return current durable order after finalization processing
     * @throws NullPointerException if the CSR or expected account commitment is null
     * @throws IllegalArgumentException if the account, order, directory or CSR is unavailable or invalid
     * @throws IllegalStateException if the order is not ready, repeated CSR differs or retained enrollment
     *         linkage is unavailable
     * @throws SecurityException if the authenticated account snapshot has changed
     * @throws PkiException if domain finalization rejects the request
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer) { return operations.orders.finalizeOrder(accountId, expectedAccountCommitment, orderId, csrDer); }

    /**
     * Finalizes a ready order while propagating transport cancellation into signing.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @param csrDer canonical PKCS#10 request DER
     * @param cancellation cooperative cancellation signal
     * @return current durable order after finalization processing
     * @throws NullPointerException if any of {@code cancellation}, {@code csrDer} is null
     * @throws IllegalArgumentException if the selected order is unavailable to the authenticated account
     * @throws IllegalStateException if the retained order has not reached an executable finalization state or
     *         the repeated finalization CSR differs from its retained original or the order lacks the retained
     *         enrollment reference required for its current state
     * @throws PkiException if cooperative finalization cancellation is observed
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer, CancellationSignal cancellation) { return operations.orders.finalizeOrder(accountId, expectedAccountCommitment, orderId, csrDer, cancellation); }

    /**
     * Polls an account-owned order using the exact current authentication snapshot.
     * Pending approvals remain processing; approved retained requests may dispatch.
     * @param accountId stable account identifier
     * @param expectedAccountCommitment current account commitment verified by JWS authentication
     * @param orderId stable order identifier
     * @return account-owned order after durable continuation
     * @throws NullPointerException if the expected account commitment is null
     * @throws IllegalArgumentException if the account, order or retained directory is unavailable
     * @throws IllegalStateException if retained enrollment continuation linkage is unavailable
     * @throws SecurityException if the authenticated account snapshot has changed
     * @throws PkiException if domain enrollment continuation fails
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId) { return operations.orders.order(accountId, expectedAccountCommitment, orderId); }

    /**
     * Continues an authenticated order with cancellation before durable admission.
     * @param accountId stable account identifier
     * @param expectedAccountCommitment current JWS-authenticated account commitment
     * @param orderId stable order identifier
     * @param cancellation transport cancellation signal
     * @return account-owned order after durable continuation
     * @throws NullPointerException if {@code cancellation} is null
     * @throws IllegalArgumentException if the selected order is unavailable to the authenticated account
     * @throws IllegalStateException if the order lacks the retained enrollment reference required for its
     *         current state
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     */
    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.
    @SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId,
            CancellationSignal cancellation) { return operations.orders.order(accountId, expectedAccountCommitment, orderId, cancellation); }


    /**
     * Reports usable explicitly opted-in SDK enrollment, without granting admission.
     * @param directory configured directory snapshot
     * @return whether its current enrollment/certificate policies and runtime support SDK issuance
     */
    public boolean hybridSdkAvailable(AcmeState.Directory directory) { return operations.enrollment.hybridSdkAvailable(directory); }

    /**
     * Freezes genuine account/order/authorization and client proof context without finalizing an order.
     * @param accountId currently JWS-authenticated account
     * @param expectedAccountCommitment exact current JWS key snapshot
     * @param orderId account-owned order
     * @param csrDer exact original SDK PKCS#10
     * @param clientNonce exact client nonce
     * @param canonicalOrigin configured listener origin
     * @return retained server challenge
     * @throws IllegalArgumentException if the selected order is unavailable to the authenticated account
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     * @throws NullPointerException if the expected account commitment is null
     */
    // Retains the existing public source and binary-compatible protocol contract.
    @SuppressWarnings({ "PMD.UseObjectForClearerAPI", "PMD.AvoidSynchronizedAtMethodLevel" })
    public synchronized zeroecho.pki.server.enrollment.EnrollmentSdkAdmission.Challenge challengeSdk(String accountId,
            String expectedAccountCommitment, String orderId, byte[] csrDer, byte[] clientNonce, String canonicalOrigin) { return operations.enrollment.challengeSdk(accountId, expectedAccountCommitment, orderId, csrDer, clientNonce, canonicalOrigin); }

    /**
     * Accepts fresh dual-client proofs or reads the same consumed receipt using current account JWS ownership.
     * Consumed replay precedes READY, mutable source/key commitments and proof expiry.
     * @param accountId current JWS-authenticated account
     * @param expectedAccountCommitment current verified key snapshot
     * @param orderId stable account-owned order
     * @param csrDer exact original SDK request
     * @param intentId retained challenge
     * @param sdkRequestId exact stable SDK request identity
     * @param primaryProof client primary signature
     * @param alternativeProof client alternative signature
     * @param canonicalOrigin configured listener origin
     * @param cancellation transport cancellation
     * @return normal retained ACME order response
     * @throws IllegalArgumentException if the selected order is unavailable to the authenticated account or the
     *         repeated SDK acceptance selects an order other than the retained original
     * @throws SecurityException if the authenticated account is inactive or its exact expected commitment
     *         changed
     * @throws NullPointerException if the expected account commitment is null
     */
    // Retains the existing public source and binary-compatible protocol contract.
    @SuppressWarnings({ "PMD.UseObjectForClearerAPI", "PMD.AvoidSynchronizedAtMethodLevel", "PMD.ExcessiveParameterList" })
    public synchronized AcmeState.Order acceptSdk(String accountId, String expectedAccountCommitment, String orderId,
            byte[] csrDer, String intentId, String sdkRequestId, byte[] primaryProof, byte[] alternativeProof,
            String canonicalOrigin, CancellationSignal cancellation) { return operations.enrollment.acceptSdk(new AcmeEnrollmentOperations.SdkAcceptance(accountId, expectedAccountCommitment, orderId, csrDer, intentId, sdkRequestId, primaryProof, alternativeProof, canonicalOrigin, cancellation)); }


    /**
     * Returns one account-owned authorization without revealing another account's state.
     *
     * @param accountId stable account identifier
     * @param authorizationId stable authorization identifier
     * @return account-owned authorization
     * @throws IllegalArgumentException if the selected authorization is unavailable to the account
     */
    public AcmeState.Authorization authorization(String accountId, String authorizationId) { return operations.challenges.authorization(accountId, authorizationId); }

    /**
     * Returns one account-owned challenge without URL-derived authority.
     *
     * @param accountId stable account identifier
     * @param challengeId stable challenge identifier
     * @return account-owned challenge
     */
    public AcmeState.Challenge challenge(String accountId, String challengeId) { return operations.challenges.challenge(accountId, challengeId); }

    /**
     * Issues or exactly replays confirmation proof material for one valid account-owned order.
     *
     * @param accountId stable account identifier
     * @param expectedAccountCommitment expected current account-record commitment
     * @param orderId stable order identifier
     * @return issued or replayed confirmation challenge
     * @throws IllegalStateException if the credential confirmation lifecycle is not pending
     */
    public CredentialConfirmationProofChallenge issueCredentialConfirmationChallenge(
            String accountId, String expectedAccountCommitment, String orderId) { return operations.confirmation.issueCredentialConfirmationChallenge(accountId, expectedAccountCommitment, orderId); }

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
    // Retains the existing public source and binary-compatible protocol contract.
    @SuppressWarnings({ "PMD.UseObjectForClearerAPI", "PMD.LongVariable" })
    public CredentialConfirmationProofResult completeCredentialConfirmation(
            String accountId, String expectedAccountCommitment, String orderId,
            long expectedLifecycleRevision, String expectedLifecycleRecordCommitment,
            String expectedChallengeRecordCommitment, byte[] response) { return operations.confirmation.completeCredentialConfirmation(accountId, expectedAccountCommitment, orderId, expectedLifecycleRevision, expectedLifecycleRecordCommitment, expectedChallengeRecordCommitment, response); }


    // Preserves the existing standalone-server monitor owner and atomic protocol transition ordering.


    /**
     * Installs the finalization fault injector for the current test thread.
     *
     * @param faults injector invoked at deterministic finalization boundaries; must not be null
     * @throws NullPointerException if the injector is null
     */
    /* default */ static void installFinalizeFault(FinalizeFaultInjector faults) {
        FINALIZE_FAULTS.set(Objects.requireNonNull(faults, "faults"));
    }

    /**
     * Removes the finalization fault injector from the current thread.
     */
    /* default */ static void clearFinalizeFault() {
        FINALIZE_FAULTS.remove();
    }

    /** Applies the current thread's selected deterministic test fault. */
    /* default */ static void tripFinalizeFault(FinalizeFaultPoint point) {
        FinalizeFaultInjector faults = FINALIZE_FAULTS.get();
        if (faults != null) {
            faults.fail(point);
        }
    }

    /** Exact selected credential and directory for one confirmation operation. */
    /* default */ record ConfirmationOrder(AcmeState.Directory directory, PkiId credentialId) { }

    /**
     * Deterministic finalization crash boundary.
     */
    /* default */ enum FinalizeFaultPoint {
        /**
         * Finalization has resolved its intent but has not attached the signing operation.
         */
        BEFORE_SIGNING_ATTACHMENT
    }

    /**
     * Package-local deterministic finalization failure seam.
     */
    /* default */
    @FunctionalInterface
    interface FinalizeFaultInjector {
        /**
         * Injects a test failure at the supplied finalization boundary.
         *
         * @param point boundary reached by the current finalization attempt
         */
        void fail(FinalizeFaultPoint point);
    }


}
