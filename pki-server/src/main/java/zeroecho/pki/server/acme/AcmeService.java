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
import java.util.Optional;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.ServerControlStore;
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
 * disclosure policy. External validators return evidence only.</p>
 */
@SuppressWarnings("PMD")
public final class AcmeService {
    private static final String ZERO = "0".repeat(64);
    private final ServerRealmContext realm;
    private final AcmeControlStore store;
    private final Clock clock;
    private final SecureRandom random;
    private final Map<String, AcmeChallengeProvider> providers;
    private final Map<String, ProviderConfig> providerConfigurations;
    private final Map<String, AcmeExternalAccountBindingProvider> eabProviders;
    private final Map<String, ProviderConfig> eabProviderConfigurations;

    /** Creates a realm-bound ACME service from explicitly enabled providers. */
    public AcmeService(ServerRealmContext realm, Clock clock, SecureRandom random,
            Map<String, AcmeChallengeProvider> providers,
            Map<String, ProviderConfig> providerConfigurations,
            Map<String, AcmeExternalAccountBindingProvider> eabProviders,
            Map<String, ProviderConfig> eabProviderConfigurations) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.store = realm.acmeControl(); this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
        this.providers = Map.copyOf(Objects.requireNonNull(providers, "providers"));
        this.providerConfigurations = Map.copyOf(Objects.requireNonNull(providerConfigurations,
                "providerConfigurations"));
        this.eabProviders = Map.copyOf(Objects.requireNonNull(eabProviders, "eabProviders"));
        this.eabProviderConfigurations = Map.copyOf(Objects.requireNonNull(eabProviderConfigurations,
                "eabProviderConfigurations"));
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

    /** Creates an ACME service without EAB providers. */
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
                if (directory.status() == AcmeState.DirectoryStatus.ACTIVE) {
                    validateFrozenDirectory(directory);
                    if (directory.eabRequired() && directory.eabProviderId().isEmpty()) {
                        throw new IllegalStateException("Required ACME EAB provider is unavailable");
                    }
                    directory.eabProviderId().ifPresent(id -> {
                        if (!eabProviders.containsKey(id)) {
                            throw new IllegalStateException("ACME EAB provider is unavailable");
                        }
                    });
                }
            }
            if (!page.hasMore()) {
                return;
            }
            offset = page.nextOffset();
        } while (true);
    }

    /** Safe immutable directory-registration input. */
    public record DirectoryRegistration(String alias, PkiId authorityId, String profileId,
            Set<String> dnsNamespaces, Duration maximumValidity, Set<String> publicKeyAlgorithms,
            Set<String> x509BindingPolicies, Set<AcmeState.ChallengeType> challengeTypes,
            Set<String> challengeProviderIds, Optional<String> eabProviderId, boolean eabRequired,
            DisclosureService.Policy disclosurePolicy) {
        /** Validates required registration input before PKI resolution. */
        public DirectoryRegistration {
            Objects.requireNonNull(alias, "alias"); Objects.requireNonNull(authorityId, "authorityId");
            Objects.requireNonNull(profileId, "profileId"); dnsNamespaces = Set.copyOf(dnsNamespaces);
            Objects.requireNonNull(maximumValidity, "maximumValidity");
            publicKeyAlgorithms = Set.copyOf(publicKeyAlgorithms); x509BindingPolicies = Set.copyOf(x509BindingPolicies);
            challengeTypes = Set.copyOf(challengeTypes); challengeProviderIds = Set.copyOf(challengeProviderIds);
            eabProviderId = Objects.requireNonNull(eabProviderId, "eabProviderId");
            Objects.requireNonNull(disclosurePolicy, "disclosurePolicy");
        }
    }

    /** Registers one immutable inactive directory revision. */
    public synchronized AcmeState.Directory registerDirectory(DirectoryRegistration registration) {
        Objects.requireNonNull(registration, "registration");
        requireExposed(registration.authorityId());
        PkiSession session = realm.session();
        CaRecord authority = session.repository().authority(registration.authorityId())
                .orElseThrow(() -> new IllegalArgumentException("ACME authority is unavailable"));
        ActiveCertificateProfile profile = session.profiles().requireActiveProfile(registration.profileId());
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
        String policy = directoryPolicyCommitment(registration, profile, authority, path);
        AcmeState.Directory unsealed = new AcmeState.Directory(directoryId, registration.alias(), revision,
                realm.configuration().realmId(), authority.caId(), profile.reference(),
                authority.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment(),
                Set.of(AcmeState.IdentifierType.DNS), registration.dnsNamespaces(),
                registration.maximumValidity(), registration.publicKeyAlgorithms(),
                registration.x509BindingPolicies(), registration.challengeTypes(),
                registration.challengeProviderIds(), registration.eabProviderId(), registration.eabRequired(),
                registration.disclosurePolicy(), AcmeState.DirectoryStatus.INACTIVE, policy, clock.instant(), ZERO);
        return store.create(unsealed);
    }

    /** Activates one exact directory revision after revalidating all frozen PKI authority. */
    public synchronized AcmeState.Directory activateDirectory(String directoryId) {
        AcmeState.Directory current = requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.ACTIVE) return current;
        validateFrozenDirectory(current);
        for (AcmeState.Directory other : directoriesForAlias(current.alias())) {
            if (other.status() == AcmeState.DirectoryStatus.ACTIVE) {
                throw new IllegalStateException("Another ACME directory revision is active");
            }
        }
        AcmeState.Directory updated = copyDirectory(current, AcmeState.DirectoryStatus.ACTIVE);
        return (AcmeState.Directory) store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /** Deactivates new account/order admission while existing unexpired orders remain usable. */
    public synchronized AcmeState.Directory deactivateDirectory(String directoryId) {
        AcmeState.Directory current = requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.INACTIVE) return current;
        AcmeState.Directory updated = copyDirectory(current, AcmeState.DirectoryStatus.INACTIVE);
        return (AcmeState.Directory) store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /** Resolves the sole active directory revision for one public alias. */
    public AcmeState.Directory activeDirectory(String alias) {
        List<AcmeState.Directory> active = directoriesForAlias(alias).stream()
                .filter(value -> value.status() == AcmeState.DirectoryStatus.ACTIVE).toList();
        if (active.size() != 1) throw new IllegalArgumentException("ACME directory is unavailable");
        return active.get(0);
    }

    /** Returns one exact directory revision for administrative and protocol inspection. */
    public AcmeState.Directory directory(String directoryId) { return requireDirectory(directoryId); }

    /** Returns a deterministic bounded page of directory revisions. */
    public ServerControlStore.Page<AcmeState.Directory> directories(int offset, int limit) {
        return store.page(AcmeState.Directory.class, offset, limit);
    }

    /** Creates or returns an account under one exact active directory. */
    public synchronized AcmeState.Account createAccount(AcmeState.Directory directory, String keyThumbprint,
            byte[] publicKeySpki, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, boolean onlyReturnExisting) {
        requireActiveExact(directory);
        Optional<AcmeState.Account> existing = accountByThumbprint(directory.directoryId(), keyThumbprint);
        if (existing.isPresent()) return existing.orElseThrow();
        if (onlyReturnExisting) throw new IllegalArgumentException("ACME account does not exist");
        if (directory.eabRequired() && eabPolicyCommitment.isEmpty()) {
            throw new IllegalArgumentException("ACME external account binding is required");
        }
        Instant now = clock.instant();
        AcmeState.Account account = new AcmeState.Account(id("account"), directory.directoryId(),
                directory.revision(), directory.commitment(), keyThumbprint, publicKeySpki,
                AcmeState.AccountStatus.VALID, contacts, termsAgreed, eabPolicyCommitment, now, now, ZERO);
        AcmeState.Account created = store.create(account);
        audit("ACME_ACCOUNT_CREATED", created.accountId(), Map.of("directory", created.directoryId()));
        return created;
    }

    /** Resolves an account by its authenticated key identity within one directory. */
    public Optional<AcmeState.Account> accountByKey(String directoryId, String keyThumbprint) {
        return accountByThumbprint(directoryId, keyThumbprint);
    }

    /** Verifies EAB inside its explicit secret-confining provider and returns only a safe commitment. */
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

    /** Resolves one active account key for strict KID authentication. */
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

    /** Returns one account record without exposing contact data through transport automatically. */
    public AcmeState.Account account(String accountId) { return requireAccount(accountId); }

    /** Durably changes account status while preserving its key and history commitment. */
    public synchronized AcmeState.Account deactivateAccount(String accountId) {
        return deactivateAccount(requireAccount(accountId));
    }

    /** Durably changes account status after exact account-key authority revalidation. */
    public synchronized AcmeState.Account deactivateAccount(String accountId, String expectedCommitment) {
        return deactivateAccount(requireAuthenticatedAccount(accountId, expectedCommitment));
    }

    private AcmeState.Account deactivateAccount(AcmeState.Account current) {
        if (current.status() == AcmeState.AccountStatus.DEACTIVATED) return current;
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), AcmeState.AccountStatus.DEACTIVATED, current.contacts(),
                current.termsAgreed(), current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account deactivated = (AcmeState.Account) store.replace(
                List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
        audit("ACME_ACCOUNT_DEACTIVATED", current.accountId(), Map.of("directory", current.directoryId()));
        return deactivated;
    }

    /** Atomically replaces bounded account contact metadata without changing key authority. */
    public synchronized AcmeState.Account updateAccountContacts(String accountId, String expectedCommitment,
            List<String> contacts) {
        AcmeState.Account current = requireAuthenticatedAccount(accountId, expectedCommitment);
        if (current.status() != AcmeState.AccountStatus.VALID) {
            throw new IllegalStateException("ACME account is unavailable");
        }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), current.status(), contacts, current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account replaced = (AcmeState.Account) store.replace(
                List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
        audit("ACME_ACCOUNT_CONTACT_UPDATED", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /** Atomically replaces one account key after exact old-record authentication. */
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
                current.directoryRevision(), current.directoryCommitment(), replacementThumbprint,
                replacementSpki, current.status(), current.contacts(), current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), clock.instant(), ZERO);
        AcmeState.Account replaced = (AcmeState.Account) store.replace(
                List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
        audit("ACME_ACCOUNT_KEY_ROLLOVER", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /** Returns a deterministic bounded page of accounts for administrative inspection. */
    public ServerControlStore.Page<AcmeState.Account> accounts(int offset, int limit) {
        return store.page(AcmeState.Account.class, offset, limit);
    }

    /** Atomically creates one account-owned order, authorization, and challenge graph. */
    public synchronized AcmeState.Order createOrder(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory,
            List<AcmeState.Identifier> requested, Optional<Instant> notBefore, Optional<Instant> notAfter,
            Duration orderLifetime) {
        AcmeState.Account account = requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        requireAccountDirectory(account, directory);
        requireActiveExact(directory); List<AcmeState.Identifier> identifiers = canonicalIdentifiers(requested, directory);
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
                directory.commitment(), directory.authorityId(), directory.profile(), directory.issuerId(),
                directory.issuancePathId(), directory.issuancePathCommitment(), identifiers, notBefore, notAfter,
                AcmeState.OrderStatus.PENDING, authorizations.stream().map(AcmeState.Authorization::authorizationId).toList(),
                Optional.empty(), now, expires, ZERO);
        AcmeState.Order created = store.createOrderGraph(order, authorizations, challenges).order();
        audit("ACME_ORDER_CREATED", accountId, Map.of("order", created.orderId(),
                "directory", created.directoryId()));
        return created;
    }

    /** Counts pending nonterminal orders up to a caller-supplied finite bound. */
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

    /** Revokes one certificate issued to the authenticated account through the bound directory. */
    public synchronized RevocationRecord revokeCertificate(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory,
            byte[] certificateDer, RevocationReason reason) {
        Objects.requireNonNull(certificateDer, "certificateDer"); Objects.requireNonNull(reason, "reason");
        requireAuthenticatedAccount(accountId, expectedAccountCommitment);
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
        RevocationRecord revoked = realm.session().revocations().revokePermanently(new RevocationCommand.RevokePermanently(
                owning.credentialId().orElseThrow(), reason, EMPTY_ATTRIBUTES));
        audit("ACME_CERTIFICATE_REVOKED", accountId, Map.of("order", owning.orderId()));
        return revoked;
    }

    private static final AttributeSet EMPTY_ATTRIBUTES = new AttributeSet() {
        @Override public Set<AttributeId> ids() { return Set.of(); }
        @Override public Optional<AttributeValue> get(AttributeId id) { Objects.requireNonNull(id); return Optional.empty(); }
        @Override public List<AttributeValue> getAll(AttributeId id) { Objects.requireNonNull(id); return List.of(); }
    };

    /** Claims and performs one explicit challenge validation attempt. */
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
        AcmeState.Order order = requireOrder(authorization.orderId()); AcmeState.Directory directory = requireDirectory(order.directoryId());
        String keyAuthorization = current.token() + "." + accountKeyAuthorizationThumbprint(accountKeyThumbprint);
        AcmeChallengeProvider provider = providers.get(current.providerId());
        AcmeChallengeProvider.Result result;
        try {
            result = provider.validate(new AcmeChallengeProvider.Context(directory.directoryId(),
                    authorization.authorizationId(), authorization.identifier(), current.type(), current.token(),
                    keyAuthorization, current.attempt(), clock.instant(), deadline),
                    providerConfigurations.get(provider.id()), cancellation);
        } catch (RuntimeException failure) {
            result = new AcmeChallengeProvider.Result(false, "PROVIDER_FAILURE", clock.instant(), clock.instant().plus(Duration.ofMinutes(5)));
        }
        if (cancellation.isCancelled()) throw new IllegalStateException("ACME validation was cancelled");
        return completeChallenge(current, authorization, order, directory, accountId, expectedAccountCommitment,
                accountKeyThumbprint, keyAuthorization, result);
    }

    /** Finalizes a ready order through the existing strict CSR and issuance services. */
    public synchronized CredentialBundle finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer) {
        requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = requireOrder(orderId);
        if (!order.accountId().equals(accountId)) throw new IllegalArgumentException("ACME order unavailable");
        if (clock.instant().isAfter(order.expiresAt())) throw new IllegalStateException("ACME order expired");
        if (order.status() == AcmeState.OrderStatus.VALID) {
            return realm.session().issuance().orElseThrow().buildBundle(
                    new zeroecho.pki.api.issuance.BundleCommand(order.credentialId().orElseThrow(),
                            Optional.empty(), Optional.empty()));
        }
        if (order.status() != AcmeState.OrderStatus.READY && order.status() != AcmeState.OrderStatus.PROCESSING) {
            throw new IllegalStateException("ACME order is not ready");
        }
        AcmeState.Directory directory = requireDirectory(order.directoryId()); validateFrozenOrder(order, directory);
        ActiveCertificateProfile profile = realm.session().profiles().requireActiveProfile(order.profile().profileId());
        if (!profile.reference().equals(order.profile())) throw new IllegalStateException("ACME order profile changed");
        CertificationRequestService requests = realm.session().requests()
                .orElseThrow(() -> new IllegalStateException("ACME CSR capability is unavailable"));
        ParsedCertificationRequest parsed = requests.parse(new CertificationRequest(profile.definition().formatId(),
                new EncodedObject(Encoding.DER, csrDer.clone())));
        requireExactIdentifiers(parsed, order.identifiers());
        if (order.status() == AcmeState.OrderStatus.READY) {
            order = (AcmeState.Order) store.replace(List.of(new AcmeControlStore.Replacement(order,
                    copyOrder(order, AcmeState.OrderStatus.PROCESSING, Optional.empty())))).get(0);
        }
        IssuanceService issuance = realm.session().issuance()
                .orElseThrow(() -> new IllegalStateException("ACME issuance capability is unavailable"));
        Optional<Validity> validity = order.notBefore().isPresent()
                ? Optional.of(new Validity(order.notBefore().orElseThrow(), order.notAfter().orElseThrow()))
                : Optional.empty();
        IssuanceIntent intent = new IssuanceIntent(order.orderId(), issuanceCommitment(order, parsed), order.profile(),
                order.issuerId(), order.issuancePathId(), order.issuancePathCommitment());
        CredentialBundle bundle = issuance.issueEndEntity(new IssueEndEntityCommand(order.authorityId(), parsed,
                order.profile().profileId(), validity, Optional.of(intent)));
        if (!bundle.credential().issuerRef().issuerId().equals(order.issuerId())
                || !bundle.credential().issuerRef().chainPathId().equals(order.issuancePathId())) {
            throw new IllegalStateException("ACME issuance selection mismatch");
        }
        realm.disclosure().registerAcme(bundle.credential().credentialId(), directory.disclosurePolicy(), accountId,
                directory.policyCommitment());
        AcmeState.Order valid = copyOrder(order, AcmeState.OrderStatus.VALID,
                Optional.of(bundle.credential().credentialId()));
        store.replace(List.of(new AcmeControlStore.Replacement(order, valid)));
        audit("ACME_CERTIFICATE_ISSUED", accountId, Map.of("order", order.orderId(),
                "credential", bundle.credential().credentialId().value()));
        return bundle;
    }

    /** Returns one account-owned order without URL-based authority. */
    public AcmeState.Order order(String accountId, String orderId) {
        AcmeState.Order order = requireOrder(orderId);
        if (!order.accountId().equals(accountId)) throw new IllegalArgumentException("ACME order unavailable");
        return order;
    }

    /** Returns one account-owned authorization without revealing another account's state. */
    public AcmeState.Authorization authorization(String accountId, String authorizationId) {
        AcmeState.Authorization value = requireAuthorization(authorizationId);
        if (!value.accountId().equals(accountId)) throw new IllegalArgumentException("ACME authorization unavailable");
        return value;
    }

    /** Returns one account-owned challenge without URL-derived authority. */
    public AcmeState.Challenge challenge(String accountId, String challengeId) {
        AcmeState.Challenge value = requireChallenge(challengeId);
        authorization(accountId, value.authorizationId());
        return value;
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
        requireExposed(directory.authorityId()); CaRecord authority = realm.session().repository().authority(directory.authorityId())
                .orElseThrow(() -> new IllegalStateException("ACME directory authority is unavailable"));
        if (authority.state() != CaState.ACTIVE || !authority.currentIssuanceIssuerId().equals(directory.issuerId())
                || !authority.issuanceChainPathId().equals(directory.issuancePathId())) {
            throw new IllegalStateException("ACME directory issuance selection changed");
        }
        IssuerChainPath path = requireCurrentPath(authority);
        if (!path.pathCommitment().equals(directory.issuancePathCommitment())
                || !realm.session().profiles().requireActiveProfile(directory.profile().profileId()).reference()
                        .equals(directory.profile())) {
            throw new IllegalStateException("ACME directory frozen policy is unavailable");
        }
        requireProviders(directory.challengeTypes(), directory.challengeProviderIds());
    }
    private void validateFrozenOrder(AcmeState.Order order, AcmeState.Directory directory) {
        if (order.directoryRevision() != directory.revision()
                || !order.directoryCommitment().equals(directory.commitment())
                || !order.authorityId().equals(directory.authorityId())
                || !order.issuerId().equals(directory.issuerId())
                || !order.issuancePathId().equals(directory.issuancePathId())
                || !order.issuancePathCommitment().equals(directory.issuancePathCommitment())) {
            throw new IllegalStateException("ACME order directory binding mismatch");
        }
        validateFrozenDirectory(directory);
    }
    private void requireActiveExact(AcmeState.Directory directory) {
        AcmeState.Directory exact = requireDirectory(directory.directoryId());
        if (exact.status() != AcmeState.DirectoryStatus.ACTIVE || !exact.commitment().equals(directory.commitment())) {
            throw new IllegalStateException("ACME directory is inactive or changed");
        }
    }
    private void requireAccountDirectory(AcmeState.Account account, AcmeState.Directory directory) {
        if (account.status() != AcmeState.AccountStatus.VALID || !account.directoryId().equals(directory.directoryId())
                || account.directoryRevision() != directory.revision()
                || !account.directoryCommitment().equals(directory.commitment())) {
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
    private AcmeState.Directory copyDirectory(AcmeState.Directory v, AcmeState.DirectoryStatus status) { return new AcmeState.Directory(v.directoryId(), v.alias(), v.revision(), v.realmId(), v.authorityId(), v.profile(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifierTypes(), v.dnsNamespaces(), v.maximumValidity(), v.publicKeyAlgorithms(), v.x509BindingPolicies(), v.challengeTypes(), v.challengeProviderIds(), v.eabProviderId(), v.eabRequired(), v.disclosurePolicy(), status, v.policyCommitment(), v.createdAt(), ZERO); }
    private AcmeState.Order copyOrder(AcmeState.Order v, AcmeState.OrderStatus status, Optional<PkiId> credential) { return new AcmeState.Order(v.orderId(), v.accountId(), v.directoryId(), v.directoryRevision(), v.directoryCommitment(), v.authorityId(), v.profile(), v.issuerId(), v.issuancePathId(), v.issuancePathCommitment(), v.identifiers(), v.notBefore(), v.notAfter(), status, v.authorizationIds(), credential, v.createdAt(), v.expiresAt(), ZERO); }
    private String id(String prefix) { byte[] value = new byte[16]; random.nextBytes(value); return prefix + ":" + java.util.HexFormat.of().formatHex(value); }
    private String token() { byte[] value = new byte[32]; random.nextBytes(value); String result = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value); java.util.Arrays.fill(value, (byte) 0); return result; }
    private static String directoryPolicyCommitment(DirectoryRegistration r, ActiveCertificateProfile profile,
            CaRecord ca, IssuerChainPath path) {
        return digest(r.alias() + '\n' + ca.caId().value() + '\n' + profile.reference() + '\n'
                + ca.currentIssuanceIssuerId().value() + '\n' + path.pathId().value() + '\n'
                + path.pathCommitment() + '\n' + r.dnsNamespaces().stream().sorted().toList() + '\n'
                + r.maximumValidity() + '\n' + r.publicKeyAlgorithms().stream().sorted().toList() + '\n'
                + r.x509BindingPolicies().stream().sorted().toList() + '\n'
                + r.challengeTypes().stream().sorted().toList() + '\n'
                + r.challengeProviderIds().stream().sorted().toList() + '\n'
                + r.eabProviderId().orElse("NONE") + '\n' + r.eabRequired() + '\n' + r.disclosurePolicy());
    }
    private void audit(String action, String actor, Map<String, String> details) {
        realm.auditTransport(action, actor, details);
    }
    private static String issuanceCommitment(AcmeState.Order order, ParsedCertificationRequest parsed) { return digest(order.commitment() + '\n' + parsed.requestId().value()); }
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
