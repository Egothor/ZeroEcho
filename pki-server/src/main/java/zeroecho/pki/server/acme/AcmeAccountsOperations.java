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

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;

/**
 * Provides accounts operations for the ACME service.
 */
final class AcmeAccountsOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeAccountsOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Creates an account or returns an existing account for the supplied directory and key.
     */
    /* default */ AcmeState.Account createAccount(AcmeState.Directory directory, String keyThumbprint,
            byte[] publicKeySpki, List<String> contacts, boolean termsAgreed,
            Optional<String> eabPolicyCommitment, boolean onlyReturnExisting){
        owner.operations.policy.requireActiveAdmission(directory);
        Optional<AcmeState.Account> existing = owner.operations.accounts.accountByThumbprint(directory.directoryId(), keyThumbprint);
        if (existing.isPresent()) { return existing.orElseThrow(); }
        if (onlyReturnExisting) { throw new IllegalArgumentException("ACME account does not exist"); }
        if (directory.eabRequired() && eabPolicyCommitment.isEmpty()) {
            throw new IllegalArgumentException("ACME external account binding is required");
        }
        Instant now = owner.clock.instant();
        AcmeState.Account account = new AcmeState.Account(owner.operations.shared.id("account"), directory.directoryId(),
                directory.revision(), directory.policyCommitment(), keyThumbprint, publicKeySpki,
                AcmeState.AccountStatus.VALID, contacts, termsAgreed, eabPolicyCommitment, now, now, AcmeService.ZERO);
        AcmeState.Account created = owner.operations.enrollment.enrollment().storeAcmeAccount(Optional.empty(), account);
        owner.operations.shared.audit("ACME_ACCOUNT_CREATED", created.accountId(), Map.of("directory", created.directoryId()));
        return created;
    }

    /**
     * Finds an account by its directory and public-key thumbprint.
     */
    /* default */ Optional<AcmeState.Account> accountByKey(String directoryId, String keyThumbprint){
        return owner.operations.accounts.accountByThumbprint(directoryId, keyThumbprint);
    }

    /**
     * Verifies an external account binding and returns its policy commitment when present.
     */
    /* default */ Optional<String> verifyExternalAccountBinding(AcmeState.Directory directory, String keyThumbprint,
            Optional<byte[]> nestedJws){
        Objects.requireNonNull(nestedJws, "nestedJws");
        if (directory.eabProviderId().isEmpty()) {
            if (nestedJws.isPresent()) { throw new IllegalArgumentException("ACME EAB is not enabled"); }
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
        AcmeExternalAccountBindingProvider provider = Optional.ofNullable(owner.eabProviders.get(providerId))
                .orElseThrow(() -> new IllegalStateException("ACME EAB provider is unavailable"));
        AcmeExternalAccountBindingProvider.Binding binding = provider.verify(
                new AcmeExternalAccountBindingProvider.Request(directory.directoryId(), directory.authorityId(),
                        directory.profile().profileId(), keyThumbprint, document, owner.clock.instant()),
                owner.eabProviderConfigurations.get(providerId));
        if (!binding.consumed() || !binding.expiresAt().isAfter(owner.clock.instant())
                || !binding.dnsNamespaces().containsAll(directory.dnsNamespaces())) {
            throw new SecurityException("ACME EAB policy is unavailable");
        }
        return Optional.of(binding.policyCommitment());
    }

    /**
     * Returns the public key retained for the account.
     */
    // Retains the established safe diagnostic or standalone monitor boundary.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    /* default */ AcmeJwsVerifier.AccountKey accountKey(String accountId, String kid){
        AcmeState.Account account = owner.operations.shared.requireAccount(accountId);
        if (account.status() != AcmeState.AccountStatus.VALID) { throw new IllegalArgumentException("ACME account unavailable"); }
        try {
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(account.publicKeySpki()));
            return new AcmeJwsVerifier.AccountKey(account.accountId(), kid, account.keyThumbprint(), key,
                    account.commitment());
        } catch (Exception failure) {
            throw new IllegalStateException("ACME account key is invalid");
        }
    }

    /**
     * Returns the retained account with the supplied identifier.
     */
    /* default */ AcmeState.Account account(String accountId){ return owner.operations.shared.requireAccount(accountId); }

    /**
     * Deactivates the selected account and retains the resulting account state.
     */
    /* default */ AcmeState.Account deactivateAccount(String accountId){
        return owner.operations.accounts.deactivateAccount(owner.operations.shared.requireAccount(accountId));
    }

    /**
     * Deactivates the selected account and retains the resulting account state.
     */
    /* default */ AcmeState.Account deactivateAccount(String accountId, String expectedCommitment){
        return owner.operations.accounts.deactivateAccount(owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedCommitment));
    }

    /**
     * Deactivates the selected account and retains the resulting account state.
     */
    /* default */ AcmeState.Account deactivateAccount(AcmeState.Account current){
        if (current.status() == AcmeState.AccountStatus.DEACTIVATED) { return current; }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), AcmeState.AccountStatus.DEACTIVATED, current.contacts(),
                current.termsAgreed(), current.eabPolicyCommitment(), current.createdAt(), owner.clock.instant(), AcmeService.ZERO);
        AcmeState.Account deactivated = owner.operations.enrollment.enrollment().storeAcmeAccount(Optional.of(current), updated);
        owner.operations.shared.audit("ACME_ACCOUNT_DEACTIVATED", current.accountId(), Map.of("directory", current.directoryId()));
        return deactivated;
    }

    /**
     * Updates account contacts after checking the expected account commitment.
     */
    /* default */ AcmeState.Account updateAccountContacts(String accountId, String expectedCommitment,
            List<String> contacts){
        AcmeState.Account current = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedCommitment);
        if (current.status() != AcmeState.AccountStatus.VALID) {
            throw new IllegalStateException("ACME account is unavailable");
        }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), current.keyThumbprint(),
                current.publicKeySpki(), current.status(), contacts, current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), owner.clock.instant(), AcmeService.ZERO);
        AcmeState.Account replaced = owner.operations.enrollment.enrollment().storeAcmeAccount(Optional.of(current), updated);
        owner.operations.shared.audit("ACME_ACCOUNT_CONTACT_UPDATED", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /**
     * Replaces the account key after checking the expected account commitment.
     */
    /* default */ AcmeState.Account rolloverAccount(String accountId, String expectedCommitment,
            String replacementThumbprint, byte[] replacementSpki){
        AcmeState.Account current = owner.operations.shared.requireAccount(accountId);
        if (current.status() != AcmeState.AccountStatus.VALID
                || !current.commitment().equals(expectedCommitment)
                || current.keyThumbprint().equals(replacementThumbprint)
                || owner.operations.accounts.accountByThumbprint(current.directoryId(), replacementThumbprint).isPresent()) {
            throw new SecurityException("ACME account key rollover is unavailable");
        }
        AcmeState.Account updated = new AcmeState.Account(current.accountId(), current.directoryId(),
                current.directoryRevision(), current.directoryPolicyCommitment(), replacementThumbprint,
                replacementSpki, current.status(), current.contacts(), current.termsAgreed(),
                current.eabPolicyCommitment(), current.createdAt(), owner.clock.instant(), AcmeService.ZERO);
        AcmeState.Account replaced = owner.operations.enrollment.enrollment().storeAcmeAccount(Optional.of(current), updated);
        owner.operations.shared.audit("ACME_ACCOUNT_KEY_ROLLOVER", accountId, Map.of("directory", current.directoryId()));
        return replaced;
    }

    /**
     * Returns a page of retained accounts.
     */
    /* default */ ServerControlStore.Page<AcmeState.Account> accounts(int offset, int limit){
        return owner.store.page(AcmeState.Account.class, offset, limit);
    }

    /**
     * Finds an account with the supplied directory and key thumbprint.
     */
    /* default */ Optional<AcmeState.Account> accountByThumbprint(String directoryId, String thumbprint){
        int offset = 0;
        ServerControlStore.Page<AcmeState.Account> page;
        do {
            page = owner.store.page(AcmeState.Account.class, offset, 256);
            Optional<AcmeState.Account> found = page.values().stream().filter(value -> value.directoryId().equals(directoryId)
                    && value.keyThumbprint().equals(thumbprint)).findFirst();
            if (found.isPresent() || !page.hasMore()) { return found; } offset = page.nextOffset();
        } while (page.hasMore());
            return Optional.empty();
    }

    /**
     * Returns an account whose retained commitment matches the authenticated request.
     */
    /* default */ AcmeState.Account requireAuthenticatedAccount(String id, String expectedCommitment){
        AcmeState.Account account = owner.operations.shared.requireAccount(id);
        if (account.status() != AcmeState.AccountStatus.VALID
                || !account.commitment().equals(Objects.requireNonNull(expectedCommitment,
                        "expectedCommitment"))) {
            throw new SecurityException("ACME account key authority changed");
        }
        return account;
    }
}
