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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerControlOperation;

/**
 * Provides directory operations for the ACME service.
 */
final class AcmeDirectoryOperations {
    private static final int SINGLE_ACTIVE_DIRECTORY = 1;
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeDirectoryOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Returns configured challenge-provider identifiers and their supported challenge types.
     */
    /* default */ Map<String, Set<AcmeState.ChallengeType>> configuredChallengeProviders(){
        Map<String, Set<AcmeState.ChallengeType>> result = new java.util.TreeMap<>();
        owner.providers.forEach((id, provider) -> result.put(id, Set.copyOf(provider.challengeTypes())));
        return Map.copyOf(result);
    }

    /**
     * Returns the configured external account binding provider identifiers.
     */
    /* default */ Set<String> configuredEabProviders(){ return Set.copyOf(owner.eabProviders.keySet()); }

    /**
     * Checks recovered ACME state against the current runtime configuration.
     */
    /* default */ void validateRecoveredState(){
        int offset = 0;
        ServerControlStore.Page<AcmeState.Directory> page;
        do {
            page = owner.store.page(AcmeState.Directory.class, offset, 256);
            for (AcmeState.Directory directory : page.values()) {
                owner.operations.policy.validateFrozenDirectory(directory);
            }
            if (!page.hasMore()) {
                return;
            }
            offset = page.nextOffset();
        } while (page.hasMore());
    }

    /**
     * Resolves the profile precondition used to register a directory.
     */
    /* default */ ServerControlOperation.AcmeDirectoryProfilePrecondition resolveDirectoryProfilePrecondition(
            AcmeService.DirectoryRegistration registration){
        AcmeService.DirectoryRegistration exact = Objects.requireNonNull(registration, "registration");
        ActiveCertificateProfile active = owner.realm.session().profiles().requireActiveProfile(exact.profileId());
        if (active.definition().certificateType() != CertificateProfileKind.END_ENTITY) {
            throw new IllegalArgumentException("ACME profile must be an active end-entity profile");
        }
        CredentialConfirmationPolicy confirmation = active.definition().confirmationPolicy()
                .orElseThrow(() -> new IllegalArgumentException("ACME profile confirmation policy is unavailable"));
        return new ServerControlOperation.AcmeDirectoryProfilePrecondition(active.reference(),
                confirmation.configurationCommitment());
    }

    /**
     * Registers a directory using the selected profile precondition.
     */
    /* default */ AcmeState.Directory registerDirectory(AcmeService.DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition){
        return owner.store.create(owner.operations.policy.prepareDirectory(registration,profilePrecondition));
    }

    /**
     * Checks directory registration against the selected profile precondition.
     */
    /* default */ void validateDirectoryRegistration(AcmeService.DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition){
        owner.operations.policy.prepareDirectory(registration,profilePrecondition);
    }

    /**
     * Registers a directory using the selected profile precondition.
     */
    /* default */ AcmeState.Directory registerDirectory(AcmeService.DirectoryRegistration registration){
        return owner.registerDirectory(registration, owner.resolveDirectoryProfilePrecondition(registration));
    }

    /**
     * Activates the selected directory after validating its current dependencies.
     */
    /* default */ AcmeState.Directory activateDirectory(String directoryId){
        AcmeState.Directory current = owner.validateDirectoryActivation(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.ACTIVE) { return current; }
        AcmeState.Directory updated = owner.operations.shared.copyDirectory(current, AcmeState.DirectoryStatus.ACTIVE);
        return (AcmeState.Directory) owner.store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /**
     * Returns the selected directory after checking its activation prerequisites.
     */
    /* default */ AcmeState.Directory validateDirectoryActivation(String directoryId){
        AcmeState.Directory current = owner.operations.shared.requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.ACTIVE) { return current; }
        owner.operations.policy.validateFrozenDirectory(current);
        owner.operations.policy.requireAdmissionCapabilities(current);
        for (AcmeState.Directory other : owner.operations.directory.directoriesForAlias(current.alias())) {
            if (other.status() == AcmeState.DirectoryStatus.ACTIVE) {
                throw new IllegalStateException("Another ACME directory revision is active");
            }
        }
        return current;
    }

    /**
     * Deactivates the selected directory and retains the updated state.
     */
    /* default */ AcmeState.Directory deactivateDirectory(String directoryId){
        AcmeState.Directory current = owner.operations.shared.requireDirectory(directoryId);
        if (current.status() == AcmeState.DirectoryStatus.INACTIVE) { return current; }
        AcmeState.Directory updated = owner.operations.shared.copyDirectory(current, AcmeState.DirectoryStatus.INACTIVE);
        return (AcmeState.Directory) owner.store.replace(List.of(new AcmeControlStore.Replacement(current, updated))).get(0);
    }

    /**
     * Returns the active directory for the supplied alias.
     */
    /* default */ AcmeState.Directory activeDirectory(String alias){
        List<AcmeState.Directory> active = owner.operations.directory.directoriesForAlias(alias).stream()
                .filter(value -> value.status() == AcmeState.DirectoryStatus.ACTIVE).toList();
        if (active.size() != SINGLE_ACTIVE_DIRECTORY) { throw new IllegalArgumentException("ACME directory is unavailable"); }
        return active.get(0);
    }

    /**
     * Returns the nonce scope for the selected directory alias.
     */
    /* default */ String nonceScope(String alias){
        List<AcmeState.Directory> known = owner.operations.directory.directoriesForAlias(alias);
        if (known.isEmpty()) {
            throw new IllegalArgumentException("ACME directory alias is unavailable");
        }
        return known.get(0).alias();
    }

    /**
     * Returns the retained directory with the supplied identifier.
     */
    /* default */ AcmeState.Directory directory(String directoryId){ return owner.operations.shared.requireDirectory(directoryId); }

    /**
     * Returns the directory associated with the selected account.
     */
    /* default */ AcmeState.Directory accountDirectory(String accountId){
        return owner.operations.shared.requireDirectory(owner.operations.shared.requireAccount(accountId).directoryId());
    }

    /**
     * Returns the directory associated with the selected order.
     */
    /* default */ AcmeState.Directory orderDirectory(String orderId){
        return owner.operations.shared.requireDirectory(owner.operations.shared.requireOrder(orderId).directoryId());
    }

    /**
     * Returns the directory associated with the selected authorization.
     */
    /* default */ AcmeState.Directory authorizationDirectory(String authorizationId){
        AcmeState.Authorization authorization = owner.operations.shared.requireAuthorization(authorizationId);
        return owner.orderDirectory(authorization.orderId());
    }

    /**
     * Returns the directory associated with the selected challenge.
     */
    /* default */ AcmeState.Directory challengeDirectory(String challengeId){
        AcmeState.Challenge challenge = owner.operations.shared.requireChallenge(challengeId);
        return owner.authorizationDirectory(challenge.authorizationId());
    }

    /**
     * Returns a page of retained directories.
     */
    /* default */ ServerControlStore.Page<AcmeState.Directory> directories(int offset, int limit){
        return owner.store.page(AcmeState.Directory.class, offset, limit);
    }

    /**
     * Returns the next revision number for the supplied directory alias.
     */
    /* default */ int nextDirectoryRevision(String alias){
        return owner.operations.directory.directoriesForAlias(alias).stream().mapToInt(AcmeState.Directory::revision).max().orElse(0) + 1;
    }

    /**
     * Returns retained directories with the supplied alias.
     */
    /* default */ List<AcmeState.Directory> directoriesForAlias(String alias){
        List<AcmeState.Directory> result = new ArrayList<>(); int offset = 0;
        ServerControlStore.Page<AcmeState.Directory> page;
        do {
            page = owner.store.page(AcmeState.Directory.class, offset, 256);
            result.addAll(page.values().stream().filter(value -> value.alias().equals(alias)).toList());
            if (!page.hasMore()) { break; } offset = page.nextOffset();
        } while (page.hasMore());
        return List.copyOf(result);
    }
}
