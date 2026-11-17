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

import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.ServerControlOperation;

/**
 * Provides policy operations for the ACME service.
 */
final class AcmePolicyOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmePolicyOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Builds a directory with the selected profile, authority and policy bindings.
     */
    /* default */ AcmeState.Directory prepareDirectory(AcmeService.DirectoryRegistration registration,
            ServerControlOperation.AcmeDirectoryProfilePrecondition profilePrecondition){
        Objects.requireNonNull(registration, "registration");
        ServerControlOperation.AcmeDirectoryProfilePrecondition expected =
                Objects.requireNonNull(profilePrecondition, "profilePrecondition");
        owner.operations.policy.requireExposed(registration.authorityId());
        PkiSession session = owner.realm.session(); // NOPMD CloseResource - Borrowed realm session; realm owns its lifecycle.
        CaRecord authority = session.repository().authority(registration.authorityId())
                .orElseThrow(() -> new IllegalArgumentException("ACME authority is unavailable"));
        owner.operations.policy.requireActiveAuthority(authority);
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
                || !registration.x509BindingPolicies().equals(owner.operations.shared.bindingPolicy(profile))) {
            throw new IllegalArgumentException("ACME algorithm policy must exactly match the active profile");
        }
        IssuerChainPath path = owner.operations.policy.requireCurrentPath(authority);
        owner.operations.policy.requireProviders(registration.challengeTypes(), registration.challengeProviderIds());
        if (registration.eabRequired() && registration.eabProviderId().isEmpty()) {
            throw new IllegalArgumentException("ACME EAB policy is contradictory");
        }
        registration.eabProviderId().ifPresent(value -> {
            if (!owner.eabProviders.containsKey(value)) { throw new IllegalArgumentException("ACME EAB provider is unavailable"); }
        });
        int revision = owner.operations.directory.nextDirectoryRevision(registration.alias());
        String directoryId = "directory:" + registration.alias() + ":r" + revision;
        String policy = owner.operations.policy.directoryPolicyCommitment(registration, profile, confirmationPolicy, authority, path);
        AcmeState.Directory unsealed = new AcmeState.Directory(directoryId, registration.alias(), revision,
                owner.realm.configuration().realmId(), authority.caId(), profile.reference(), registration.enrollmentProfileId(),
                authority.currentIssuanceIssuerId(), path.pathId(), path.pathCommitment(),
                Set.of(AcmeState.IdentifierType.DNS), registration.dnsNamespaces(),
                registration.maximumValidity(), registration.publicKeyAlgorithms(),
                registration.x509BindingPolicies(), registration.challengeTypes(),
                registration.challengeProviderIds(), registration.eabProviderId(), registration.eabRequired(),
                confirmationPolicy, confirmationPolicy.configurationCommitment(),
                AcmeState.DirectoryStatus.INACTIVE, policy, owner.clock.instant(), AcmeService.ZERO);
        return unsealed;
    }

    /**
     * Checks the retained directory against its frozen policy bindings.
     */
    /* default */ void validateFrozenDirectory(AcmeState.Directory directory){
        if (!directory.realmId().equals(owner.realm.configuration().realmId())) {
            throw new IllegalStateException("ACME directory realm binding differs");
        }
        owner.operations.policy.requireExposed(directory.authorityId());
        owner.realm.session().repository().authority(directory.authorityId())
                .orElseThrow(() -> new IllegalStateException("ACME directory authority is unavailable"));
        IssuerChainPath path = owner.realm.session().repository().chainPath(directory.issuancePathId())
                .orElseThrow(() -> new IllegalStateException("ACME directory issuance path is unavailable"));
        ImportedCertificateProfileVersion imported = owner.operations.policy.requireFrozenProfile(directory);
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

    /**
     * Returns the certificate profile selected by the frozen directory binding.
     */
    /* default */ ImportedCertificateProfileVersion requireFrozenProfile(AcmeState.Directory directory){
        ImportedCertificateProfileVersion imported = owner.realm.session().profiles()
                .getImportedVersion(directory.profile().profileId(), directory.profile().profileVersion())
                .orElseThrow(() -> new IllegalStateException("ACME directory frozen profile is unavailable"));
        if (!directory.profile().equals(imported.reference())) {
            throw new IllegalStateException("ACME directory frozen profile differs");
        }
        return imported;
    }

    /**
     * Checks that the order retains the directory's selected issuance bindings.
     */
    /* default */ void validateFrozenOrder(AcmeState.Order order, AcmeState.Directory directory){
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
        owner.operations.policy.validateFrozenDirectory(directory);
    }

    /**
     * Checks that the directory permits new enrollment admission.
     */
    /* default */ void requireActiveAdmission(AcmeState.Directory directory){
        AcmeState.Directory exact = owner.operations.shared.requireDirectory(directory.directoryId());
        if (exact.status() != AcmeState.DirectoryStatus.ACTIVE
                || !exact.commitment().equals(directory.commitment())) {
            throw new IllegalStateException("ACME directory is inactive or changed");
        }
        owner.operations.policy.validateFrozenDirectory(exact);
        owner.operations.policy.requireAdmissionCapabilities(exact);
    }

    /**
     * Checks that the runtime provides the capabilities required for directory admission.
     */
    /* default */ void requireAdmissionCapabilities(AcmeState.Directory directory){
        owner.realm.enrollmentProfiles().requireBinding(directory.enrollmentProfileId(), directory.profile().profileId(),
                directory.authorityId().value(), true);
        CaRecord authority = owner.realm.session().repository().authority(directory.authorityId())
                .orElseThrow(() -> new IllegalStateException("ACME directory authority is unavailable"));
        owner.operations.policy.requireActiveAuthority(authority);
        if (!authority.currentIssuanceIssuerId().equals(directory.issuerId())
                || !authority.issuanceChainPathId().equals(directory.issuancePathId())) {
            throw new IllegalStateException("ACME directory issuance selection is no longer current");
        }
        owner.operations.policy.requireProviders(directory.challengeTypes(), directory.challengeProviderIds());
        if (directory.eabRequired() && directory.eabProviderId().isEmpty()) {
            throw new IllegalStateException("Required ACME EAB provider is unavailable");
        }
        directory.eabProviderId().ifPresent(id -> {
            if (!owner.eabProviders.containsKey(id)) {
                throw new IllegalStateException("ACME EAB provider is unavailable");
            }
        });
    }

    /**
     * Checks that the selected certificate authority is active.
     */
    /* default */ void requireActiveAuthority(CaRecord authority){
        if (authority.state() != CaState.ACTIVE) {
            throw new IllegalStateException("ACME authority is not active");
        }
    }

    /**
     * Checks that the account belongs to the selected directory.
     */
    /* default */ void requireAccountDirectory(AcmeState.Account account, AcmeState.Directory directory){
        if (account.status() != AcmeState.AccountStatus.VALID || !account.directoryId().equals(directory.directoryId())
                || account.directoryRevision() != directory.revision()
                || !account.directoryPolicyCommitment().equals(directory.policyCommitment())) {
            throw new IllegalArgumentException("ACME account directory mismatch");
        }
    }

    /**
     * Returns the current issuer path for the selected authority.
     */
    /* default */ IssuerChainPath requireCurrentPath(CaRecord authority){
        IssuerChainPath path = owner.realm.session().repository().chainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new IllegalArgumentException("ACME issuance path is unavailable"));
        if (!path.authorityId().equals(authority.caId())
                || !path.issuerId().equals(authority.currentIssuanceIssuerId())) {
            throw new IllegalArgumentException("ACME issuance path authority mismatch");
        }
        return path;
    }

    /**
     * Checks that the configured providers support the requested challenge types.
     */
    /* default */ void requireProviders(Set<AcmeState.ChallengeType> types, Set<String> ids){
        if (!owner.providers.keySet().containsAll(ids)) { throw new IllegalArgumentException("ACME challenge provider unavailable"); }
        for (AcmeState.ChallengeType type : types) {
            if (ids.stream().map(owner.providers::get).noneMatch(provider -> provider.challengeTypes().contains(type))) {
                throw new IllegalArgumentException("ACME challenge type has no provider");
            }
        }
    }

    /**
     * Returns the configured provider for the selected directory and challenge type.
     */
    /* default */ String providerFor(AcmeState.Directory directory, AcmeState.ChallengeType type){
        return directory.challengeProviderIds().stream().sorted().filter(id -> owner.providers.get(id).challengeTypes().contains(type))
                .findFirst().orElseThrow(() -> new IllegalStateException("ACME challenge provider is unavailable"));
    }

    /**
     * Checks that the selected authority is exposed by the realm configuration.
     */
    /* default */ void requireExposed(PkiId authorityId){
        if (!owner.realm.configuration().authorityExposure().allows(authorityId)) { throw new IllegalArgumentException("ACME authority is outside realm exposure"); }
    }

    /**
     * Computes the commitment for the selected directory policy and issuance bindings.
     */
    /* default */ String directoryPolicyCommitment(AcmeService.DirectoryRegistration r, ActiveCertificateProfile profile,
            CredentialConfirmationPolicy confirmationPolicy, CaRecord ca, IssuerChainPath path){
        return owner.operations.shared.digest(r.alias() + '\n' + ca.caId().value() + '\n' + profile.reference() + '\n' + r.enrollmentProfileId() + '\n'
                + ca.currentIssuanceIssuerId().value() + '\n' + path.pathId().value() + '\n'
                + path.pathCommitment() + '\n' + r.dnsNamespaces().stream().sorted().toList() + '\n'
                + r.maximumValidity() + '\n' + r.publicKeyAlgorithms().stream().sorted().toList() + '\n'
                + r.x509BindingPolicies().stream().sorted().toList() + '\n'
                + r.challengeTypes().stream().sorted().toList() + '\n'
                + r.challengeProviderIds().stream().sorted().toList() + '\n'
                + r.eabProviderId().orElse("NONE") + '\n' + r.eabRequired() + '\n'
                + confirmationPolicy.configurationCommitment());
    }
}
