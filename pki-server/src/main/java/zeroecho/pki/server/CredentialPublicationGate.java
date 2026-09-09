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

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.application.PkiRepository;

/**
 * Synchronous stateless gate that freezes confirmation before leaf disclosure.
 *
 * <p>The gate accepts only a stable credential identity and an explicit typed
 * owner. Credential metadata and the exact profile version frozen by issuance
 * are resolved from authoritative session services. It never loads credential
 * payload bytes.</p>
 */
public final class CredentialPublicationGate {
    private final PkiRepository repository;
    private final ProfileService profiles;
    private final CredentialConfirmationService confirmations;
    private final DisclosureService disclosure;
    private final Clock clock;
    private final Runnable lifecycleGuard;

    /**
     * Explicit administrative audit identity, distinct from credential ownership.
     *
     * @param principalId canonical server principal identity
     */
    public record AuditActor(String principalId) {
        /** Validates the actor using the server principal-identity contract. */
        public AuditActor {
            principalId = Permission.requirePrincipal(principalId);
        }
    }

    /* default */ CredentialPublicationGate(PkiRepository repository, ProfileService profiles,
            CredentialConfirmationService confirmations, DisclosureService disclosure, Clock clock,
            Runnable lifecycleGuard) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.profiles = Objects.requireNonNull(profiles, "profiles");
        this.confirmations = Objects.requireNonNull(confirmations, "confirmations");
        this.disclosure = Objects.requireNonNull(disclosure, "disclosure");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.lifecycleGuard = Objects.requireNonNull(lifecycleGuard, "lifecycleGuard");
    }

    /**
     * Initializes or verifies confirmation, then registers or verifies disclosure.
     *
     * @param credentialId authoritative issued credential identity
     * @param owner optional explicit owner; never inferred from the current actor
     * @param auditActor explicit audit actor; never inferred from {@code owner}
     * @return newly registered or exactly matching existing disclosure record
     * @throws IllegalArgumentException if the credential or its frozen profile is unavailable
     * @throws IllegalStateException if authoritative state conflicts or the realm is closed
     */
    public DisclosureService.Record register(PkiId credentialId, Optional<DisclosureService.Owner> owner,
            AuditActor auditActor) {
        lifecycleGuard.run();
        PkiId exactCredentialId = Objects.requireNonNull(credentialId, "credentialId");
        Optional<DisclosureService.Owner> exactOwner = Objects.requireNonNull(owner, "owner");
        AuditActor exactActor = Objects.requireNonNull(auditActor, "auditActor");
        ResolvedCredential resolved = resolve(exactCredentialId);
        CredentialConfirmationPolicy policy = resolved.policy();
        validateOwner(policy, exactOwner);
        CredentialConfirmationLifecycle lifecycle = initializeOrVerify(exactCredentialId, policy);
        verifyLifecycle(lifecycle, exactCredentialId, policy);
        return disclosure.registerExact(exactCredentialId, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                disclosurePolicy(policy.disclosurePolicy()), exactOwner, policy.configurationCommitment(),
                exactActor.principalId());
    }

    /* default */ Permission.Resource publicationResource(RealmId realmId, PkiId credentialId,
            Optional<DisclosureService.Owner> owner) {
        Objects.requireNonNull(realmId, "realmId");
        PkiId exactCredentialId = Objects.requireNonNull(credentialId, "credentialId");
        ResolvedCredential resolved = resolve(exactCredentialId);
        validateOwner(resolved.policy(), Objects.requireNonNull(owner, "owner"));
        Permission.Scope scope = new Permission.Scope(realmId, Optional.of(resolved.authorityId()),
                Optional.empty(), Optional.of(resolved.profileId()));
        return new Permission.Resource(Permission.ResourceType.CERTIFICATE, scope,
                Optional.of(exactCredentialId), Optional.empty());
    }

    private ResolvedCredential resolve(PkiId credentialId) {
        Credential credential = repository.credential(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Credential is unavailable"));
        if (!credentialId.equals(credential.credentialId())) {
            throw new IllegalStateException("Authoritative credential identity differs");
        }
        if (!(credential.profileBinding() instanceof EndEntityProfileBinding binding)) {
            throw new IllegalStateException("Credential is not bound to an end-entity profile");
        }
        CertificateProfileRef reference = binding.reference();
        ImportedCertificateProfileVersion imported = profiles
                .getImportedVersion(reference.profileId(), reference.profileVersion())
                .orElseThrow(() -> new IllegalStateException("Frozen credential profile is unavailable"));
        if (!reference.equals(imported.reference())) {
            throw new IllegalStateException("Frozen credential profile reference differs");
        }
        CertificateProfileDefinition definition = imported.definition();
        CredentialConfirmationPolicy policy = definition.confirmationPolicy()
                .orElseThrow(() -> new IllegalStateException("Frozen credential confirmation policy is absent"));
        return new ResolvedCredential(credential.issuerRef().caId(), reference.profileId(), policy);
    }

    private CredentialConfirmationLifecycle initializeOrVerify(PkiId credentialId,
            CredentialConfirmationPolicy policy) {
        Optional<CredentialConfirmationLifecycle> existing = confirmations.get(credentialId);
        if (existing.isPresent()) {
            return existing.orElseThrow();
        }
        Instant reviewAt;
        try {
            reviewAt = clock.instant().plus(policy.confirmationWindow());
        } catch (DateTimeException | ArithmeticException ex) {
            throw new IllegalStateException("Confirmation review time is outside the supported range", ex);
        }
        CredentialConfirmationInitialization initialization = new CredentialConfirmationInitialization(
                credentialId, policy.disclosurePolicy(), policy.configurationCommitment(),
                policy.disclosurePolicy() != ConfirmationDisclosurePolicy.PUBLIC, reviewAt,
                policy.proofSuite());
        return confirmations.initialize(initialization);
    }

    private static void verifyLifecycle(CredentialConfirmationLifecycle lifecycle, PkiId credentialId,
            CredentialConfirmationPolicy policy) {
        CredentialConfirmationLifecycle exact = Objects.requireNonNull(lifecycle, "lifecycle");
        if (!exact.credentialId().equals(credentialId)
                || exact.initialPolicy() != policy.disclosurePolicy()
                || !exact.initialPolicyCommitment().equals(policy.configurationCommitment())
                || exact.confirmationRequired()
                        != (policy.disclosurePolicy() != ConfirmationDisclosurePolicy.PUBLIC)
                || !exact.proofSuite().equals(policy.proofSuite())) {
            throw new IllegalStateException("Credential confirmation lifecycle conflicts with frozen policy");
        }
    }

    private static DisclosureService.Policy disclosurePolicy(ConfirmationDisclosurePolicy policy) {
        return switch (policy) {
            case PUBLIC -> DisclosureService.Policy.PUBLIC;
            case PUBLIC_UNLISTED -> DisclosureService.Policy.PUBLIC_UNLISTED;
            case AUTHENTICATED -> DisclosureService.Policy.AUTHENTICATED;
            case OWNER_ONLY -> DisclosureService.Policy.OWNER_ONLY;
            case RESTRICTED -> DisclosureService.Policy.RESTRICTED;
            case NOT_PUBLISHED -> DisclosureService.Policy.NOT_PUBLISHED;
        };
    }

    private static boolean requiresOwner(ConfirmationDisclosurePolicy policy) {
        return policy == ConfirmationDisclosurePolicy.OWNER_ONLY;
    }

    private void validateOwner(CredentialConfirmationPolicy policy,
            Optional<DisclosureService.Owner> owner) {
        if (requiresOwner(policy.disclosurePolicy()) && owner.isEmpty()) {
            throw new IllegalArgumentException("Frozen disclosure policy requires an explicit owner");
        }
        disclosure.validateOwner(owner);
    }

    private record ResolvedCredential(PkiId authorityId, String profileId,
            CredentialConfirmationPolicy policy) { }
}
