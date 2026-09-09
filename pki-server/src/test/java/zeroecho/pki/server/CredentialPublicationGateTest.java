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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.application.PkiRepository;

class CredentialPublicationGateTest {
    private static final Instant NOW = Instant.parse("2026-08-29T10:15:30Z");
    private static final PkiId CREDENTIAL_ID = new PkiId("credential-publication-a");
    private static final DisclosureService.Owner OWNER = DisclosureService.Owner.acmeAccount("account-a");
    private static final Optional<DisclosureService.Owner> OPTIONAL_OWNER = Optional.of(OWNER);
    private static final CredentialPublicationGate.AuditActor AUDIT_ACTOR =
            new CredentialPublicationGate.AuditActor("publication-operator");

    @Test
    void initializesConfirmationBeforeRegisteringDisclosureWithoutOpeningPayload() {
        Fixture fixture = fixture(ConfirmationDisclosurePolicy.OWNER_ONLY, Clock.fixed(NOW, ZoneOffset.UTC));
        when(fixture.confirmations().get(CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(fixture.confirmations().initialize(any(CredentialConfirmationInitialization.class)))
                .thenAnswer(invocation -> CredentialConfirmationLifecycle.initialize(invocation.getArgument(0)));
        DisclosureService.Record expected = disclosureRecord(fixture.policy(), OWNER, NOW);
        when(fixture.disclosure().registerExact(CREDENTIAL_ID, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                DisclosureService.Policy.OWNER_ONLY, OPTIONAL_OWNER, fixture.policy().configurationCommitment(),
                AUDIT_ACTOR.principalId()))
                .thenReturn(expected);

        DisclosureService.Record actual = fixture.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR);

        assertSame(expected, actual);
        ArgumentCaptor<CredentialConfirmationInitialization> initialization =
                ArgumentCaptor.forClass(CredentialConfirmationInitialization.class);
        InOrder order = inOrder(fixture.confirmations(), fixture.disclosure());
        order.verify(fixture.confirmations()).get(CREDENTIAL_ID);
        order.verify(fixture.confirmations()).initialize(initialization.capture());
        order.verify(fixture.disclosure()).registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.OWNER_ONLY, OPTIONAL_OWNER,
                fixture.policy().configurationCommitment(), AUDIT_ACTOR.principalId());
        assertEquals(NOW.plus(Duration.ofHours(24L)), initialization.getValue().confirmationReviewAt());
        assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                CredentialConfirmationLifecycle.initialize(initialization.getValue()).state());
        verify(fixture.repository(), never()).openCredential(any());
    }

    @Test
    void exactReplayUsesFrozenLifecycleAndPublicPolicyIsNotRequired() {
        Fixture fixture = fixture(ConfirmationDisclosurePolicy.PUBLIC,
                Clock.fixed(NOW.plus(Duration.ofDays(30L)), ZoneOffset.UTC));
        CredentialConfirmationInitialization initialization = new CredentialConfirmationInitialization(
                CREDENTIAL_ID, ConfirmationDisclosurePolicy.PUBLIC, fixture.policy().configurationCommitment(),
                false, NOW.plus(Duration.ofHours(24L)), fixture.policy().proofSuite());
        CredentialConfirmationLifecycle existing = CredentialConfirmationLifecycle.initialize(initialization);
        when(fixture.confirmations().get(CREDENTIAL_ID)).thenReturn(Optional.of(existing));
        DisclosureService.Record expected = disclosureRecord(fixture.policy(), OWNER, NOW);
        when(fixture.disclosure().registerExact(CREDENTIAL_ID, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                DisclosureService.Policy.PUBLIC, OPTIONAL_OWNER, fixture.policy().configurationCommitment(),
                AUDIT_ACTOR.principalId()))
                .thenReturn(expected);

        assertSame(expected, fixture.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR));

        assertEquals(CredentialConfirmationLifecycle.State.NOT_REQUIRED, existing.state());
        verify(fixture.confirmations(), never()).initialize(any());
    }

    @Test
    void lifecycleOrProfileConflictFailsBeforeDisclosure() {
        Fixture fixture = fixture(ConfirmationDisclosurePolicy.OWNER_ONLY, Clock.fixed(NOW, ZoneOffset.UTC));
        CredentialConfirmationPolicy publicPolicy = policy(ConfirmationDisclosurePolicy.PUBLIC);
        CredentialConfirmationLifecycle conflicting = CredentialConfirmationLifecycle.initialize(
                new CredentialConfirmationInitialization(CREDENTIAL_ID, ConfirmationDisclosurePolicy.PUBLIC,
                        publicPolicy.configurationCommitment(), false, NOW, publicPolicy.proofSuite()));
        when(fixture.confirmations().get(CREDENTIAL_ID)).thenReturn(Optional.of(conflicting));

        assertThrows(IllegalStateException.class,
                () -> fixture.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR));
        verify(fixture.disclosure(), never()).registerExact(any(), any(), any(), any(),
                any(), any());

        ImportedCertificateProfileVersion imported = fixture.imported();
        byte[] differentHash = new byte[CertificateProfileRef.HASH_BYTES];
        differentHash[0] = 1;
        CertificateProfileRef mismatched = new CertificateProfileRef(imported.reference().profileId(),
                imported.reference().profileVersion(), differentHash);
        Credential credential = mock(Credential.class);
        when(credential.credentialId()).thenReturn(CREDENTIAL_ID);
        when(credential.issuerRef()).thenReturn(new IssuerRef(ServerTestSupport.AUTHORITY));
        when(credential.profileBinding()).thenReturn(new EndEntityProfileBinding(mismatched));
        when(fixture.repository().credential(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        assertThrows(IllegalStateException.class,
                () -> fixture.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR));
    }

    @Test
    void confirmationFailureOrReviewTimeOverflowNeverRegistersDisclosure() {
        Fixture failure = fixture(ConfirmationDisclosurePolicy.OWNER_ONLY, Clock.fixed(NOW, ZoneOffset.UTC));
        when(failure.confirmations().get(CREDENTIAL_ID)).thenReturn(Optional.empty());
        when(failure.confirmations().initialize(any())).thenThrow(new IllegalStateException("durability unknown"));
        assertThrows(IllegalStateException.class,
                () -> failure.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR));
        verify(failure.disclosure(), never()).registerExact(any(), any(), any(), any(),
                any(), any());

        Fixture overflow = fixture(ConfirmationDisclosurePolicy.OWNER_ONLY,
                Clock.fixed(Instant.MAX.minusSeconds(1L), ZoneOffset.UTC));
        when(overflow.confirmations().get(CREDENTIAL_ID)).thenReturn(Optional.empty());
        assertThrows(IllegalStateException.class,
                () -> overflow.gate().register(CREDENTIAL_ID, OPTIONAL_OWNER, AUDIT_ACTOR));
        verify(overflow.confirmations(), never()).initialize(any());
        verify(overflow.disclosure(), never()).registerExact(any(), any(), any(), any(),
                any(), any());
    }

    @Test
    void disclosureRegistrationIsExactReplayAndRejectsEveryCorrelationMismatch() {
        ServerControlStore store = mock(ServerControlStore.class);
        AtomicReference<DisclosureService.Record> durable = new AtomicReference<>();
        AtomicReference<AuditEvent> auditEvent = new AtomicReference<>();
        when(store.findDisclosure(CREDENTIAL_ID)).thenAnswer(ignored -> Optional.ofNullable(durable.get()));
        org.mockito.Mockito.doAnswer(invocation -> {
            durable.set(invocation.getArgument(0));
            return null;
        }).when(store).createDisclosure(any());
        DisclosureService service = new DisclosureService(new RealmId("realm-a"), store,
                DisclosureService.Defaults.recommended(), Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(),
                auditEvent::set);
        String commitment = "a".repeat(64);

        DisclosureService.Record first = service.registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.OWNER_ONLY,
                OPTIONAL_OWNER, commitment, AUDIT_ACTOR.principalId());
        DisclosureService.Record replay = service.registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.OWNER_ONLY,
                OPTIONAL_OWNER, commitment, AUDIT_ACTOR.principalId());

        assertSame(first, replay);
        assertEquals(AUDIT_ACTOR.principalId(), auditEvent.get().principal().name());
        verify(store, times(1)).createDisclosure(any());
        assertThrows(IllegalStateException.class, () -> service.registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.PUBLIC,
                OPTIONAL_OWNER, commitment, AUDIT_ACTOR.principalId()));
        assertThrows(IllegalStateException.class, () -> service.registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.OWNER_ONLY,
                Optional.of(DisclosureService.Owner.acmeAccount("account-b")), commitment,
                AUDIT_ACTOR.principalId()));
        assertThrows(IllegalStateException.class, () -> service.registerExact(CREDENTIAL_ID,
                DisclosureService.ObjectType.LEAF_CERTIFICATE, DisclosureService.Policy.OWNER_ONLY,
                OPTIONAL_OWNER, "b".repeat(64), AUDIT_ACTOR.principalId()));
        assertThrows(IllegalArgumentException.class,
                () -> new CredentialPublicationGate.AuditActor("invalid actor"));
    }

    private static Fixture fixture(ConfirmationDisclosurePolicy disclosurePolicy, Clock clock) {
        PkiRepository repository = mock(PkiRepository.class);
        ProfileService profiles = mock(ProfileService.class);
        CredentialConfirmationService confirmations = mock(CredentialConfirmationService.class);
        DisclosureService disclosure = mock(DisclosureService.class);
        ImportedCertificateProfileVersion imported = imported(disclosurePolicy);
        Credential credential = mock(Credential.class);
        when(credential.credentialId()).thenReturn(CREDENTIAL_ID);
        when(credential.issuerRef()).thenReturn(new IssuerRef(ServerTestSupport.AUTHORITY));
        when(credential.profileBinding()).thenReturn(new EndEntityProfileBinding(imported.reference()));
        when(repository.credential(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        when(profiles.getImportedVersion(imported.reference().profileId(), imported.reference().profileVersion()))
                .thenReturn(Optional.of(imported));
        CredentialPublicationGate gate = new CredentialPublicationGate(repository, profiles, confirmations,
                disclosure, clock, () -> { });
        return new Fixture(gate, repository, confirmations, disclosure, imported,
                imported.definition().confirmationPolicy().orElseThrow());
    }

    private static ImportedCertificateProfileVersion imported(ConfirmationDisclosurePolicy disclosurePolicy) {
        BuiltInCertificateProfileTemplate template = BuiltInCertificateProfileCatalog
                .load(CredentialPublicationGateTest.class.getClassLoader()).stream()
                .filter(candidate -> candidate.definition().profileId().equals("server-tls"))
                .findFirst().orElseThrow();
        CertificateProfileDefinition base = template.definition();
        CertificateProfileDefinition definition = new CertificateProfileDefinition(base.certificateType(),
                base.profileId(), base.profileVersion(), base.formatId(), base.displayName(), base.maximumValidity(),
                base.subjectPolicy(), base.certificatePolicy(), base.algorithmBindingPolicy(),
                Optional.of(policy(disclosurePolicy)));
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        CertificateProfileRef reference = new CertificateProfileRef(definition.profileId(),
                definition.profileVersion(), new byte[CertificateProfileRef.HASH_BYTES]);
        return new ImportedCertificateProfileVersion(reference, CertificateProfileDefinition.SCHEMA_VERSION,
                definition, canonical, NOW);
    }

    private static CredentialConfirmationPolicy policy(ConfirmationDisclosurePolicy disclosurePolicy) {
        CredentialConfirmationPolicy standard = BuiltInCertificateProfileCatalog
                .load(CredentialPublicationGateTest.class.getClassLoader()).stream()
                .filter(candidate -> candidate.definition().profileId().equals("server-tls"))
                .findFirst().orElseThrow().definition().confirmationPolicy().orElseThrow();
        return new CredentialConfirmationPolicy(disclosurePolicy, standard.confirmationWindow(),
                standard.proofSuite());
    }

    private static DisclosureService.Record disclosureRecord(CredentialConfirmationPolicy policy,
            DisclosureService.Owner owner, Instant updatedAt) {
        Optional<String> principal = owner.type() == DisclosureService.Owner.OwnerType.SECURITY_PRINCIPAL
                ? Optional.of(owner.ownerId()) : Optional.empty();
        Optional<String> account = owner.type() == DisclosureService.Owner.OwnerType.ACME_ACCOUNT
                ? Optional.of(owner.ownerId()) : Optional.empty();
        return new DisclosureService.Record(CREDENTIAL_ID, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                DisclosureService.Policy.valueOf(policy.disclosurePolicy().name()), principal, account,
                policy.configurationCommitment(), updatedAt);
    }

    private record Fixture(CredentialPublicationGate gate, PkiRepository repository,
            CredentialConfirmationService confirmations, DisclosureService disclosure,
            ImportedCertificateProfileVersion imported, CredentialConfirmationPolicy policy) { }
}
