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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.server.AuthorityExposurePolicy;
import zeroecho.pki.server.CredentialPublicationGate;
import zeroecho.pki.server.DisclosureService;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Restart recovery at the durable-ledger/order attachment boundary. */
class AcmeContinuationRecoveryTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path temporaryDirectory;
    private static final Instant NOW = Instant.parse("2026-08-20T10:00:00Z");
    private static final String DIRECTORY_ID = "directory:restart:r1";
    private static final String ORDER_ID = "order:restart";
    private static final String ACCOUNT_ID = "account:restart";

    @Test
    void pollingAttachesSameLedgerOperationAfterCrashBeforeOrderAttachment() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = new PkiId("signing:restart");
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        CertificateProfileRef profile = new CertificateProfileRef("leaf", 1, new byte[32]);
        AcmeState.Directory directory = directory(authorityId, issuerId, path, profile);
        AtomicReference<AcmeState.Order> stored = new AtomicReference<>(crashedOrder(directory));

        AcmeControlStore control = mock(AcmeControlStore.class);
        when(control.page(AcmeState.Directory.class, 0, 256))
                .thenReturn(new ServerControlStore.Page<>(List.of(), 0, false));
        when(control.get(AcmeState.Directory.class, DIRECTORY_ID)).thenReturn(Optional.of(directory));
        when(control.get(AcmeState.Order.class, ORDER_ID)).thenAnswer(ignored -> Optional.of(stored.get()));
        when(control.replace(any())).thenAnswer(invocation -> invocation.<List<AcmeControlStore.Replacement>>getArgument(0)
                .stream().map(replacement -> {
                    AcmeState.Order next = (AcmeState.Order) replacement.next();
                    stored.set(next);
                    return next;
                }).toList());

        PkiRepository repository = mock(PkiRepository.class);
        when(repository.authority(authorityId)).thenReturn(Optional.of(new CaRecord(authorityId, CaKind.ROOT,
                CaState.ACTIVE, new KeyRef("key:restart"), new SubjectRef("CN=Restart"), List.of(issuerId),
                issuerId, path.pathId())));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        ProfileService profiles = mock(ProfileService.class);
        ActiveCertificateProfile active = mock(ActiveCertificateProfile.class);
        CertificateProfileDefinition definition = mock(CertificateProfileDefinition.class);
        when(active.reference()).thenReturn(profile);
        when(active.definition()).thenReturn(definition);
        when(definition.confirmationPolicy()).thenReturn(Optional.of(confirmationPolicy()));
        ImportedCertificateProfileVersion imported = mock(ImportedCertificateProfileVersion.class);
        when(imported.reference()).thenReturn(profile);
        when(imported.definition()).thenReturn(definition);
        when(profiles.getImportedVersion(profile.profileId(), profile.profileVersion()))
                .thenReturn(Optional.of(imported));
        when(profiles.requireActiveProfile(profile.profileId())).thenReturn(active);
        PkiSession session = mock(PkiSession.class);
        when(session.repository()).thenReturn(repository);
        when(session.profiles()).thenReturn(profiles);
        SemanticSigningService signing = mock(SemanticSigningService.class);
        when(session.semanticSigning()).thenReturn(Optional.of(signing));
        when(signing.findIssuance(any(RetainedIssuanceBinding.class)))
                .thenReturn(Optional.of(snapshot(operationId, authorityId, profile.profileId(), false)));

        ServerRealmContext realm = mock(ServerRealmContext.class);
        ServerRealmConfiguration configuration = mock(ServerRealmConfiguration.class);
        when(configuration.realmId()).thenReturn(new RealmId("restart"));
        when(configuration.authorityExposure()).thenReturn(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false));
        when(realm.configuration()).thenReturn(configuration);
        when(realm.acmeControl()).thenReturn(control);
        when(realm.session()).thenReturn(session);
        when(realm.enrollmentProfiles()).thenReturn(mock(zeroecho.pki.server.enrollment.EnrollmentProfileService.class));
        AcmeChallengeProvider provider = mock(AcmeChallengeProvider.class);
        when(provider.id()).thenReturn("http");
        when(provider.challengeTypes()).thenReturn(Set.of(AcmeState.ChallengeType.HTTP_01));
        AcmeService service = new AcmeService(realm, Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(),
                Map.of("http", provider), Map.of("http", new ProviderConfig("http", Map.of())));

        AcmeState.Account account = account(directory);
        when(control.get(AcmeState.Account.class, ACCOUNT_ID)).thenReturn(Optional.of(account));
        zeroecho.pki.server.enrollment.EnrollmentCoordinator enrollment = installEnrollment(realm, directory,
                snapshot(operationId, authorityId, profile.profileId(), false), null);
        org.junit.jupiter.api.Assertions.assertThrows(SecurityException.class,
                () -> service.order(ACCOUNT_ID, "9".repeat(64), ORDER_ID));
        zeroecho.pki.server.enrollment.EnrollmentTransaction.Intent intent = enrollment.find(null, null, null, null, null, null)
                .orElseThrow().intent();
        when(intent.authorityId()).thenReturn(new PkiId("ca:substituted"));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                () -> service.order(ACCOUNT_ID, account.commitment(), ORDER_ID));
        when(intent.authorityId()).thenReturn(authorityId);
        verify(enrollment, org.mockito.Mockito.never()).dispatch(any(), any());
        AcmeService.installFinalizeFault(point -> { throw new IllegalStateException("Simulated attachment crash"); });
        try {
            org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,
                    () -> service.order(ACCOUNT_ID, account.commitment(), ORDER_ID));
            assertEquals(Optional.empty(), stored.get().signingOperationId());
        } finally {
            AcmeService.clearFinalizeFault();
        }
        AcmeState.Order recovered = service.order(ACCOUNT_ID, account.commitment(), ORDER_ID);

        assertEquals(AcmeState.OrderStatus.PROCESSING, recovered.status());
        assertEquals(Optional.of(operationId), recovered.signingOperationId());
        assertEquals(stored.get(), recovered);
    }

    @Test
    void processingApprovalBindingSurvivesCodecRoundTripWithoutFakeSigningReceipt() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(new PkiId("x509:restart")));
        AcmeState.Directory directory = directory(authorityId, issuerId, path,
                new CertificateProfileRef("leaf", 1, new byte[32]));
        AcmeState.Order processing = copyLifecycle(crashedOrder(directory), AcmeState.OrderStatus.PROCESSING,
                Optional.of("3".repeat(64)), Optional.empty(), "0".repeat(64));
        AcmeStateCodec codec = new AcmeStateCodec();
        AcmeState.Order sealed = (AcmeState.Order) codec.seal(processing);
        assertEquals(sealed, codec.decode(codec.encode(sealed)));
        assertEquals(Optional.empty(), sealed.signingOperationId());
        assertEquals(Optional.of("3".repeat(64)), sealed.issuanceCommitment());
    }

    private enum Scenario { NORMAL, CANCEL_BEFORE_ACCEPT, MUTATE_CALLER_CSR, UNCERTAIN_ACCEPT }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(Scenario.class)
    void repeatedFinalizeReusesCoordinatorBindingAcrossRestart(Scenario scenario) throws Exception {
        try (zeroecho.pki.server.SemanticPreparationFixture custody =
                zeroecho.pki.server.SemanticPreparationFixture.open(temporaryDirectory.resolve("custody"))) {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = custody.prepared().receipt().operationId();
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        CertificateProfileRef profile = new CertificateProfileRef("leaf", 1, new byte[32]);
        AcmeState.Directory directory = directory(authorityId, issuerId, path, profile);
        AcmeState.Order ready = copyLifecycle(crashedOrder(directory), AcmeState.OrderStatus.READY,
                Optional.empty(), Optional.empty(), "4".repeat(64));
        AtomicReference<AcmeState.Order> stored = new AtomicReference<>(ready);
        AcmeState.Account account = new AcmeState.Account(ACCOUNT_ID, DIRECTORY_ID,
                directory.revision(), directory.policyCommitment(), "7".repeat(64), java.util.HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                AcmeState.AccountStatus.VALID, List.of(), true, Optional.empty(), NOW, NOW,
                "8".repeat(64));

        AcmeControlStore control = mock(AcmeControlStore.class);
        when(control.page(AcmeState.Directory.class, 0, 256))
                .thenReturn(new ServerControlStore.Page<>(List.of(), 0, false));
        when(control.get(AcmeState.Account.class, ACCOUNT_ID)).thenReturn(Optional.of(account));
        when(control.get(AcmeState.Directory.class, DIRECTORY_ID)).thenReturn(Optional.of(directory));
        when(control.get(AcmeState.Order.class, ORDER_ID)).thenAnswer(ignored -> Optional.of(stored.get()));
        when(control.replace(any())).thenAnswer(invocation -> invocation
                .<List<AcmeControlStore.Replacement>>getArgument(0).stream().map(replacement -> {
                    AcmeState.Order next = (AcmeState.Order) replacement.next();
                    stored.set(next);
                    return next;
                }).toList());

        PkiRepository repository = mock(PkiRepository.class);
        when(repository.authority(authorityId)).thenReturn(Optional.of(new CaRecord(authorityId, CaKind.ROOT,
                CaState.ACTIVE, new KeyRef("key:restart"), new SubjectRef("CN=Restart"), List.of(issuerId),
                issuerId, path.pathId())));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        ProfileService profiles = mock(ProfileService.class);
        ActiveCertificateProfile active = mock(ActiveCertificateProfile.class);
        zeroecho.pki.api.profile.CertificateProfileDefinition definition =
                mock(zeroecho.pki.api.profile.CertificateProfileDefinition.class);
        when(active.reference()).thenReturn(profile);
        when(active.definition()).thenReturn(definition);
        when(definition.formatId()).thenReturn(new FormatId("X509"));
        when(definition.confirmationPolicy()).thenReturn(Optional.of(confirmationPolicy()));
        ImportedCertificateProfileVersion imported = mock(ImportedCertificateProfileVersion.class);
        when(imported.reference()).thenReturn(profile);
        when(imported.definition()).thenReturn(definition);
        when(profiles.getImportedVersion(profile.profileId(), profile.profileVersion()))
                .thenReturn(Optional.of(imported));
        when(profiles.requireActiveProfile(profile.profileId())).thenReturn(active);
        ParsedCertificationRequest parsed = mock(ParsedCertificationRequest.class);
        when(parsed.requestId()).thenReturn(new PkiId("request:canonical-csr"));
        when(parsed.subjectAlternativeNames()).thenReturn(List.of(new SubjectAlternativeName.DnsName("example.test")));
        CertificationRequestService requests = mock(CertificationRequestService.class);
        byte[] callerCsr = { 1, 2, 3 };
        when(requests.parseX509(any())).thenAnswer(invocation -> {
            if (scenario == Scenario.MUTATE_CALLER_CSR) callerCsr[0] = 99;
            return parsed;
        });
        SemanticSigningService signing = mock(SemanticSigningService.class);
        PreparedSemanticSigningRequest prepared = custody.prepared();
        SigningAcceptanceReceipt receipt = prepared.receipt();
        java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        PkiSession session = mock(PkiSession.class);
        when(session.repository()).thenReturn(repository);
        when(session.profiles()).thenReturn(profiles);
        when(session.requests()).thenReturn(Optional.of(requests));
        when(session.semanticSigning()).thenReturn(Optional.of(signing));


        ServerRealmContext realm = realm(control, session);
        zeroecho.pki.server.enrollment.EnrollmentCoordinator enrollment = installEnrollment(realm, directory,
                snapshot(operationId, authorityId, profile.profileId(), false), receipt);
        if (scenario == Scenario.CANCEL_BEFORE_ACCEPT) {
            when(enrollment.dispatch(any(), any())).thenAnswer(invocation -> {
                cancelled.set(true);
                throw new zeroecho.pki.api.PkiException("ACME finalization was cancelled");
            });
        }
        if (scenario == Scenario.UNCERTAIN_ACCEPT) {
            zeroecho.pki.server.enrollment.EnrollmentTransaction retained = enrollment
                    .find(null, null, null, null, null, null).orElseThrow();
            when(retained.state()).thenReturn(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.UNCERTAIN);
        }
        AcmeService first = service(realm);
        if (scenario == Scenario.CANCEL_BEFORE_ACCEPT) {
            org.junit.jupiter.api.Assertions.assertThrows(zeroecho.pki.api.PkiException.class,
                    () -> first.finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID, callerCsr, cancelled::get));
            verify(signing, org.mockito.Mockito.never()).accept(any());
            verify(enrollment).dispatch(any(), any());
            assertEquals(Optional.empty(), stored.get().signingOperationId());
            return;
        }
        AcmeState.Order processing = first.finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                callerCsr, cancelled::get);
        if (scenario == Scenario.UNCERTAIN_ACCEPT) {
            assertEquals(Optional.empty(), processing.signingOperationId());
            zeroecho.pki.server.enrollment.EnrollmentTransaction retained = enrollment
                    .find(null, null, null, null, null, null).orElseThrow();
            SigningAcceptanceReceipt retryReceipt = SigningAcceptanceReceipt.parse(new PkiId("signing:retry"), receipt.encodedCommitment());
            when(retained.receipt()).thenReturn(Optional.of(retryReceipt));
            when(retained.state()).thenReturn(zeroecho.pki.server.enrollment.EnrollmentTransaction.State.ACCEPTED);
        }
        AcmeState.Order repeated = first.finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                new byte[] { 1, 2, 3 });
        AcmeState.Order restarted = service(realm).finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                new byte[] { 1, 2, 3 });

        assertEquals(AcmeState.OrderStatus.PROCESSING, processing.status());
        if (scenario == Scenario.UNCERTAIN_ACCEPT) assertEquals(Optional.of(new PkiId("signing:retry")), repeated.signingOperationId());
        else assertEquals(processing.signingOperationId(), repeated.signingOperationId());
        assertEquals(repeated.signingOperationId(), restarted.signingOperationId());
        assertEquals(processing.issuanceCommitment(), restarted.issuanceCommitment());
        verify(enrollment, times(3)).dispatch(any(), any());
        verify(signing, org.mockito.Mockito.never()).prepareCorrelatedEndEntity(any(), any(), any(), any());
        verify(signing, org.mockito.Mockito.never()).accept(any());
        verify(signing, org.mockito.Mockito.never()).discard(any());
        }
    }

    @Test
    void completedRecoveryRegistersSharedPublicationBeforeOrderBecomesValid() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = new PkiId("signing:restart");
        PkiId credentialId = snapshot(operationId, authorityId, "leaf", true).completedCredentialId().orElseThrow();
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        CertificateProfileRef profile = new CertificateProfileRef("leaf", 1, new byte[32]);
        AcmeState.Directory directory = directory(authorityId, issuerId, path, profile);
        AtomicReference<AcmeState.Order> stored = new AtomicReference<>(crashedOrder(directory));
        AcmeState.Account account = new AcmeState.Account(ACCOUNT_ID, DIRECTORY_ID,
                directory.revision(), directory.policyCommitment(), "7".repeat(64), java.util.HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
                AcmeState.AccountStatus.VALID, List.of(), true, Optional.empty(), NOW, NOW,
                "8".repeat(64));

        AcmeControlStore control = mock(AcmeControlStore.class);
        when(control.page(AcmeState.Directory.class, 0, 256))
                .thenReturn(new ServerControlStore.Page<>(List.of(), 0, false));
        when(control.get(AcmeState.Account.class, ACCOUNT_ID)).thenReturn(Optional.of(account));
        when(control.get(AcmeState.Directory.class, DIRECTORY_ID)).thenReturn(Optional.of(directory));
        when(control.get(AcmeState.Order.class, ORDER_ID)).thenAnswer(ignored -> Optional.of(stored.get()));
        when(control.replace(any())).thenAnswer(invocation -> invocation
                .<List<AcmeControlStore.Replacement>>getArgument(0).stream().map(replacement -> {
                    AcmeState.Order next = (AcmeState.Order) replacement.next();
                    stored.set(next);
                    return next;
                }).toList());

        PkiRepository repository = mock(PkiRepository.class);
        when(repository.authority(authorityId)).thenReturn(Optional.of(new CaRecord(authorityId, CaKind.ROOT,
                CaState.ACTIVE, new KeyRef("key:restart"), new SubjectRef("CN=Restart"), List.of(issuerId),
                issuerId, path.pathId())));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        Credential credential = mock(Credential.class);
        when(credential.credentialId()).thenReturn(credentialId);
        when(credential.issuerRef()).thenReturn(new IssuerRef(authorityId, issuerId, path.pathId()));
        when(credential.profileBinding()).thenReturn(new EndEntityProfileBinding(profile));
        when(repository.credential(credentialId)).thenReturn(Optional.of(credential));
        ProfileService profiles = mock(ProfileService.class);
        ActiveCertificateProfile active = mock(ActiveCertificateProfile.class);
        CertificateProfileDefinition definition = mock(CertificateProfileDefinition.class);
        when(active.reference()).thenReturn(profile);
        when(active.definition()).thenReturn(definition);
        when(definition.confirmationPolicy()).thenReturn(Optional.of(confirmationPolicy()));
        ImportedCertificateProfileVersion imported = mock(ImportedCertificateProfileVersion.class);
        when(imported.reference()).thenReturn(profile);
        when(imported.definition()).thenReturn(definition);
        when(profiles.getImportedVersion(profile.profileId(), profile.profileVersion()))
                .thenReturn(Optional.of(imported));
        when(profiles.requireActiveProfile(profile.profileId())).thenReturn(active);
        PkiSession session = mock(PkiSession.class);
        when(session.repository()).thenReturn(repository);
        when(session.profiles()).thenReturn(profiles);
        SemanticSigningService signing = mock(SemanticSigningService.class);
        when(session.semanticSigning()).thenReturn(Optional.of(signing));
        when(signing.findIssuance(any(RetainedIssuanceBinding.class)))
                .thenReturn(Optional.of(snapshot(operationId, authorityId, profile.profileId(), true)));
        CredentialPublicationGate publication = mock(CredentialPublicationGate.class);
        ServerRealmContext realm = realm(control, session);
        when(realm.credentialPublication()).thenReturn(publication);

        installEnrollment(realm, directory, snapshot(operationId, authorityId, profile.profileId(), true), null);
        when(signing.find(operationId)).thenReturn(Optional.of(snapshot(operationId, authorityId, profile.profileId(), true)));
        AcmeState.Order recovered = service(realm).order(ACCOUNT_ID, account.commitment(), ORDER_ID);

        assertEquals(AcmeState.OrderStatus.VALID, recovered.status());
        assertEquals(Optional.of(credentialId), recovered.credentialId());
        InOrder ordering = inOrder(publication, control);
        ordering.verify(publication).register(credentialId,
                Optional.of(DisclosureService.Owner.acmeAccount(ACCOUNT_ID)),
                new CredentialPublicationGate.AuditActor("acme-service"));
        ordering.verify(control).replace(any());
    }


    private static AcmeState.Account account(AcmeState.Directory directory) {
        return new AcmeState.Account(ACCOUNT_ID, DIRECTORY_ID, directory.revision(), directory.policyCommitment(),
                "7".repeat(64), java.util.HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"), AcmeState.AccountStatus.VALID, List.of(), true,
                Optional.empty(), NOW, NOW, "8".repeat(64));
    }

    private static zeroecho.pki.server.enrollment.EnrollmentCoordinator installEnrollment(ServerRealmContext realm,
            AcmeState.Directory directory, SemanticSigningOperation signed, SigningAcceptanceReceipt receipt) {
        zeroecho.pki.server.enrollment.EnrollmentCoordinator enrollment =
                mock(zeroecho.pki.server.enrollment.EnrollmentCoordinator.class);
        zeroecho.pki.server.enrollment.EnrollmentTransaction transaction =
                mock(zeroecho.pki.server.enrollment.EnrollmentTransaction.class);
        zeroecho.pki.server.enrollment.EnrollmentTransaction.Intent intent =
                mock(zeroecho.pki.server.enrollment.EnrollmentTransaction.Intent.class);
        zeroecho.pki.server.enrollment.EnrollmentTransaction.Requester requester =
                mock(zeroecho.pki.server.enrollment.EnrollmentTransaction.Requester.class);
        when(requester.type()).thenReturn(zeroecho.pki.application.IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT);
        when(requester.actorId()).thenReturn(ACCOUNT_ID);
        when(intent.requester()).thenReturn(requester);
        when(intent.realmId()).thenReturn(new RealmId("restart"));
        when(intent.source()).thenReturn(new zeroecho.pki.server.enrollment.EnrollmentTransaction.Source(
                zeroecho.pki.server.enrollment.EnrollmentTransaction.Protocol.ACME, directory.alias(), directory.directoryId(),
                directory.revision(), directory.commitment(), directory.enrollmentProfileId(), "0".repeat(64), Optional.empty()));
        when(intent.operation()).thenReturn(zeroecho.pki.server.enrollment.EnrollmentTransaction.Operation.ISSUE);
        when(intent.transactionId()).thenReturn(sha256(ORDER_ID.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        when(intent.requestSha256()).thenReturn(sha256(new byte[] {1, 2, 3}));
        when(intent.authorityId()).thenReturn(directory.authorityId());
        when(intent.profile()).thenReturn(directory.profile());
        when(intent.issuerId()).thenReturn(directory.issuerId());
        when(intent.pathId()).thenReturn(directory.issuancePathId());
        when(intent.pathCommitment()).thenReturn(directory.issuancePathCommitment());
        when(intent.validity()).thenReturn(Optional.empty());
        when(intent.requestKind()).thenReturn(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10);
        when(intent.expiresAt()).thenReturn(NOW.plusSeconds(3600));
        when(transaction.intent()).thenReturn(intent);
        when(transaction.id()).thenReturn("enrollment:restart");
        SigningAcceptanceReceipt actualReceipt = receipt;
        if (actualReceipt == null) {
            actualReceipt = mock(SigningAcceptanceReceipt.class);
            when(actualReceipt.operationId()).thenReturn(signed.submissionId().id());
        }
        when(transaction.receipt()).thenReturn(Optional.of(actualReceipt));
        when(transaction.credentialId()).thenReturn(signed.completedCredentialId());
        when(transaction.state()).thenReturn(signed.completedCredentialId().isPresent()
                ? zeroecho.pki.server.enrollment.EnrollmentTransaction.State.ISSUED
                : zeroecho.pki.server.enrollment.EnrollmentTransaction.State.ACCEPTED);
        when(enrollment.find(any(), any(), any(), any(), any(), any())).thenReturn(Optional.of(transaction));
        when(enrollment.dispatch(any(), any())).thenReturn(transaction);
        when(enrollment.issuanceBinding(any())).thenReturn(new RetainedIssuanceBinding(directory.authorityId(),
                "enrollment:restart", directory.profile(), directory.issuerId(), directory.issuancePathId(),
                directory.issuancePathCommitment(), "3".repeat(64)));
        ParsedCertificationRequest parsed = mock(ParsedCertificationRequest.class);
        when(parsed.subjectAlternativeNames()).thenReturn(List.of(new SubjectAlternativeName.DnsName("example.test")));
        when(enrollment.inspectIdentity(any())).thenReturn(parsed);
        when(realm.enrollmentCoordinator()).thenReturn(Optional.of(enrollment));
        return enrollment;
    }

    private static String sha256(byte[] bytes) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static ServerRealmContext realm(AcmeControlStore control, PkiSession session) {
        ServerRealmContext realm = mock(ServerRealmContext.class);
        ServerRealmConfiguration configuration = mock(ServerRealmConfiguration.class);
        when(configuration.realmId()).thenReturn(new RealmId("restart"));
        when(configuration.authorityExposure()).thenReturn(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false));
        when(realm.configuration()).thenReturn(configuration);
        when(realm.acmeControl()).thenReturn(control);
        when(realm.session()).thenReturn(session);
        when(realm.enrollmentProfiles()).thenReturn(mock(zeroecho.pki.server.enrollment.EnrollmentProfileService.class));
        return realm;
    }

    private static AcmeService service(ServerRealmContext realm) {
        AcmeChallengeProvider provider = mock(AcmeChallengeProvider.class);
        when(provider.id()).thenReturn("http");
        when(provider.challengeTypes()).thenReturn(Set.of(AcmeState.ChallengeType.HTTP_01));
        return new AcmeService(realm, Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(),
                Map.of("http", provider), Map.of("http", new ProviderConfig("http", Map.of())));
    }

    private static SemanticSigningOperation snapshot(PkiId id, PkiId authority, String profile, boolean completed) {
        zeroecho.pki.api.signing.SemanticSigningScope scope = new zeroecho.pki.api.signing.SemanticSigningScope(
                zeroecho.pki.api.signing.SemanticSigningKind.ISSUANCE, "ISSUE_END_ENTITY",
                new zeroecho.pki.api.audit.AccessContext(new zeroecho.pki.api.audit.Principal("ACME_ACCOUNT", ACCOUNT_ID),
                        new zeroecho.pki.api.audit.Purpose("ACME_FINALIZE"), Optional.empty(), Optional.empty()),
                new KeyRef("key:restart"), Optional.of(authority), Optional.empty(), Optional.of(profile),
                Optional.empty());
        return new SemanticSigningOperation(new zeroecho.pki.api.orch.SigningSubmissionId(id, "test", NOW),
                scope, completed ? zeroecho.pki.api.signing.SigningOperationState.SUCCEEDED
                        : zeroecho.pki.api.signing.SigningOperationState.PENDING,
                completed ? zeroecho.pki.api.signing.SemanticSigningState.COMPLETED
                        : zeroecho.pki.api.signing.SemanticSigningState.SIGNING,
                1, 1, NOW, NOW.plusSeconds(60), Optional.empty(),
                completed ? Optional.of(new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.DER,
                        new byte[] { 1, 2, 3 })) : Optional.empty());
    }

    private static AcmeState.Directory directory(PkiId authorityId, PkiId issuerId, IssuerChainPath path,
            CertificateProfileRef profile) {
        return new AcmeState.Directory(DIRECTORY_ID, "restart", 1, new RealmId("restart"),
                authorityId, profile, "acme-enrollment", issuerId, path.pathId(), path.pathCommitment(),
                Set.of(AcmeState.IdentifierType.DNS), Set.of("example.test"), Duration.ofDays(30),
                Set.of("RSA"), Set.of("STANDARD_ONLY"), Set.of(AcmeState.ChallengeType.HTTP_01),
                Set.of("http"), Optional.empty(), false, confirmationPolicy(),
                confirmationPolicy().configurationCommitment(),
                AcmeState.DirectoryStatus.ACTIVE, "1".repeat(64), NOW, "2".repeat(64));
    }

    private static CredentialConfirmationPolicy confirmationPolicy() {
        return new CredentialConfirmationPolicy(ConfirmationDisclosurePolicy.OWNER_ONLY, Duration.ofHours(24),
                new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1", "9".repeat(64)));
    }

    private static AcmeState.Order crashedOrder(AcmeState.Directory directory) {
        return new AcmeState.Order(ORDER_ID, ACCOUNT_ID, DIRECTORY_ID, directory.revision(),
                directory.policyCommitment(), directory.authorityId(), directory.profile(), directory.issuerId(),
                directory.issuancePathId(), directory.issuancePathCommitment(),
                List.of(new AcmeState.Identifier(AcmeState.IdentifierType.DNS, "example.test", false)),
                Optional.empty(), Optional.empty(), AcmeState.OrderStatus.READY, List.of("authorization:restart"),
                Optional.empty(), Optional.of("3".repeat(64)), Optional.empty(), NOW,
                NOW.plus(Duration.ofHours(1)), "4".repeat(64));
    }

    private static AcmeState.Order copyLifecycle(AcmeState.Order source, AcmeState.OrderStatus status,
            Optional<String> issuanceCommitment, Optional<PkiId> operationId, String commitment) {
        return new AcmeState.Order(source.orderId(), source.accountId(), source.directoryId(),
                source.directoryRevision(), source.directoryPolicyCommitment(), source.authorityId(), source.profile(),
                source.issuerId(), source.issuancePathId(), source.issuancePathCommitment(), source.identifiers(),
                source.notBefore(), source.notAfter(), status, source.authorizationIds(), Optional.empty(),
                issuanceCommitment, operationId, source.createdAt(), source.expiresAt(), commitment);
    }
}
