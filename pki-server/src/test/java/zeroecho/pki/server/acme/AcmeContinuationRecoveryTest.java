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
import zeroecho.pki.api.IssuanceService;
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
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.SigningIssuanceBinding;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
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
        when(session.issuanceSigningOperationId(any(SigningIssuanceBinding.class)))
                .thenReturn(Optional.of(operationId));
        when(session.issuanceSigningOperation(any(PkiId.class), any(SigningIssuanceBinding.class)))
                .thenReturn(new PkiOperationOutcome.Pending("issuance", operationId));

        ServerRealmContext realm = mock(ServerRealmContext.class);
        ServerRealmConfiguration configuration = mock(ServerRealmConfiguration.class);
        when(configuration.realmId()).thenReturn(new RealmId("restart"));
        when(configuration.authorityExposure()).thenReturn(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false));
        when(realm.configuration()).thenReturn(configuration);
        when(realm.acmeControl()).thenReturn(control);
        when(realm.session()).thenReturn(session);
        AcmeChallengeProvider provider = mock(AcmeChallengeProvider.class);
        when(provider.id()).thenReturn("http");
        when(provider.challengeTypes()).thenReturn(Set.of(AcmeState.ChallengeType.HTTP_01));
        AcmeService service = new AcmeService(realm, Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(),
                Map.of("http", provider), Map.of("http", new ProviderConfig("http", Map.of())));

        AcmeState.Order recovered = service.order(ACCOUNT_ID, ORDER_ID);

        assertEquals(AcmeState.OrderStatus.PROCESSING, recovered.status());
        assertEquals(Optional.of(operationId), recovered.signingOperationId());
        assertEquals(stored.get(), recovered);
    }

    @Test
    void issuanceCommitmentIgnoresMutableOrderLifecycleAcrossRepeatedFinalizeAndRestart() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = new PkiId("signing:restart");
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        AcmeState.Directory directory = directory(authorityId, issuerId, path,
                new CertificateProfileRef("leaf", 1, new byte[32]));
        AcmeState.Order beforeAttachment = crashedOrder(directory);
        ParsedCertificationRequest request = mock(ParsedCertificationRequest.class);
        when(request.requestId()).thenReturn(new PkiId("request:canonical-csr"));
        String expected = AcmeService.issuanceCommitment(beforeAttachment, request);
        AcmeState.Order processing = copyLifecycle(beforeAttachment, AcmeState.OrderStatus.PROCESSING,
                Optional.of(expected), Optional.of(operationId), "5".repeat(64));
        AcmeState.Order restarted = copyLifecycle(processing, AcmeState.OrderStatus.PROCESSING,
                Optional.of(expected), Optional.of(operationId), "6".repeat(64));

        assertEquals(expected, AcmeService.issuanceCommitment(processing, request));
        assertEquals(expected, AcmeService.issuanceCommitment(restarted, request));
    }

    @Test
    void repeatedFinalizeBeforeAttachmentProcessingAndRestartUsesOneIssuance() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = new PkiId("signing:restart");
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        CertificateProfileRef profile = new CertificateProfileRef("leaf", 1, new byte[32]);
        AcmeState.Directory directory = directory(authorityId, issuerId, path, profile);
        AcmeState.Order ready = copyLifecycle(crashedOrder(directory), AcmeState.OrderStatus.READY,
                Optional.empty(), Optional.empty(), "4".repeat(64));
        AtomicReference<AcmeState.Order> stored = new AtomicReference<>(ready);
        AcmeState.Account account = new AcmeState.Account(ACCOUNT_ID, DIRECTORY_ID,
                directory.revision(), directory.policyCommitment(), "7".repeat(64), new byte[32],
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
        when(requests.parse(any())).thenReturn(parsed);
        IssuanceService issuance = mock(IssuanceService.class);
        when(issuance.issueEndEntity(any(), any())).thenThrow(new PendingSigningOperation(operationId));
        PkiSession session = mock(PkiSession.class);
        when(session.repository()).thenReturn(repository);
        when(session.profiles()).thenReturn(profiles);
        when(session.requests()).thenReturn(Optional.of(requests));
        when(session.issuance()).thenReturn(Optional.of(issuance));
        when(session.issuanceSigningOperationId(any(SigningIssuanceBinding.class)))
                .thenAnswer(ignored -> stored.get().signingOperationId());
        when(session.issuanceSigningOperation(any(PkiId.class), any(SigningIssuanceBinding.class)))
                .thenReturn(new PkiOperationOutcome.Pending("issuance", operationId));

        ServerRealmContext realm = realm(control, session);
        AcmeService first = service(realm);
        AcmeState.Order processing = first.finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                new byte[] { 1, 2, 3 });
        AcmeState.Order repeated = first.finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                new byte[] { 1, 2, 3 });
        AcmeState.Order restarted = service(realm).finalizeOrder(ACCOUNT_ID, account.commitment(), ORDER_ID,
                new byte[] { 1, 2, 3 });

        assertEquals(AcmeState.OrderStatus.PROCESSING, processing.status());
        assertEquals(processing.signingOperationId(), repeated.signingOperationId());
        assertEquals(processing.signingOperationId(), restarted.signingOperationId());
        assertEquals(processing.issuanceCommitment(), restarted.issuanceCommitment());
        verify(issuance, times(1)).issueEndEntity(any(), any());
    }

    @Test
    void completedRecoveryRegistersSharedPublicationBeforeOrderBecomesValid() {
        PkiId authorityId = new PkiId("ca:restart");
        PkiId issuerId = new PkiId("issuer:restart");
        PkiId operationId = new PkiId("signing:restart");
        PkiId credentialId = new PkiId("credential:restart");
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:restart")));
        CertificateProfileRef profile = new CertificateProfileRef("leaf", 1, new byte[32]);
        AcmeState.Directory directory = directory(authorityId, issuerId, path, profile);
        AtomicReference<AcmeState.Order> stored = new AtomicReference<>(crashedOrder(directory));
        AcmeState.Account account = new AcmeState.Account(ACCOUNT_ID, DIRECTORY_ID,
                directory.revision(), directory.policyCommitment(), "7".repeat(64), new byte[32],
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
        when(session.issuanceSigningOperationId(any(SigningIssuanceBinding.class)))
                .thenReturn(Optional.of(operationId));
        when(session.issuanceSigningOperation(any(PkiId.class), any(SigningIssuanceBinding.class)))
                .thenReturn(new PkiOperationOutcome.Completed(new PkiOperationResult("issuance", Map.of(
                        "credentialId", new PkiOperationValue.Text(credentialId.value())))));
        CredentialPublicationGate publication = mock(CredentialPublicationGate.class);
        ServerRealmContext realm = realm(control, session);
        when(realm.credentialPublication()).thenReturn(publication);

        AcmeState.Order recovered = service(realm).order(ACCOUNT_ID, ORDER_ID);

        assertEquals(AcmeState.OrderStatus.VALID, recovered.status());
        assertEquals(Optional.of(credentialId), recovered.credentialId());
        InOrder ordering = inOrder(publication, control);
        ordering.verify(publication).register(credentialId,
                Optional.of(DisclosureService.Owner.acmeAccount(ACCOUNT_ID)),
                new CredentialPublicationGate.AuditActor("acme-service"));
        ordering.verify(control).replace(any());
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
        return realm;
    }

    private static AcmeService service(ServerRealmContext realm) {
        AcmeChallengeProvider provider = mock(AcmeChallengeProvider.class);
        when(provider.id()).thenReturn("http");
        when(provider.challengeTypes()).thenReturn(Set.of(AcmeState.ChallengeType.HTTP_01));
        return new AcmeService(realm, Clock.fixed(NOW, ZoneOffset.UTC), new SecureRandom(),
                Map.of("http", provider), Map.of("http", new ProviderConfig("http", Map.of())));
    }

    private static AcmeState.Directory directory(PkiId authorityId, PkiId issuerId, IssuerChainPath path,
            CertificateProfileRef profile) {
        return new AcmeState.Directory(DIRECTORY_ID, "restart", 1, new RealmId("restart"),
                authorityId, profile, issuerId, path.pathId(), path.pathCommitment(),
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
