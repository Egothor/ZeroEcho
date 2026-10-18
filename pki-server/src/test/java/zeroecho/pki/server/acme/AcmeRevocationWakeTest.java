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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.server.AuthorityExposurePolicy;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.ServerRealmContext;

final class AcmeRevocationWakeTest {
    private static final String ACCOUNT_ID = "account:test";
    private static final String ACCOUNT_COMMITMENT = "1".repeat(64);
    private static final PkiId CREDENTIAL_ID = new PkiId("credential:test");

    @Test
    void signalsExactlyOnceAfterCompletedCheckAndBeforeLookup() {
        byte[] certificate = { 1, 2, 3 };
        AtomicReference<PkiOperationOutcome> outcome = new AtomicReference<>(
                new PkiOperationOutcome.Completed(new PkiOperationResult("revoke", Map.of())));
        AtomicBoolean revocationLookup = new AtomicBoolean();
        AtomicInteger wakes = new AtomicInteger();
        AtomicInteger audits = new AtomicInteger();
        PkiId authorityId = new PkiId("ca:test");
        PkiId issuerId = new PkiId("issuer:test");
        String directoryPolicyCommitment = "3".repeat(64);
        BuiltInCertificateProfileTemplate template = BuiltInCertificateProfileCatalog
                .load(getClass().getClassLoader()).stream()
                .filter(candidate -> candidate.definition().profileId().equals("server-tls"))
                .findFirst().orElseThrow();
        CertificateProfileRef profile = new CertificateProfileRef(template.definition().profileId(),
                template.definition().profileVersion(), new byte[CertificateProfileRef.HASH_BYTES]);
        CredentialConfirmationPolicy confirmationPolicy = template.definition().confirmationPolicy().orElseThrow();
        ImportedCertificateProfileVersion imported = new ImportedCertificateProfileVersion(profile,
                zeroecho.pki.api.profile.CertificateProfileDefinition.SCHEMA_VERSION,
                template.definition(), template.canonicalJson(), Instant.parse("2026-08-20T00:00:00Z"));
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId,
                List.of(new PkiId("x509:issuer-test")));
        PkiId pathId = path.pathId();
        String pathCommitment = path.pathCommitment();
        AcmeControlStore control = mock(AcmeControlStore.class);
        when(control.page(AcmeState.Directory.class, 0, 256))
                .thenReturn(new ServerControlStore.Page<>(List.of(), 0, false));
        AcmeState.Account account = new AcmeState.Account(ACCOUNT_ID, "directory:test", 1,
                directoryPolicyCommitment, "5".repeat(64), java.util.HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"), AcmeState.AccountStatus.VALID,
                List.of(), true, Optional.empty(), Instant.parse("2026-08-20T00:00:00Z"),
                Instant.parse("2026-08-20T00:00:00Z"), ACCOUNT_COMMITMENT);
        when(control.get(AcmeState.Account.class, ACCOUNT_ID)).thenReturn(Optional.of(account));
        AcmeState.Directory directory = new AcmeState.Directory("directory:test", "test", 1,
                new RealmId("realm-test"), authorityId, profile, "acme-enrollment", issuerId, pathId, pathCommitment,
                Set.of(AcmeState.IdentifierType.DNS), Set.of("example.test"), Duration.ofDays(30),
                Set.of("RSA"), Set.of("STANDARD_ONLY"), Set.of(AcmeState.ChallengeType.HTTP_01),
                Set.of("http"), Optional.empty(), false, confirmationPolicy,
                confirmationPolicy.configurationCommitment(), AcmeState.DirectoryStatus.INACTIVE,
                directoryPolicyCommitment, Instant.parse("2026-08-20T00:00:00Z"), "6".repeat(64));
        AcmeState.Order order = new AcmeState.Order("order:test", ACCOUNT_ID, directory.directoryId(), 1,
                directoryPolicyCommitment, authorityId, profile, issuerId, pathId, pathCommitment,
                List.of(new AcmeState.Identifier(AcmeState.IdentifierType.DNS, "example.test", false)),
                Optional.empty(), Optional.empty(), AcmeState.OrderStatus.VALID,
                List.of("authorization:test"), Optional.of(CREDENTIAL_ID), Optional.empty(), Optional.empty(),
                Instant.parse("2026-08-20T00:00:00Z"), Instant.parse("2026-08-22T00:00:00Z"),
                "7".repeat(64));
        when(control.page(AcmeState.Order.class, 0, 256))
                .thenReturn(new ServerControlStore.Page<>(List.of(order), 0, false));

        DurableContentReference content = mock(DurableContentReference.class);
        when(content.sha256()).thenReturn(sha256(certificate));
        Credential credential = new Credential(CREDENTIAL_ID, new FormatId("x509"),
                new IssuerRef(authorityId, issuerId, pathId), new SubjectRef("CN=example.test"),
                new Validity(Instant.parse("2026-08-20T00:00:00Z"), Instant.parse("2026-08-22T00:00:00Z")),
                "1", new PkiId("public-key:test"), new EndEntityProfileBinding(profile),
                CredentialStatus.ISSUED, content, new SimpleAttributeSet(List.of()));
        PkiRepository repository = mock(PkiRepository.class);
        when(repository.credential(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        CaRecord authority = new CaRecord(authorityId, CaKind.ROOT, CaState.RETIRED,
                new KeyRef("key:test"), new SubjectRef("CN=Test CA"), List.of(issuerId), issuerId, pathId);
        when(repository.authority(authorityId)).thenReturn(Optional.of(authority));
        when(repository.chainPath(pathId)).thenReturn(Optional.of(path));
        ProfileService profiles = mock(ProfileService.class);
        when(profiles.getImportedVersion(profile.profileId(), profile.profileVersion()))
                .thenReturn(Optional.of(imported));
        RevocationService revocations = mock(RevocationService.class);
        RevocationRecord record = mock(RevocationRecord.class);
        when(revocations.get(CREDENTIAL_ID)).thenAnswer(ignored -> {
            revocationLookup.set(true);
            return Optional.of(record);
        });
        PkiSession session = mock(PkiSession.class);
        when(session.repository()).thenReturn(repository);
        when(session.profiles()).thenReturn(profiles);
        when(session.operations()).thenReturn(new TestEvidenceExecutor(outcome));
        when(session.revocations()).thenReturn(revocations);
        ServerRealmContext realm = mock(ServerRealmContext.class);
        ServerRealmConfiguration configuration = mock(ServerRealmConfiguration.class);
        when(configuration.realmId()).thenReturn(new RealmId("realm-test"));
        when(configuration.authorityExposure()).thenReturn(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, java.util.Set.of(), false));
        when(realm.configuration()).thenReturn(configuration);
        when(realm.acmeControl()).thenReturn(control);
        when(realm.session()).thenReturn(session);
        doAnswer(ignored -> {
            audits.incrementAndGet();
            return null;
        }).when(realm).auditTransport(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyMap());
        AcmeService service = new AcmeService(realm,
                Clock.fixed(Instant.parse("2026-08-21T00:00:00Z"), ZoneOffset.UTC), new SecureRandom(),
                Map.of(), Map.of(), Map.of(), Map.of(), () -> {
                    assertFalse(revocationLookup.get());
                    wakes.incrementAndGet();
                    throw new IllegalStateException("test wake failure");
                });

        assertEquals(record, service.revokeCertificate(ACCOUNT_ID, ACCOUNT_COMMITMENT, directory,
                certificate, RevocationReason.KEY_COMPROMISE, "request:test"));
        assertEquals(1, wakes.get());
        assertEquals(1, audits.get());

        outcome.set(new PkiOperationOutcome.Failed(PkiOperation.RevokeCredential.NAME,
                PkiOperationFailure.CANCELLED, "TEST_CANCELLED"));
        assertThrows(IllegalStateException.class, () -> service.revokeCertificate(ACCOUNT_ID,
                ACCOUNT_COMMITMENT, directory, certificate, RevocationReason.KEY_COMPROMISE, "request:test-2"));
        assertEquals(1, wakes.get());
        assertEquals(1, audits.get());
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }

    private record TestEvidenceExecutor(AtomicReference<PkiOperationOutcome> outcome)
            implements zeroecho.pki.application.PkiOperationExecutor, RevocationEvidenceExecutor {
        @Override public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
            return outcome.get();
        }
        @Override public PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
                RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
            return outcome.get();
        }
    }
}
