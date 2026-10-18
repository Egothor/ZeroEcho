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

package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.SemanticIssuanceFixture;

class FilesystemSignScopeAcceptanceTest {
    @Test void proofPrefixCannotAcceptOrReserveCertificateState(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand base = rootCommand(store, 9);
            CrlScope scope = candidateScope(base, store);
            DomainContinuationTemplate prefix = DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                    "PROVE_MANAGED_KEY", "CA_SUBJECT_KEY", base.fairnessAuthorityId().value(), "", "profile", "",
                    base.keyRef().value());
            SignWorkflowStore.AcceptanceCommand proof = withOuter(base, new SignWorkflowStore.OuterCommand(
                    prefix.kind(), base.operationId().value(), prefix.command(), prefix.commandCommitment()),
                    base.fairnessAuthorityId());
            IllegalStateException failure = assertThrows(IllegalStateException.class, () -> store.acceptSign(proof));
            assertEquals("Managed key proof command is invalid", failure.getMessage());
            assertTrue(store.getSignWorkflow(proof.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(proof.operationId()).isEmpty());
            assertTrue(reservations(store).findOwner(scope).isEmpty());
            assertTrue(reservations(store).findReservation(scope, BigInteger.valueOf(9)).isEmpty());
            try (zeroecho.pki.spi.store.MetadataSnapshot snapshot = store.metadataStore().snapshot()) {
                assertTrue(snapshot.get(CrlScopeMetadataCodec.counterKey(scope)).isEmpty());
            }
        }
    }

    @Test void sameScopeSerialAcrossGenerationsHasOneConcurrentWinner(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                java.util.concurrent.ExecutorService workers = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            SignWorkflowStore.AcceptanceCommand first = command(store, 1, 42, -1, "", null);
            SignWorkflowStore.AcceptanceCommand second = command(store, 2, 42, -1, "", null);
            java.util.concurrent.CyclicBarrier barrier = new java.util.concurrent.CyclicBarrier(2);
            List<java.util.concurrent.Future<SignWorkflowStore.AcceptanceResult>> results = new java.util.ArrayList<>();
            for (SignWorkflowStore.AcceptanceCommand candidate : List.of(first, second)) {
                results.add(workers.submit(() -> {
                    FilesystemPkiStore.installSignAcceptanceValidatedObserver(() -> {
                        try { barrier.await(10, java.util.concurrent.TimeUnit.SECONDS); }
                        catch (Exception failure) { throw new IllegalStateException(failure); }
                    });
                    try { return store.acceptSign(candidate); }
                    finally { FilesystemPkiStore.clearSignAcceptanceValidatedObserver(); }
                }));
            }
            List<SignWorkflowStore.AcceptanceResult> outcomes = List.of(results.get(0).get(), results.get(1).get());
            assertEquals(1, java.util.Collections.frequency(outcomes, SignWorkflowStore.AcceptanceResult.ACCEPTED));
            assertEquals(1, java.util.Collections.frequency(outcomes, SignWorkflowStore.AcceptanceResult.CONFLICT));
            SignWorkflowStore.AcceptanceCommand winner = outcomes.get(0) == SignWorkflowStore.AcceptanceResult.ACCEPTED ? first : second;
            SignWorkflowStore.AcceptanceCommand loser = winner == first ? second : first;
            assertEquals(SignWorkflowStore.AcceptanceResult.ATTACHED_EXISTING, store.acceptSign(winner));
            assertTrue(store.getSignWorkflow(loser.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(loser.operationId()).isEmpty());
            ScopeSerialReservation reserved = reservations(store).findReservation(scope(store,
                    SemanticIssuanceFixture.issuer(store, 1)), BigInteger.valueOf(42)).orElseThrow();
            assertEquals(new ScopeSerialReservation.SigningOwner(winner.operationId(),
                    winner.outer().orElseThrow().commandCommitment().substring(10)), reserved.issuanceOwner());
        }
    }

    @Test void correlationTransactionConflictLeavesNoNewReservation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand winner = command(store, 1, 42, -1, "", null);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(winner));
            SignWorkflowStore.AcceptanceCommand other = command(store, 1, 43, -1, "", null);
            SignWorkflowStore.OuterCommand outer = other.outer().orElseThrow();
            SignWorkflowStore.AcceptanceCommand conflict = withOuter(other, new SignWorkflowStore.OuterCommand(outer.kind(),
                    winner.outer().orElseThrow().correlationId(), outer.command(), outer.commandCommitment()), other.fairnessAuthorityId());
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(conflict));
            assertTrue(store.getSignWorkflow(conflict.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(conflict.operationId()).isEmpty());
            assertTrue(reservations(store).findReservation(scope(store, SemanticIssuanceFixture.issuer(store, 1)), BigInteger.valueOf(43)).isEmpty());
        }
    }

    @Test void definiteAndUnknownCommitResolveAllClaimsTogetherAfterReopen(@TempDir Path root) throws Exception {
        for (FilesystemPkiStore.SignAcceptanceCommitFault fault : FilesystemPkiStore.SignAcceptanceCommitFault.values()) {
            Path directory = root.resolve(fault.name());
            SignWorkflowStore.AcceptanceCommand command;
            CrlScope scope;
            try (FilesystemPkiStore store = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults())) {
                command = rootCommand(store, 9);
                scope = candidateScope(command, store);
                FilesystemPkiStore.installSignAcceptanceCommitFault(fault);
                try { assertThrows(RuntimeException.class, () -> store.acceptSign(command)); }
                finally { FilesystemPkiStore.clearSignAcceptanceCommitFault(); }
                assertThrows(zeroecho.pki.api.PkiException.class, store::signingNow);
            }
            try (FilesystemPkiStore reopened = new FilesystemPkiStore(directory, FsPkiStoreOptions.defaults())) {
                boolean committed = fault == FilesystemPkiStore.SignAcceptanceCommitFault.AFTER_COMMIT_AS_UNKNOWN;
                assertEquals(committed, reopened.getSignWorkflow(command.operationId()).isPresent());
                assertEquals(committed, reopened.getDomainContinuation(command.operationId()).isPresent());
                assertEquals(committed, reopened.getDomainContinuation(DomainContinuationStore.Kind.CA,
                        command.outer().orElseThrow().correlationId()).isPresent());
                assertEquals(committed, reservations(reopened).findOwner(scope).isPresent());
                try (zeroecho.pki.spi.store.MetadataSnapshot snapshot = reopened.metadataStore().snapshot();
                        zeroecho.pki.spi.store.MetadataSnapshot.Record counter = snapshot.get(
                                CrlScopeMetadataCodec.counterKey(scope)).orElse(null)) {
                    assertEquals(committed, counter != null);
                    if (counter != null) {
                        try (java.io.InputStream input = counter.openStream()) {
                            assertEquals(BigInteger.ONE, CrlScopeMetadataCodec.decodeCounter(counter.key(),
                                    input.readAllBytes()).nextNumber());
                        }
                    }
                }
                assertEquals(committed, reservations(reopened).findReservation(scope, BigInteger.valueOf(9)).isPresent());
                assertEquals(committed ? SignWorkflowStore.AcceptanceResolution.MATCHED : SignWorkflowStore.AcceptanceResolution.NOT_ACCEPTED,
                        reopened.resolveAcceptance(command.operationId(), command.commitment()));
            }
        }
    }

    @Test void terminalFailureNeverReleasesAcceptedSerial(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand accepted = command(store, 1, 42, -1, "", null);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(accepted));
            SignWorkflowStore.Workflow claimed = store.claimSignStep(accepted.operationId(), 0, java.time.Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(accepted.operationId(), claimed.revision(), claimed.fence(), SignWorkflowStore.State.FAILED,
                    Optional.of("DENIED"), Optional.empty(), Optional.empty()).orElseThrow();
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(command(store, 2, 42, -1, "", null)));
            assertTrue(reservations(store).findReservation(scope(store, SemanticIssuanceFixture.issuer(store, 1)), BigInteger.valueOf(42)).isPresent());
        }
    }

    @Test void rootAuthorityIsFrozenBeforeSigningAndCrossAuthorityScopeClaimConflicts(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand first = rootCommand(store, 9);
            PkiId authority = DomainCommandEncoding.rootAuthorityId(first.operationId());
            assertEquals(authority, DomainCommandEncoding.rootAuthorityId(first.operationId()));
            assertEquals(authority.value(), DomainCommandEncoding.decode(first.outer().orElseThrow().command()).field(13));
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(first));
            SignWorkflowStore.AcceptanceCommand other = rootCommand(store, 10);
            assertEquals(SignWorkflowStore.AcceptanceResult.CONFLICT, store.acceptSign(other));
            assertTrue(store.getSignWorkflow(other.operationId()).isEmpty());
            assertTrue(reservations(store).findReservation(candidateScope(first, store), BigInteger.TEN).isEmpty());
            assertEquals(authority, reservations(store).findOwner(candidateScope(first, store)).orElseThrow().authorityId());
        }
    }

    @Test void intermediateClaimsChildScopeButReservesOnlyParentSerial(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand base = command(store, 1, 42, -1, "", null);
            Credential issuer = SemanticIssuanceFixture.issuer(store, 1);
            DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CREATE_INTERMEDIATE",
                    "x509", SemanticIssuanceFixture.AUTHORITY.value(), "child-authority", SemanticIssuanceFixture.issuerId(1).value(),
                    SemanticIssuanceFixture.path(1).pathId().value(), SemanticIssuanceFixture.path(1).pathCommitment(), "child-key",
                    "profile", "1", "1".repeat(64), "CN=Leaf", SemanticIssuanceFixture.BEFORE.toString(), SemanticIssuanceFixture.AFTER.toString(),
                    "42", SemanticIssuanceFixture.KEY.value(), issuer.content().contentId(), issuer.content().sha256(),
                    SemanticIssuanceFixture.publicKeyDigest(), "", "", "");
            template = zeroecho.pki.testkit.IntermediateProofProvenanceFixture.withProof(template,
                    base.providerNamespace(), base.providerConfigurationCommitment(), base.candidate().length(), base.candidate().sha256());
            SignWorkflowStore.AcceptanceCommand intermediate = withOuter(base, new SignWorkflowStore.OuterCommand(template.kind(),
                    base.operationId().value(), template.command(), template.commandCommitment()), base.fairnessAuthorityId());
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(intermediate));
            CrlScope child = candidateScope(intermediate, store);
            assertEquals(new PkiId("child-authority"), reservations(store).findOwner(child).orElseThrow().authorityId());
            assertTrue(reservations(store).findReservation(child, BigInteger.valueOf(42)).isEmpty());
            assertTrue(reservations(store).findReservation(scope(store, issuer), BigInteger.valueOf(42)).isPresent());
        }
    }

    @Test void legacyIntermediateDnRecoversFromRetainedCandidateAndCompletedCertificate(@TempDir Path root) throws Exception {
        PkiId operation;
        java.security.cert.X509Certificate certificate = SemanticIssuanceFixture.caCertificate(
                new javax.security.auth.x500.X500Principal("CN=Legacy Child,O=ZeroEcho,C=CZ"), BigInteger.valueOf(42));
        String legacy = zeroecho.pkix.Pkix.distinguishedNameString(zeroecho.pkix.Pkix.parseDistinguishedName(
                certificate.getSubjectX500Principal().getEncoded()));
        assertFalse(legacy.equals(certificate.getSubjectX500Principal().getName()));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand accepted = legacyIntermediateCommand(store, certificate, legacy);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(accepted));
            operation = accepted.operationId();
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.Workflow claim = store.claimSignStep(operation, 0, java.time.Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(operation, claim.revision(), claim.fence(), SignWorkflowStore.State.SUCCEEDED, Optional.of("SIGNED"),
                    Optional.of(new zeroecho.pki.api.EncodedObject(Encoding.BINARY, certificate.getSignature())), Optional.of(store.signingNow())).orElseThrow();
            new zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver(store)
                    .advance(store.getSignWorkflow(operation).orElseThrow());
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
        }
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            assertEquals(DomainContinuationStore.State.COMPLETED, store.getDomainContinuation(operation).orElseThrow().state());
            assertEquals(legacy, store.getCa(new PkiId("legacy-child")).orElseThrow().subjectRef().value());
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void legacyIntermediateRecoveryRejectsChangedRetainedEvidence(boolean changeSignature, @TempDir Path root) throws Exception {
        java.security.cert.X509Certificate certificate = SemanticIssuanceFixture.caCertificate(
                new javax.security.auth.x500.X500Principal("CN=Legacy Child,O=ZeroEcho,C=CZ"), BigInteger.valueOf(42));
        String legacy = zeroecho.pkix.Pkix.distinguishedNameString(zeroecho.pkix.Pkix.parseDistinguishedName(
                certificate.getSubjectX500Principal().getEncoded()));
        String expected = changeSignature ? "Retained intermediate signature differs from its accepted workflow"
                : "Retained intermediate candidate commitment differs";
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand accepted = legacyIntermediateCommand(store, certificate, legacy);
            assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(accepted));
            SignWorkflowStore.Workflow claim = store.claimSignStep(accepted.operationId(), 0,
                    java.time.Duration.ofSeconds(10)).orElseThrow();
            store.transitionSign(accepted.operationId(), claim.revision(), claim.fence(), SignWorkflowStore.State.SUCCEEDED,
                    Optional.of("SIGNED"), Optional.of(new zeroecho.pki.api.EncodedObject(Encoding.BINARY, certificate.getSignature())),
                    Optional.of(store.signingNow())).orElseThrow();
            new zeroecho.pki.impl.core.continuation.SigningOuterTerminalDriver(store)
                    .advance(store.getSignWorkflow(accepted.operationId()).orElseThrow());
            DomainContinuationStore.Record domain = store.getDomainContinuation(accepted.operationId()).orElseThrow();
            assertEquals(DomainContinuationStore.State.COMPLETED, domain.state());
            byte[] signature = certificate.getSignature();
            byte[] tbs = certificate.getTBSCertificate();
            if (changeSignature) {
                signature[0] ^= 1;
            } else {
                tbs = SemanticIssuanceFixture.caCertificate(certificate.getSubjectX500Principal(), BigInteger.valueOf(43))
                        .getTBSCertificate();
            }
            byte[] changed = zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs, signature, false);
            DomainContinuationStore.Record replacement = new DomainContinuationStore.Record(domain.operationId(), domain.version(),
                    domain.kind(), domain.correlationId(), domain.state(), domain.revision(), domain.createdAt(), domain.deadline(),
                    domain.command(), domain.commandCommitment(), domain.signingContent(),
                    Optional.of(new zeroecho.pki.api.EncodedObject(Encoding.DER, changed)), domain.detailCode());
            zeroecho.pki.spi.store.MetadataKey key = new zeroecho.pki.spi.store.MetadataKey(
                    "io.zeroecho.pki.domain-continuation", accepted.operationId().value());
            long revision;
            try (zeroecho.pki.spi.store.MetadataSnapshot snapshot = store.metadataStore().snapshot();
                    zeroecho.pki.spi.store.MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
                revision = record.recordRevision();
            }
            assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED,
                    store.metadataStore().directCommit(List.of(new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.REPLACE, key, revision,
                            FsCodec.encode(FsCodec.DOMAIN_CONTINUATION, replacement)))).outcome());
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> CrlScopeRecovery.validate(store, reservations(store)));
            assertEquals(expected, failure.getMessage());
        }
        assertThrows(IllegalStateException.class, () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults()));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"CN=Unrelated,O=ZeroEcho,C=CZ", "O=ZeroEcho,CN=Legacy Child,C=CZ"})
    void legacyIntermediateSubjectCannotSelectUnrelatedOrPermutedScope(String subject, @TempDir Path root) throws Exception {
        java.security.cert.X509Certificate certificate = SemanticIssuanceFixture.caCertificate(
                new javax.security.auth.x500.X500Principal("CN=Legacy Child,O=ZeroEcho,C=CZ"), BigInteger.valueOf(42));
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            CrlScope other = CrlScope.of(new javax.security.auth.x500.X500Principal(subject).getEncoded(),
                    certificate.getPublicKey().getEncoded());
            CrlScopeOwner otherOwner = new CrlScopeOwner(other, new PkiId("unrelated-child"));
            reservations(store).claim(otherOwner);
            SignWorkflowStore.AcceptanceCommand invalid = legacyIntermediateCommand(store, certificate, subject);
            CrlScope candidate = candidateScope(invalid, store);
            assertThrows(IllegalArgumentException.class, () -> store.acceptSign(invalid));
            assertTrue(store.getSignWorkflow(invalid.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(invalid.operationId()).isEmpty());
            assertTrue(reservations(store).findOwner(candidate).isEmpty());
            assertEquals(otherOwner, reservations(store).findOwner(other).orElseThrow());
            assertTrue(reservations(store).findReservation(scope(store, SemanticIssuanceFixture.issuer(store, 1)),
                    BigInteger.valueOf(42)).isEmpty());
        }
    }

    private static SignWorkflowStore.AcceptanceCommand legacyIntermediateCommand(FilesystemPkiStore store,
            java.security.cert.X509Certificate certificate, String subject) throws Exception {
        SignWorkflowStore.AcceptanceCommand base = command(store, 1, 42, -1, "", null);
        Credential issuer = SemanticIssuanceFixture.issuer(store, 1);
        DurableContentReference candidate = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER,
                certificate.getTBSCertificate());
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CREATE_INTERMEDIATE",
                "x509", SemanticIssuanceFixture.AUTHORITY.value(), "legacy-child", SemanticIssuanceFixture.issuerId(1).value(),
                SemanticIssuanceFixture.path(1).pathId().value(), SemanticIssuanceFixture.path(1).pathCommitment(), "child-key",
                "profile", "1", "1".repeat(64), subject, SemanticIssuanceFixture.BEFORE.toString(), SemanticIssuanceFixture.AFTER.toString(),
                "42", SemanticIssuanceFixture.KEY.value(), issuer.content().contentId(), issuer.content().sha256(),
                SemanticIssuanceFixture.publicKeyDigest(), "", "", "");
        template = zeroecho.pki.testkit.IntermediateProofProvenanceFixture.withProof(template,
                base.providerNamespace(), base.providerConfigurationCommitment(), candidate.length(), candidate.sha256());
        store.stagedContent().retireUnownedContent(base.candidate());
        return new SignWorkflowStore.AcceptanceCommand(base.operationId(), base.providerNamespace(),
                base.providerConfigurationCommitment(), base.accessContext(), base.keyRef(), base.fairnessAuthorityId(), base.algorithmId(),
                base.signatureEncoding(), base.createdAt(), base.deadline(), candidate, Optional.of(new SignWorkflowStore.OuterCommand(
                        template.kind(), base.operationId().value(), template.command(), template.commandCommitment())),
                SignWorkflowStore.Mode.NORMAL, Optional.empty());
    }

    @Test void extraIntegerInsideCanonicalTbsRejectsWithoutAnyClaim(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            SignWorkflowStore.AcceptanceCommand valid = rootCommand(store, 9);
            CrlScope scope = candidateScope(valid, store);
            org.bouncycastle.asn1.ASN1Sequence original = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                    PkiTestRuntime.readContent(store, valid.candidate()));
            org.bouncycastle.asn1.ASN1EncodableVector fields = new org.bouncycastle.asn1.ASN1EncodableVector();
            for (org.bouncycastle.asn1.ASN1Encodable field : original) { fields.add(field); }
            fields.add(new org.bouncycastle.asn1.ASN1Integer(7));
            byte[] extra = new org.bouncycastle.asn1.DERSequence(fields).getEncoded();
            new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(extra, 1_048_576);
            SignWorkflowStore.AcceptanceCommand invalid = new SignWorkflowStore.AcceptanceCommand(valid.operationId(),
                    valid.providerNamespace(), valid.providerConfigurationCommitment(), valid.accessContext(), valid.keyRef(),
                    valid.fairnessAuthorityId(), valid.algorithmId(), valid.signatureEncoding(), valid.createdAt(), valid.deadline(),
                    PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER, extra), valid.outer(),
                    SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
            assertThrows(IllegalArgumentException.class, () -> store.acceptSign(invalid));
            assertTrue(store.getSignWorkflow(invalid.operationId()).isEmpty());
            assertTrue(store.getDomainContinuation(invalid.operationId()).isEmpty());
            assertTrue(reservations(store).findOwner(scope).isEmpty());
            assertTrue(reservations(store).findReservation(scope, BigInteger.valueOf(9)).isEmpty());
        }
    }

    @Test void rootRolloverRetainsScopeAuthorityAndRejectsSubstitution(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential issuer = SemanticIssuanceFixture.issuer(store, 1);
            store.putCa(new zeroecho.pki.api.ca.CaRecord(SemanticIssuanceFixture.AUTHORITY,
                    zeroecho.pki.api.ca.CaKind.ROOT, zeroecho.pki.api.ca.CaState.ACTIVE, SemanticIssuanceFixture.KEY,
                    issuer.subjectRef(), List.of(SemanticIssuanceFixture.issuerId(1)), SemanticIssuanceFixture.issuerId(1),
                    SemanticIssuanceFixture.path(1).pathId()));
            for (boolean substituted : new boolean[] {false, true}) {
                int serial = substituted ? 10 : 9;
                PkiId authority = substituted ? new PkiId("substituted-authority") : SemanticIssuanceFixture.AUTHORITY;
                SignWorkflowStore.AcceptanceCommand base = rootCommand(store, serial);
                List<String> fields = new java.util.ArrayList<>(DomainCommandEncoding.decode(base.outer().orElseThrow().command()).fields());
                fields.set(13, authority.value());
                DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                        "ROLLOVER_ROOT", fields.toArray(String[]::new));
                SignWorkflowStore.AcceptanceCommand rollover = withOuter(base, new SignWorkflowStore.OuterCommand(template.kind(),
                        base.operationId().value(), template.command(), template.commandCommitment()), authority);
                if (substituted) {
                    assertThrows(IllegalArgumentException.class, () -> store.acceptSign(rollover));
                    assertTrue(store.getSignWorkflow(rollover.operationId()).isEmpty());
                    assertTrue(store.getDomainContinuation(rollover.operationId()).isEmpty());
                    assertTrue(reservations(store).findReservation(scope(store, issuer), BigInteger.TEN).isEmpty());
                } else {
                    assertEquals(SignWorkflowStore.AcceptanceResult.ACCEPTED, store.acceptSign(rollover));
                    ScopeSerialReservation reservation = reservations(store).findReservation(scope(store, issuer), BigInteger.valueOf(9)).orElseThrow();
                    assertEquals(rollover.operationId(), ((ScopeSerialReservation.SigningOwner) reservation.issuanceOwner()).operationId());
                }
                assertEquals(SemanticIssuanceFixture.AUTHORITY, reservations(store).findOwner(scope(store, issuer)).orElseThrow().authorityId());
            }
        }
    }

    static SignWorkflowStore.AcceptanceCommand rootCommand(FilesystemPkiStore store, int serial) throws Exception {
        Instant now = store.signingNow();
        String namespace = store.signingNamespace() + ".scope-test";
        PkiId operation = SigningSubmissionId.create(namespace, now, new SecureRandom()).id();
        PkiId authority = DomainCommandEncoding.rootAuthorityId(operation);
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, "CREATE_ROOT",
                "x509", "root", "root", SemanticIssuanceFixture.KEY.value(), "profile", "1", "1".repeat(64),
                SemanticIssuanceFixture.BEFORE.toString(), SemanticIssuanceFixture.AFTER.toString(), Integer.toString(serial),
                "CN=Acceptance Issuer", "", "", authority.value());
        byte[] tbs = SemanticIssuanceFixture.certificate("CN=Acceptance Issuer", BigInteger.valueOf(serial),
                SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER).toASN1Structure().getTBSCertificate().getEncoded();
        return new SignWorkflowStore.AcceptanceCommand(operation, namespace, new SigningProvider.ConfigurationCommitment(new byte[32]),
                new AccessContext(new Principal("TEST", "scope"), new Purpose("SIGN"), Optional.empty(), Optional.empty()),
                SemanticIssuanceFixture.KEY, authority, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(),
                Encoding.BINARY, now, now.plusSeconds(60), PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER, tbs),
                Optional.of(new SignWorkflowStore.OuterCommand(template.kind(), operation.value(), template.command(), template.commandCommitment())),
                SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
    }

    static CrlScope candidateScope(SignWorkflowStore.AcceptanceCommand command, FilesystemPkiStore store) throws Exception {
        org.bouncycastle.asn1.x509.TBSCertificate candidate = org.bouncycastle.asn1.x509.TBSCertificate.getInstance(
                PkiTestRuntime.readContent(store, command.candidate()));
        return CrlScope.of(candidate.getSubject().getEncoded(), candidate.getSubjectPublicKeyInfo().getEncoded());
    }

    private static SignWorkflowStore.AcceptanceCommand withOuter(SignWorkflowStore.AcceptanceCommand command,
            SignWorkflowStore.OuterCommand outer, PkiId fairness) {
        return new SignWorkflowStore.AcceptanceCommand(command.operationId(), command.providerNamespace(),
                command.providerConfigurationCommitment(), command.accessContext(), command.keyRef(), fairness, command.algorithmId(),
                command.signatureEncoding(), command.createdAt(), command.deadline(), command.candidate(), Optional.of(outer),
                SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
    }

    @Test void mismatchedFrozenCoordinatesRejectWithoutAnyAcceptanceOrReservation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential issuer = SemanticIssuanceFixture.issuer(store, 1);
            CrlScope scope = scope(store, issuer);
            for (int field : new int[] {0, 1, 2, 3, 8, 9, 10, 11, 12, 13, 14}) {
                SignWorkflowStore.AcceptanceCommand command = command(store, 1, 42, field,
                        field == 3 || field == 13 || field == 14 ? "2".repeat(64)
                        : field == 8 || field == 9 ? "2027-01-01T00:00:00Z" : field == 10 ? "43" : "different", null);
                assertThrows(IllegalArgumentException.class, () -> store.acceptSign(command), "field " + field);
                assertTrue(store.getSignWorkflow(command.operationId()).isEmpty());
                assertTrue(store.getDomainContinuation(command.operationId()).isEmpty());
                assertTrue(reservations(store).findReservation(scope, BigInteger.valueOf(42)).isEmpty());
            }
        }
    }

    @Test void malformedAndTrailingCandidateRejectWithoutReservation(@TempDir Path root) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            Credential issuer = SemanticIssuanceFixture.issuer(store, 1);
            byte[] valid = SemanticIssuanceFixture.certificate("CN=Leaf", BigInteger.valueOf(42),
                    SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER).toASN1Structure().getTBSCertificate().getEncoded();
            for (byte[] invalid : List.of(new byte[] {1, 2, 3}, java.util.Arrays.copyOf(valid, valid.length + 1))) {
                SignWorkflowStore.AcceptanceCommand command = command(store, 1, 42, -1, "", invalid);
                assertThrows(RuntimeException.class, () -> store.acceptSign(command));
                assertTrue(store.getSignWorkflow(command.operationId()).isEmpty());
                assertTrue(reservations(store).findReservation(scope(store, issuer), BigInteger.valueOf(42)).isEmpty());
            }
        }
    }

    static SignWorkflowStore.AcceptanceCommand command(FilesystemPkiStore store, int generation, int serial,
            int changedField, String changed, byte[] candidate) throws Exception {
        Credential issuer = SemanticIssuanceFixture.issuer(store, generation);
        Instant now = store.signingNow();
        String namespace = store.signingNamespace() + ".scope-test";
        PkiId operation = SigningSubmissionId.create(namespace, now, new SecureRandom()).id();
        String[] fields = {SemanticIssuanceFixture.AUTHORITY.value(), SemanticIssuanceFixture.issuerId(generation).value(),
                SemanticIssuanceFixture.path(generation).pathId().value(), SemanticIssuanceFixture.path(generation).pathCommitment(),
                "profile", "1", "1".repeat(64), "CN=Leaf", SemanticIssuanceFixture.BEFORE.toString(),
                SemanticIssuanceFixture.AFTER.toString(), Integer.toString(serial), SemanticIssuanceFixture.KEY.value(),
                issuer.content().contentId(), issuer.content().sha256(), SemanticIssuanceFixture.publicKeyDigest(),
                "", "", "", "", "", "", "", DomainAttributeEncoding.encode(new SimpleAttributeSet())};
        if (changedField >= 0) { fields[changedField] = changed; }
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                "ISSUE_END_ENTITY", fields);
        byte[] tbs = candidate == null ? SemanticIssuanceFixture.certificate("CN=Leaf", BigInteger.valueOf(serial),
                SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER).toASN1Structure().getTBSCertificate().getEncoded() : candidate;
        DurableContentReference content = PkiTestRuntime.operationReference(store.stagedContent(), Encoding.DER, tbs);
        return new SignWorkflowStore.AcceptanceCommand(operation, namespace, new SigningProvider.ConfigurationCommitment(new byte[32]),
                new AccessContext(new Principal("TEST", "scope"), new Purpose("SIGN"), Optional.empty(), Optional.empty()),
                SemanticIssuanceFixture.KEY, SemanticIssuanceFixture.AUTHORITY,
                zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Encoding.BINARY,
                now, now.plusSeconds(60), content, Optional.of(new SignWorkflowStore.OuterCommand(template.kind(),
                        operation.value(), template.command(), template.commandCommitment())),
                        SignWorkflowStore.Mode.NORMAL, java.util.Optional.empty());
    }

    static CrlScopeReservationStore reservations(FilesystemPkiStore store) {
        return new CrlScopeReservationStore(store.metadataStore(), BigInteger.ONE, result -> { });
    }

    static CrlScope scope(FilesystemPkiStore store, Credential issuer) throws Exception {
        java.security.cert.X509Certificate certificate = store.certificateHolder(issuer);
        return CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), certificate.getPublicKey().getEncoded());
    }
}
