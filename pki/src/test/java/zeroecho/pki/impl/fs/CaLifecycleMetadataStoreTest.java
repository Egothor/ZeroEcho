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

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.ca.*;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.testkit.IssuerBindingFixture;

/** Durable root-candidate registration, fenced activation, snapshot and reopen semantics. */
final class CaLifecycleMetadataStoreTest {
    @Test void candidateIsPendingUntilOneFencedAcknowledgedActivationAndSurvivesSnapshots(@TempDir Path root) throws Exception {
        PkiId authority;
        RootTrustAnchorTransition transition;
        RootTrustAnchorActivation activation;
        Path pending = root.resolve("pending"), activated = root.resolve("activated");
        try (var store = new FilesystemPkiStore(root.resolve("source"), FsPkiStoreOptions.defaults())) {
            CaRecord ca = FilesystemPkiStoreTest.TestObjects.minimalCaRecord(store, "root-lifecycle", CaState.ACTIVE);
            store.putCa(ca); authority = ca.caId();
            var original = store.getCaHeadSnapshot(authority).orElseThrow();
            var material = candidate(store, ca, original);
            transition = material.transition();
            var registrationConflict = new AuthorityMetadataStore(new HeadConflictMetadata(store.metadataStore(), authority), ignored -> { });
            RootTrustAnchorTransition unregistered = transition;
            assertEquals("Root candidate registration lost its expected head conflict",
                    assertThrows(IllegalArgumentException.class, () -> registrationConflict.registerCandidate(unregistered, FsHistoryPolicy.disabled())).getMessage());
            assertEquals(original, store.getCaHeadSnapshot(authority).orElseThrow());
            assertEquals(transition, store.registerRootCandidate(transition));
            assertEquals(transition, store.registerRootCandidate(transition));
            var changedTransition = new RootTrustAnchorTransition(transition.version(), transition.transitionId(), authority, original,
                    transition.oldCredentialId(), transition.oldCertificateSha256(), transition.oldBindingCommitment(),
                    transition.candidateIssuerId(), transition.candidatePathId(), transition.candidateCredentialId(),
                    transition.candidateCertificateSha256(), transition.candidateBindingCommitment(), transition.originatingSigningOperationId(),
                    "domain:v1:" + "4".repeat(64));
            assertEquals("Root candidate transition ID already has different immutable content",
                    assertThrows(IllegalArgumentException.class, () -> store.registerRootCandidate(changedTransition)).getMessage());
            var stale = new CaHeadSnapshot(1, authority, original.epoch() + 1, original.issuerId(), original.pathId(), original.bindingCommitment());
            var staleActivation = new RootTrustAnchorActivation(1, transition.transitionId(), transition.commitment(), stale,
                    transition.candidateIssuerId(), transition.candidatePathId(), stale.epoch() + 1, new PkiId("stale-activation"),
                    "root-operator", "1".repeat(64), "2".repeat(64), Instant.now(), true);
            RootTrustAnchorTransition pendingTransition = transition;
            assertEquals("Root activation expected head or approved receipt differs from its candidate",
                    assertThrows(IllegalArgumentException.class, () -> store.activateRootCandidate(pendingTransition.transitionId(), stale, staleActivation)).getMessage());
            assertEquals(original, store.getCaHeadSnapshot(authority).orElseThrow());
            assertEquals(ca.currentIssuanceIssuerId(), store.getCa(authority).orElseThrow().currentIssuanceIssuerId());
            CaRecord pendingCa = store.getCa(authority).orElseThrow();
            CaRecord bypass = new CaRecord(authority, ca.kind(), ca.state(), store.getIssuerGeneration(transition.candidateIssuerId()).orElseThrow().signingKeyRef(),
                    ca.subjectRef(), pendingCa.issuerIds(), transition.candidateIssuerId(), transition.candidatePathId());
            assertEquals("Selected CA head changes require an admitted epoch fence",
                    assertThrows(IllegalArgumentException.class, () -> store.putCa(bypass)).getMessage());
            assertEquals(original, store.getCaHeadSnapshot(authority).orElseThrow());
            assertEquals("Root anchor changes require an acknowledged candidate activation",
                    assertThrows(IllegalArgumentException.class, () -> store.compareAndSetCaHead(original, bypass)).getMessage());
            assertEquals(original, store.getCaHeadSnapshot(authority).orElseThrow());
            store.exportSnapshot(pending, Instant.now().plusSeconds(1));
            activation = new RootTrustAnchorActivation(1, transition.transitionId(), transition.commitment(), original,
                    transition.candidateIssuerId(), transition.candidatePathId(), original.epoch() + 1,
                    new PkiId("activation-request"), "root-operator", "1".repeat(64), "2".repeat(64), Instant.now(), true);
            var activationConflict = new AuthorityMetadataStore(new HeadConflictMetadata(store.metadataStore(), authority), ignored -> { });
            RootTrustAnchorActivation unactivated = activation;
            assertEquals("Root activation lost its expected head conflict",
                    assertThrows(IllegalArgumentException.class, () -> activationConflict.activateCandidate(pendingTransition.transitionId(), original, unactivated, FsHistoryPolicy.disabled())).getMessage());
            assertEquals(original, store.getCaHeadSnapshot(authority).orElseThrow());
            assertEquals(activation, store.activateRootCandidate(transition.transitionId(), original, activation));
            assertEquals(activation, store.activateRootCandidate(transition.transitionId(), original, activation));
            assertEquals(transition, store.registerRootCandidate(transition));
            assertEquals(2, store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            var changedActivation = new RootTrustAnchorActivation(activation.version(), activation.transitionId(), activation.transitionCommitment(),
                    activation.expectedHead(), activation.candidateIssuerId(), activation.candidatePathId(), activation.newEpoch(),
                    activation.activationRequestId(), "different-actor", activation.approvalPolicyCommitment(), activation.approvedTargetCommitment(), activation.acceptedAt(), true);
            assertEquals("Root activation already has a different immutable receipt",
                    assertThrows(IllegalArgumentException.class, () -> store.activateRootCandidate(pendingTransition.transitionId(), original, changedActivation)).getMessage());
            var staleCandidateOperation = new PkiId("stale-candidate-operation");
            var staleCandidate = new RootTrustAnchorTransition(1, RootTrustAnchorTransition.idFor(staleCandidateOperation), authority, original,
                    transition.oldCredentialId(), transition.oldCertificateSha256(), transition.oldBindingCommitment(),
                    transition.candidateIssuerId(), transition.candidatePathId(), transition.candidateCredentialId(),
                    transition.candidateCertificateSha256(), transition.candidateBindingCommitment(), staleCandidateOperation, transition.commandCommitment());
            assertEquals("Root candidate expected head is stale or authority is inactive",
                    assertThrows(IllegalArgumentException.class, () -> store.registerRootCandidate(staleCandidate)).getMessage());
            assertEquals(2, store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            assertFalse(store.compareAndSetCaHead(original, bypass));
            store.exportSnapshot(activated, Instant.now().plusSeconds(1));
            var current = store.getCa(authority).orElseThrow();
            PkiId renewal = retainRoot(store, current, material.keys(), "renewed-root", 3);
            var renewalPath = IssuerChainPath.create(authority, renewal, List.of(store.getIssuerGeneration(renewal).orElseThrow().credentialId()));
            var members = new java.util.ArrayList<>(current.issuerIds()); members.add(renewal);
            var renewed = new CaRecord(authority, current.kind(), current.state(), current.issuerKeyRef(), current.subjectRef(), members, renewal, renewalPath.pathId());
            assertTrue(store.compareAndSetCaHead(store.getCaHeadSnapshot(authority).orElseThrow(), renewed));
            var reselection = new CaRecord(authority, current.kind(), current.state(), current.issuerKeyRef(), current.subjectRef(), members,
                    transition.candidateIssuerId(), transition.candidatePathId());
            assertTrue(store.compareAndSetCaHead(store.getCaHeadSnapshot(authority).orElseThrow(), reselection));
            assertEquals(4, store.getCaHeadSnapshot(authority).orElseThrow().epoch());

        }
        try (var store = new FilesystemPkiStore(root.resolve("source"), FsPkiStoreOptions.defaults())) {
            assertEquals(4, store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            assertEquals(activation, store.getRootTrustAnchorActivation(transition.transitionId()).orElseThrow());
            assertEquals(transition.candidateIssuerId(), store.getCa(authority).orElseThrow().currentIssuanceIssuerId());
        }
        try (var store = new FilesystemPkiStore(pending, FsPkiStoreOptions.defaults())) {
            assertEquals(1, store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            assertEquals(transition, store.getRootTrustAnchorTransitionForIssuer(transition.candidateIssuerId()).orElseThrow());
            assertTrue(store.getRootTrustAnchorActivation(transition.transitionId()).isEmpty());
        }
        try (var store = new FilesystemPkiStore(activated, FsPkiStoreOptions.defaults())) {
            assertEquals(2, store.getCaHeadSnapshot(authority).orElseThrow().epoch());
            assertEquals(activation, store.getRootTrustAnchorActivation(transition.transitionId()).orElseThrow());
            assertEquals(transition.candidateIssuerId(), store.getCa(authority).orElseThrow().currentIssuanceIssuerId());
            try (var snapshot = store.metadataStore().snapshot(); var transaction = store.metadataStore().beginTransaction();
                    var receipt = snapshot.get(CaLifecycleMetadataCodec.activationKey(transition.transitionId())).orElseThrow()) {
                transaction.delete(receipt.key(), receipt.recordRevision());
                assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED, transaction.commit().outcome());
            }
            assertThrows(RuntimeException.class, () -> store.exportSnapshot(root.resolve("invalid-restore-source"), Instant.now().plusSeconds(1)));
        }
        assertThrows(RuntimeException.class, () -> new FilesystemPkiStore(activated, FsPkiStoreOptions.defaults()));
    }

    private static Candidate candidate(FilesystemPkiStore store, CaRecord ca, CaHeadSnapshot original) throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var keys = generator.generateKeyPair();
        PkiId issuerId = retainRoot(store, ca, keys, "candidate-root", 2);
        var credentialId = store.getIssuerGeneration(issuerId).orElseThrow().credentialId();
        var path = IssuerChainPath.create(ca.caId(), issuerId, List.of(credentialId));
        var old = store.getIssuerGeneration(original.issuerId()).orElseThrow();
        var oldBinding = store.getIssuerCryptographicBinding(old.issuerId()).orElseThrow();
        var newBinding = store.getIssuerCryptographicBinding(issuerId).orElseThrow();
        var operation = new PkiId("candidate-signing-operation");
        return new Candidate(new RootTrustAnchorTransition(1, RootTrustAnchorTransition.idFor(operation), ca.caId(), original,
                old.credentialId(), oldBinding.certificateSha256(), oldBinding.commitment(), issuerId, path.pathId(), credentialId,
                newBinding.certificateSha256(), newBinding.commitment(), operation, "domain:v1:" + "3".repeat(64)), keys);
    }
    private record Candidate(RootTrustAnchorTransition transition, java.security.KeyPair keys) { }

    private static PkiId retainRoot(FilesystemPkiStore store, CaRecord ca, java.security.KeyPair keys, String label, int serial) throws Exception {
        var sourceGeneration = store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow();
        Credential source = store.getCredential(sourceGeneration.credentialId()).orElseThrow();
        var name = new org.bouncycastle.asn1.x500.X500Name(ca.subjectRef().value());
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, java.math.BigInteger.valueOf(serial),
                java.util.Date.from(source.validity().notBefore()), java.util.Date.from(source.validity().notAfter()), name, keys.getPublic());
        byte[] der = builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())).getEncoded();
        var content = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(store.stagedContent(), zeroecho.pki.api.Encoding.DER, der);
        PkiId credentialId = new PkiId(label + "-credential");
        PkiId issuerId = IssuerGeneration.idFor(ca.caId(), credentialId);
        var path = IssuerChainPath.create(ca.caId(), issuerId, List.of(credentialId));
        store.putCredential(new Credential(credentialId, source.formatId(), new IssuerRef(ca.caId(), issuerId, path.pathId()),
                source.subjectRef(), source.validity(), Integer.toString(serial), new PkiId("candidate-public-key"), source.profileBinding(),
                source.status(), content, source.attributes()));
        var generation = new IssuerGeneration(issuerId, ca.caId(), credentialId, new zeroecho.pki.api.KeyRef("candidate-root-key"),
                IssuerGenerationState.ACTIVE, sourceGeneration.profilePolicyCommitment(), sourceGeneration.x509BindingCommitment());
        IssuerBindingFixture.put(store, generation, zeroecho.core.alg.BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256);
        store.putIssuerChainPath(path);
        return issuerId;
    }

    /** Forces one real metadata CAS loss without changing the logical head or fabricating an outcome. */
    private static final class HeadConflictMetadata implements zeroecho.pki.spi.store.TransactionalMetadataStore {
        private final zeroecho.pki.spi.store.TransactionalMetadataStore delegate;
        private final zeroecho.pki.spi.store.MetadataKey head;
        HeadConflictMetadata(zeroecho.pki.spi.store.TransactionalMetadataStore delegate, PkiId caId) {
            this.delegate = delegate; this.head = CaLifecycleMetadataCodec.headKey(caId);
        }
        @Override public zeroecho.pki.spi.store.MetadataStoreId id() { return delegate.id(); }
        @Override public zeroecho.pki.spi.store.MetadataStoreCapabilities capabilities() { return delegate.capabilities(); }
        @Override public zeroecho.pki.spi.store.MetadataSnapshot snapshot() throws java.io.IOException { return delegate.snapshot(); }
        @Override public zeroecho.pki.spi.store.MetadataCommitResult resolve(zeroecho.pki.spi.store.MetadataTransactionId id) throws java.io.IOException { return delegate.resolve(id); }
        @Override public void acknowledge(zeroecho.pki.spi.store.MetadataTransactionId id) throws java.io.IOException { delegate.acknowledge(id); }
        @Override public void close() { }
        @Override public zeroecho.pki.spi.store.MetadataTransaction beginTransaction() throws java.io.IOException {
            var transaction = delegate.beginTransaction();
            return new zeroecho.pki.spi.store.MetadataTransaction() {
                @Override public zeroecho.pki.spi.store.MetadataTransactionId id() { return transaction.id(); }
                @Override public void create(zeroecho.pki.spi.store.MetadataKey key, zeroecho.core.io.RepeatableContent content,
                        zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException { transaction.create(key, content, cancellation); }
                @Override public void replace(zeroecho.pki.spi.store.MetadataKey key, long revision, zeroecho.core.io.RepeatableContent content,
                        zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException { transaction.replace(key, revision, content, cancellation); }
                @Override public void delete(zeroecho.pki.spi.store.MetadataKey key, long revision) { transaction.delete(key, revision); }
                @Override public zeroecho.pki.spi.store.MetadataCommitResult commit() throws java.io.IOException {
                    try (var snapshot = delegate.snapshot(); var retained = snapshot.get(head).orElseThrow();
                            var competing = delegate.beginTransaction();
                            var bytes = new zeroecho.core.io.ImmutableByteContent(CredentialMetadataAuthority.read(retained, AuthorityMetadataCodec.MAX_VALUE_BYTES))) {
                        competing.replace(head, retained.recordRevision(), bytes, zeroecho.core.io.CancellationSignal.NONE);
                        assertEquals(zeroecho.pki.spi.store.MetadataCommitResult.Outcome.COMMITTED, competing.commit().outcome());
                    }
                    return transaction.commit();
                }
                @Override public void abort() throws java.io.IOException { transaction.abort(); }
                @Override public void close() throws java.io.IOException { transaction.close(); }
            };
        }
    }

}
