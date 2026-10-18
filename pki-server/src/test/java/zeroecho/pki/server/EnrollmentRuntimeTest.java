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

package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

class EnrollmentRuntimeTest {
    @TempDir Path directory;
    private static KeyPair rootKey;
    private static KeyPair raKey;
    private static X509Certificate rootCertificate;
    private static X509Certificate raCertificate;
    private static HttpServerTestSupport.Fixture tls;

    @BeforeAll
    static void material() throws Exception {
        tls = HttpServerTestSupport.tls();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] { 71, 11, 4, 7 });
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, random);
        rootKey = generator.generateKeyPair();
        raKey = generator.generateKeyPair();
        X500Principal rootName = new X500Principal("CN=Enrollment Root");
        rootCertificate = Pkix.certificateBuilder().subject(rootName).issuer(rootName)
                .serialNumber(java.math.BigInteger.ONE).publicKey(rootKey.getPublic())
                .validity(Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2028-01-01T00:00:00Z"))
                .basicConstraints(BasicConstraints.ca(), true).keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN), true)
                .build(Pkix.signer(rootKey.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
        raCertificate = Pkix.certificateBuilder().subject(new X500Principal("CN=Enrollment RA")).issuer(rootName)
                .serialNumber(java.math.BigInteger.TWO).publicKey(raKey.getPublic())
                .validity(Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2027-01-01T00:00:00Z"))
                .basicConstraints(BasicConstraints.endEntity(), true)
                .keyUsage(Set.of(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT), true)
                .build(Pkix.signer(rootKey.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
    }

    @Test
    void realCustodySurvivesRestartAndCloseFencesWhileBorrowed() throws Exception {
        Fixture fixture = fixture();
        Path log;
        AtomicReference<KeyringPassword> acquired = new AtomicReference<>();
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> {
            KeyringPassword password = password(); acquired.set(password); return password;
        });
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            log = store.log();
            EnrollmentRuntime runtime = open(fixture, store.store(), dependencies);
            assertTrue(acquired.get().isDestroyed());
            assertThrows(Exception.class, () -> { try (KeyringPassword password = password();
                    KeyringStore ignored = KeyringStore.open(fixture.keyring(), password)) { } });
            EnrollmentRuntime.CredentialLease lease = runtime.acquire("scep-a");
            assertThrows(IllegalStateException.class, () -> runtime.acquire("scep-a"));
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(lease.privateKey()); signature.update(new byte[] { 1, 2, 3 });
            byte[] signed = signature.sign();
            signature.initVerify(lease.responseChain().getFirst()); signature.update(new byte[] { 1, 2, 3 });
            assertTrue(signature.verify(signed));
            assertThrows(IllegalStateException.class, runtime::close);
            assertThrows(IllegalStateException.class, () -> runtime.acquire("scep-a"));
            assertThrows(Exception.class, () -> { try (KeyringPassword password = password();
                    KeyringStore ignored = KeyringStore.open(fixture.keyring(), password)) { } });
            assertEquals(raCertificate, lease.responseChain().getFirst());
            lease.close(); lease.close();
            assertThrows(IllegalStateException.class, lease::privateKey);
            runtime.close(); runtime.close();
            try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(fixture.keyring(), password)) {
                assertTrue(reopened.contains("ra.priv"));
            }
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)));
                EnrollmentRuntime reopened = open(fixture, control, dependencies)) {
            assertEquals("scep-a", reopened.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, "authority"));
            assertEquals(ServerTestSupport.CLOCK.instant().plusSeconds(600), reopened.admissionDeadline("scep-a"));
        }
    }

    @Test void explicitEstGeneratorSignerUsesExistingCustodyAndSurvivesRestart() throws Exception {
        Fixture original = fixture();
        EnrollmentRuntimeConfiguration.CredentialSet prior = original.configuration().credentialSets().getFirst();
        EnrollmentRuntimeConfiguration.CredentialSet signer = new EnrollmentRuntimeConfiguration.CredentialSet("est-generator-v1",
                EnrollmentRuntimeConfiguration.Protocol.EST, prior.authorityId(), prior.issuerId(), prior.chainPathId(),
                prior.signer(), List.of(), List.of(), Optional.empty());
        EnrollmentRuntimeConfiguration configuration = new EnrollmentRuntimeConfiguration(original.configuration().budgets(),
                original.configuration().keyrings(), List.of(signer), List.of(new EnrollmentRuntimeConfiguration.ActiveCredential(
                        signer.protocol(), signer.authorityId(), signer.credentialId())), Optional.empty());
        Fixture fixture = original.withConfiguration(configuration);
        Path log;
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            log = store.log();
            try (EnrollmentRuntime runtime = open(fixture, store.store(), dependencies());
                    EnrollmentRuntime.CredentialLease lease = runtime.acquire(signer.credentialId())) {
                assertEquals(signer.credentialId(), runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.EST, "authority"));
                runtime.requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol.EST, signer.credentialId(), signer.authorityId(), signer.issuerId(), signer.chainPathId());
                assertThrows(IllegalStateException.class, () -> runtime.requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol.CMP,
                        signer.credentialId(), signer.authorityId(), signer.issuerId(), signer.chainPathId()));
                assertThrows(IllegalStateException.class, () -> runtime.requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol.EST,
                        "missing", signer.authorityId(), signer.issuerId(), signer.chainPathId()));
                assertThrows(IllegalStateException.class, () -> runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, "authority"));
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(lease.privateKey()); signature.update(new byte[] { 9, 2, 6 });
                byte[] proof = signature.sign();
                signature.initVerify(lease.responseChain().getFirst()); signature.update(new byte[] { 9, 2, 6 });
                assertTrue(signature.verify(proof));
            }
        }
        try (ServerControlStore control = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)));
                EnrollmentRuntime runtime = open(fixture, control, dependencies());
                EnrollmentRuntime.CredentialLease lease = runtime.acquire(signer.credentialId())) {
            assertEquals(raCertificate, lease.responseChain().getFirst());
        }
        assertThrows(IllegalArgumentException.class, () -> new EnrollmentRuntimeConfiguration.CredentialSet("bad",
                signer.protocol(), signer.authorityId(), signer.issuerId(), signer.chainPathId(), Optional.empty(), List.of(), List.of(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new EnrollmentRuntimeConfiguration.CredentialSet("bad",
                signer.protocol(), signer.authorityId(), signer.issuerId(), signer.chainPathId(), signer.signer(), List.of(original.ra()), List.of(), Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new EnrollmentRuntimeConfiguration.CredentialSet("bad",
                signer.protocol(), signer.authorityId(), signer.issuerId(), signer.chainPathId(), signer.signer(), List.of(), List.of("a".repeat(64)), Optional.empty()));
    }

    @Test
    void rejectsChangedSameIdAndCorruptCommitmentAndReleasesFailedOwners() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            try (EnrollmentRuntime runtime = open(fixture, store.store(), dependencies())) { }
            byte[] original = Files.readAllBytes(fixture.ra());
            Files.write(fixture.ra(), rootCertificate.getEncoded());
            assertThrows(IllegalStateException.class, () -> open(fixture, store.store(), dependencies()));
            Files.write(fixture.ra(), original);
            try (KeyringPassword password = password(); KeyringStore ring = KeyringStore.open(fixture.keyring(), password)) {
                ring.putPrivate("ra", "RSA", rootKey.getPrivate());
            }
            assertThrows(IllegalStateException.class, () -> open(fixture, store.store(), dependencies()));
            try (KeyringPassword password = password(); KeyringStore ring = KeyringStore.open(fixture.keyring(), password)) {
                ring.putPrivate("ra", "RSA", raKey.getPrivate());
            }
            ServerControlStore.ProtocolRecord previous = store.store().protocolRecord(ServerControlStore.ENROLLMENT_CREDENTIAL, "scep-a").orElseThrow();
            store.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                    previous.namespace(), previous.recordId(), "0".repeat(64), new byte[] { 2 }), Optional.of(previous.commitment()))));
            assertThrows(IllegalStateException.class, () -> open(fixture, store.store(), dependencies()));
            try (KeyringPassword password = password(); KeyringStore ignored = KeyringStore.open(fixture.keyring(), password)) { }
        }
    }

    @Test
    void rolloverKeepsOldSelectionAndMissingPinnedSetsFailClosed() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            try (EnrollmentRuntime runtime = open(fixture, store.store(), dependencies())) { }
            EnrollmentRuntimeConfiguration.CredentialSet first = fixture.configuration().credentialSets().getFirst();
            EnrollmentRuntimeConfiguration.CredentialSet second = new EnrollmentRuntimeConfiguration.CredentialSet("scep-b",
                    first.protocol(), first.authorityId(), first.issuerId(), first.chainPathId(), first.signer(),
                    first.requestTrustAnchors(), first.authorizedRaKeys(), first.pbm());
            EnrollmentRuntimeConfiguration next = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                    fixture.configuration().keyrings(), List.of(first, second), List.of(
                            new EnrollmentRuntimeConfiguration.ActiveCredential(first.protocol(), first.authorityId(), "scep-b")), Optional.empty());
            try (EnrollmentRuntime runtime = open(fixture.withConfiguration(next), store.store(), dependencies())) {
                assertEquals("scep-b", runtime.activeCredentialId(first.protocol(), first.authorityId()));
                try (EnrollmentRuntime.CredentialLease retained = runtime.acquire("scep-a")) {
                    assertEquals("scep-a", retained.configuration().credentialId());
                }
            }
            assertThrows(IllegalStateException.class, () -> open(fixture, store.store(), dependencies()));
        }
    }

    @Test
    void rejectsWrongAuthorityMissingUnlockAndResolvedStorageOverlap() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            assertThrows(IllegalStateException.class, () -> open(fixture, store.store(), PkiSessionRuntimeDependencies.none()));
            EnrollmentRuntimeConfiguration.CredentialSet source = fixture.configuration().credentialSets().getFirst();
            EnrollmentRuntimeConfiguration.CredentialSet wrong = new EnrollmentRuntimeConfiguration.CredentialSet("other",
                    source.protocol(), "other-authority", source.issuerId(), source.chainPathId(), source.signer(), List.of(), List.of(), Optional.empty());
            EnrollmentRuntimeConfiguration wrongConfig = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                    fixture.configuration().keyrings(), List.of(wrong), List.of(), Optional.empty());
            assertThrows(IllegalStateException.class, () -> open(fixture.withConfiguration(wrongConfig), store.store(), dependencies()));
            Path symlink = directory.resolve("store-link");
            Files.createSymbolicLink(symlink, Path.of(fixture.realm().pkiSessionConfiguration().store().require("root")));
            EnrollmentRuntimeConfiguration overlapped = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                    List.of(), List.of(), List.of(), Optional.of(new EnrollmentRuntimeConfiguration.KeygenArtifacts(
                            symlink, 1024, 2048, 2, 1, Duration.ofMinutes(10))));
            assertThrows(IllegalArgumentException.class, () -> open(fixture.withConfiguration(overlapped), store.store(), dependencies()));
        }
    }

    @Test
    void pbmCommitmentDetectsSecretAndOwnerPolicyReplacement() throws Exception {
        Fixture fixture = fixture();
        EnrollmentRuntimeConfiguration.CredentialSet original = fixture.configuration().credentialSets().getFirst();
        EnrollmentRuntimeConfiguration.PbmIdentity identity = new EnrollmentRuntimeConfiguration.PbmIdentity("0123", "device",
                new EnrollmentRuntimeConfiguration.KeyReference("protocol", "pbm"), List.of("administrator"));
        EnrollmentRuntimeConfiguration.Pbm pbm = new EnrollmentRuntimeConfiguration.Pbm(1000, 10000, 16, 32,
                Set.of(EnrollmentRuntimeConfiguration.PbmDigest.SHA256), Set.of(EnrollmentRuntimeConfiguration.PbmMac.HMAC_SHA256), List.of(identity));
        EnrollmentRuntimeConfiguration.CredentialSet cmp = new EnrollmentRuntimeConfiguration.CredentialSet("cmp-a",
                EnrollmentRuntimeConfiguration.Protocol.CMP, original.authorityId(), original.issuerId(), original.chainPathId(),
                Optional.empty(), List.of(), List.of(), Optional.of(pbm));
        EnrollmentRuntimeConfiguration config = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                fixture.configuration().keyrings(), List.of(cmp), List.of(new EnrollmentRuntimeConfiguration.ActiveCredential(
                        cmp.protocol(), cmp.authorityId(), cmp.credentialId())), Optional.empty());
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            try (EnrollmentRuntime runtime = open(fixture.withConfiguration(config), store.store(), dependencies());
                    EnrollmentRuntime.CredentialLease lease = runtime.acquire("cmp-a")) {
                assertEquals(32, lease.pbmSecret("0123").getEncoded().length);
                assertThrows(IllegalStateException.class, () -> lease.pbmSecret("abcd"));
                assertThrows(IllegalStateException.class, lease::privateKey);
            }
            EnrollmentRuntimeConfiguration.PbmIdentity differentOwner = new EnrollmentRuntimeConfiguration.PbmIdentity("0123", "device",
                    identity.secret(), List.of("different-administrator"));
            EnrollmentRuntimeConfiguration.Pbm changedPolicy = new EnrollmentRuntimeConfiguration.Pbm(1000, 10000, 16, 32,
                    pbm.digests(), pbm.macs(), List.of(differentOwner));
            EnrollmentRuntimeConfiguration.CredentialSet changedSet = new EnrollmentRuntimeConfiguration.CredentialSet(cmp.credentialId(),
                    cmp.protocol(), cmp.authorityId(), cmp.issuerId(), cmp.chainPathId(), cmp.signer(), List.of(), List.of(), Optional.of(changedPolicy));
            EnrollmentRuntimeConfiguration changedConfig = new EnrollmentRuntimeConfiguration(config.budgets(), config.keyrings(),
                    List.of(changedSet), config.activeCredentials(), Optional.empty());
            assertThrows(IllegalStateException.class, () -> open(fixture.withConfiguration(changedConfig), store.store(), dependencies()));
            try (KeyringPassword password = password(); KeyringStore ring = KeyringStore.open(fixture.keyring(), password)) {
                byte[] changed = new byte[32]; java.util.Arrays.fill(changed, (byte) 6);
                ring.putSecret("pbm", "HMAC", new SecretKeySpec(changed, "HmacSHA256"));
            }
            assertThrows(IllegalStateException.class, () -> open(fixture.withConfiguration(config), store.store(), dependencies()));
        }
    }

    @Test
    void lostCommitAcknowledgementCannotLeaveAnOwnerOrReplacePinnedIdentity() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            ServerControlStore uncertain = org.mockito.Mockito.spy(store.store());
            org.mockito.Mockito.doAnswer(invocation -> {
                invocation.callRealMethod();
                throw new IllegalStateException("simulated lost acknowledgement");
            }).when(uncertain).mutateProtocol(org.mockito.ArgumentMatchers.anyList());
            assertThrows(IllegalStateException.class, () -> open(fixture, uncertain, dependencies()));
            try (EnrollmentRuntime recovered = open(fixture, store.store(), dependencies())) {
                assertEquals("scep-a", recovered.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, "authority"));
            }
        }
    }

    @Test
    void validityBoundsAdmissionAndExpiredRetainedCredentialsRemainUnavailable() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            java.time.Clock nearExpiry = java.time.Clock.fixed(Instant.parse("2026-12-31T23:59:00Z"), java.time.ZoneOffset.UTC);
            try (EnrollmentRuntime runtime = EnrollmentRuntime.open(fixture.configuration(), fixture.realm(), fixture.repository(),
                    store.store(), registry(store.store()), dependencies(), nearExpiry, Optional.empty())) {
                assertEquals(Instant.parse("2027-01-01T00:00:00Z"), runtime.admissionDeadline("scep-a"));
            }
            java.time.Clock expired = java.time.Clock.fixed(Instant.parse("2027-01-01T00:00:00Z"), java.time.ZoneOffset.UTC);
            assertThrows(IllegalStateException.class, () -> EnrollmentRuntime.open(fixture.configuration(), fixture.realm(), fixture.repository(),
                    store.store(), registry(store.store()), dependencies(), expired, Optional.empty()));
            EnrollmentRuntimeConfiguration retained = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                    fixture.configuration().keyrings(), fixture.configuration().credentialSets(), List.of(), Optional.empty());
            try (EnrollmentRuntime runtime = EnrollmentRuntime.open(retained, fixture.realm(), fixture.repository(), store.store(), registry(store.store()),
                    dependencies(), expired, Optional.empty())) {
                EnrollmentRuntimeConfiguration.CredentialSet set = retained.credentialSets().getFirst();
                runtime.requireRetainedCredential("scep-a", set.authorityId(), set.issuerId(), set.chainPathId());
                assertThrows(IllegalStateException.class, () -> runtime.requireRetainedCredential("scep-a", "other-authority", set.issuerId(), set.chainPathId()));
                assertThrows(IllegalStateException.class, () -> runtime.requireRetainedCredential("scep-a", set.authorityId(), "other-issuer", set.chainPathId()));
                assertThrows(IllegalStateException.class, () -> runtime.requireRetainedCredential("scep-a", set.authorityId(), set.issuerId(), "other-path"));
                assertThrows(IllegalStateException.class, () -> runtime.acquire("scep-a"));
            }
        }
    }

    @Test
    void endpointRegistrationRequiresProvisionedModesAndArtifactCapability() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory);
                EnrollmentRuntime runtime = open(fixture, store.store(), dependencies())) {
            zeroecho.pki.server.enrollment.EnrollmentProfileService profiles = new zeroecho.pki.server.enrollment.EnrollmentProfileService(store.store());
            profiles.register(new zeroecho.pki.server.enrollment.EnrollmentProfile("profile", "Profile",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "certificate", Set.of(), Optional.empty(), List.of(), false));
            zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry endpoints = new zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry(store.store(), profiles);
            endpoints.installRuntime(runtime);
            assertThrows(IllegalStateException.class, () -> endpoints.register(new zeroecho.pki.server.cmp.CmpEndpoint(
                    "cmp", "authority", "certificate", "profile", zeroecho.pki.server.cmp.CmpProtectionPolicy.SHARED_SECRET_MAC)));
            assertThrows(IllegalStateException.class, () -> endpoints.register(new zeroecho.pki.server.est.EstEndpoint(
                    "est", "authority", "certificate", "profile", new zeroecho.pki.server.est.KeygenPolicy(true, List.of("RSA"), 2048, false))));
            assertTrue(endpoints.list(zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol.CMP).isEmpty());
        }
    }

    @Test
    void concurrentBorrowerRetainsCustodyUntilItReleasesAfterShutdownFence() throws Exception {
        Fixture fixture = fixture();
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory);
                java.util.concurrent.ExecutorService worker = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            EnrollmentRuntime runtime = open(fixture, store.store(), dependencies());
            java.util.concurrent.CountDownLatch acquired = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
            java.util.concurrent.Future<?> borrowing = worker.submit(() -> {
                try (EnrollmentRuntime.CredentialLease lease = runtime.acquire("scep-a")) {
                    acquired.countDown();
                    assertTrue(release.await(5, java.util.concurrent.TimeUnit.SECONDS));
                    assertEquals(raCertificate, lease.responseChain().getFirst());
                }
                return null;
            });
            try {
                assertTrue(acquired.await(5, java.util.concurrent.TimeUnit.SECONDS));
                assertThrows(IllegalStateException.class, runtime::close);
                assertThrows(IllegalStateException.class, () -> runtime.acquire("scep-a"));
            } finally { release.countDown(); }
            borrowing.get(5, java.util.concurrent.TimeUnit.SECONDS);
            runtime.close();
            try (KeyringPassword password = password(); KeyringStore ignored = KeyringStore.open(fixture.keyring(), password)) { }
        }
    }

    @Test
    void failedEndpointCapabilityValidationDoesNotPinCorrectableCredentialIdentity() throws Exception {
        Fixture fixture = fixture();
        EnrollmentRuntimeConfiguration.CredentialSet scep = fixture.configuration().credentialSets().getFirst();
        EnrollmentRuntimeConfiguration.CredentialSet signatureOnly = new EnrollmentRuntimeConfiguration.CredentialSet("cmp-a",
                EnrollmentRuntimeConfiguration.Protocol.CMP, scep.authorityId(), scep.issuerId(), scep.chainPathId(), scep.signer(),
                List.of(directory.resolve("root.der")), List.of(), Optional.empty());
        EnrollmentRuntimeConfiguration.ActiveCredential active = new EnrollmentRuntimeConfiguration.ActiveCredential(
                signatureOnly.protocol(), signatureOnly.authorityId(), signatureOnly.credentialId());
        EnrollmentRuntimeConfiguration wrong = new EnrollmentRuntimeConfiguration(fixture.configuration().budgets(),
                fixture.configuration().keyrings(), List.of(signatureOnly), List.of(active), Optional.empty());
        Path log;
        try (ServerTestSupport.OpenedStore store = ServerTestSupport.open(directory)) {
            log = store.log();
            zeroecho.pki.server.enrollment.EnrollmentProfileService profiles = new zeroecho.pki.server.enrollment.EnrollmentProfileService(store.store());
            profiles.register(new zeroecho.pki.server.enrollment.EnrollmentProfile("profile", "Profile",
                    zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "certificate", Set.of("authority"),
                    Optional.empty(), List.of(), false));
            registry(store.store()).register(new zeroecho.pki.server.cmp.CmpEndpoint("cmp", "authority", "certificate", "profile",
                    zeroecho.pki.server.cmp.CmpProtectionPolicy.SHARED_SECRET_MAC));
            assertThrows(IllegalStateException.class, () -> open(fixture.withConfiguration(wrong), store.store(), dependencies()));
            assertTrue(store.store().protocolRecord(ServerControlStore.ENROLLMENT_CREDENTIAL, "cmp-a").isEmpty());
            try (KeyringPassword password = password(); KeyringStore ignored = KeyringStore.open(fixture.keyring(), password)) { }
        }
        EnrollmentRuntimeConfiguration.Pbm policy = new EnrollmentRuntimeConfiguration.Pbm(1000, 10000, 16, 32,
                Set.of(EnrollmentRuntimeConfiguration.PbmDigest.SHA256), Set.of(EnrollmentRuntimeConfiguration.PbmMac.HMAC_SHA256),
                List.of(new EnrollmentRuntimeConfiguration.PbmIdentity("0123", "device",
                        new EnrollmentRuntimeConfiguration.KeyReference("protocol", "pbm"), List.of("administrator"))));
        EnrollmentRuntimeConfiguration.CredentialSet corrected = new EnrollmentRuntimeConfiguration.CredentialSet("cmp-a",
                signatureOnly.protocol(), signatureOnly.authorityId(), signatureOnly.issuerId(), signatureOnly.chainPathId(),
                signatureOnly.signer(), signatureOnly.requestTrustAnchors(), List.of(), Optional.of(policy));
        EnrollmentRuntimeConfiguration correct = new EnrollmentRuntimeConfiguration(wrong.budgets(), wrong.keyrings(),
                List.of(corrected), wrong.activeCredentials(), Optional.empty());
        try (ServerControlStore store = new ServerControlStore(DurableTransactionalMetadataStore.open(log, OptionalLong.of(1_048_576)));
                EnrollmentRuntime runtime = open(fixture.withConfiguration(correct), store, dependencies())) {
            assertEquals("cmp-a", runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.CMP, "authority"));
            assertTrue(store.protocolRecord(ServerControlStore.ENROLLMENT_CREDENTIAL, "cmp-a").isPresent());
            try (EnrollmentRuntime.CredentialLease lease = runtime.acquire("cmp-a")) {
                assertEquals(32, lease.pbmSecret("0123").getEncoded().length);
            }
        }
    }

    private Fixture fixture() throws Exception {
        PkiServerConfiguration server = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        Files.createDirectories(Path.of(server.realm().pkiSessionConfiguration().store().require("root")));
        Files.createFile(server.realm().controlLogPath());
        Path root = Files.write(directory.resolve("root.der"), rootCertificate.getEncoded());
        Path ra = Files.write(directory.resolve("ra.der"), raCertificate.getEncoded());
        Path keyring = directory.resolve("protocol.zek");
        try (KeyringPassword password = password(); KeyringStore ring = KeyringStore.create(keyring, password)) {
            ring.putPrivate("ra", "RSA", raKey.getPrivate());
            byte[] bytes = new byte[32]; java.util.Arrays.fill(bytes, (byte) 4);
            ring.putSecret("pbm", "HMAC", new SecretKeySpec(bytes, "HmacSHA256"));
        }
        PkiId authorityId = new PkiId("authority");
        PkiId certificateId = new PkiId("ca-certificate");
        PkiId issuerId = IssuerGeneration.idFor(authorityId, certificateId);
        IssuerGeneration issuer = new IssuerGeneration(issuerId, authorityId, certificateId, new KeyRef("ca.prv"),
                IssuerGenerationState.ACTIVE, ServerTestSupport.DIGEST, ServerTestSupport.DIGEST);
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(certificateId));
        CaRecord authority = new CaRecord(authorityId, CaKind.ROOT, CaState.ACTIVE, new KeyRef("ca.prv"),
                new SubjectRef("subject"), List.of(issuerId), issuerId, path.pathId());
        PkiRepository repository = mock(PkiRepository.class);
        when(repository.authority(authorityId)).thenReturn(Optional.of(authority));
        when(repository.issuer(issuerId)).thenReturn(Optional.of(issuer));
        when(repository.chainPath(path.pathId())).thenReturn(Optional.of(path));
        PkiRepositoryContent content = mock(PkiRepositoryContent.class);
        when(content.openStream()).thenAnswer(ignored -> new ByteArrayInputStream(rootCertificate.getEncoded()));
        when(repository.openCredential(certificateId)).thenReturn(content);
        EnrollmentRuntimeConfiguration.CredentialSet set = new EnrollmentRuntimeConfiguration.CredentialSet("scep-a",
                EnrollmentRuntimeConfiguration.Protocol.SCEP, authorityId.value(), issuerId.value(), path.pathId().value(),
                Optional.of(new EnrollmentRuntimeConfiguration.Signer(new EnrollmentRuntimeConfiguration.KeyReference("protocol", "ra"),
                        List.of(ra, root))), List.of(), List.of(), Optional.empty());
        EnrollmentRuntimeConfiguration config = new EnrollmentRuntimeConfiguration(EnrollmentTestSupport.runtimeConfiguration().budgets(),
                List.of(new EnrollmentRuntimeConfiguration.Keyring("protocol", keyring)), List.of(set),
                List.of(new EnrollmentRuntimeConfiguration.ActiveCredential(set.protocol(), set.authorityId(), set.credentialId())), Optional.empty());
        return new Fixture(server.realm(), repository, config, keyring, ra);
    }

    private static KeyringPassword password() { return new KeyringPassword("test-enrollment-password".toCharArray()); }
    private static PkiSessionRuntimeDependencies dependencies() {
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(EnrollmentRuntimeTest::password);
    }
    private static EnrollmentRuntime open(Fixture fixture, ServerControlStore control, PkiSessionRuntimeDependencies dependencies) {
        return EnrollmentRuntime.open(fixture.configuration(), fixture.realm(), fixture.repository(), control, registry(control),
                dependencies, ServerTestSupport.CLOCK, Optional.empty());
    }
    private static zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry registry(ServerControlStore control) {
        return new zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry(control,
                new zeroecho.pki.server.enrollment.EnrollmentProfileService(control));
    }
    private record Fixture(ServerRealmConfiguration realm, PkiRepository repository,
            EnrollmentRuntimeConfiguration configuration, Path keyring, Path ra) {
        Fixture withConfiguration(EnrollmentRuntimeConfiguration value) { return new Fixture(realm, repository, value, keyring, ra); }
    }
}
