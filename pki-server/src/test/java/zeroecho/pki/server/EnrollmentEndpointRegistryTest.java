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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.delegatesTo;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtectionPolicy;
import zeroecho.pki.server.enrollment.EnrollmentEndpoint;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol;
import zeroecho.pki.server.enrollment.EnrollmentProfile;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentProfileState;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.est.KeygenPolicy;
import zeroecho.pki.server.scep.ScepEndpoint;

/** Durable endpoint identity, revision, policy-admission, and recovery contracts. */
class EnrollmentEndpointRegistryTest {
    @TempDir Path directory;

    @Test
    void persistsAllProtocolBindingsAndTombstonesAcrossRestart() throws Exception {
        Path log;
        List<EnrollmentEndpoint> endpoints = endpoints();
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            log = opened.log();
            EnrollmentProfileService profiles = profiles(opened.store());
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(opened.store(), profiles);
            for (EnrollmentEndpoint endpoint : endpoints) registry.register(endpoint);
            EnrollmentEndpointRegistry.Snapshot original = registry.requireCurrent(endpoints.getFirst());
            ServerControlStore.ProtocolRecord stale = opened.store().protocolRecord(
                    ServerControlStore.ENROLLMENT_ENDPOINT, "EST:endpoint").orElseThrow();
            assertEquals(endpoints.getFirst(), registry.deregister(Protocol.EST, "endpoint").orElseThrow());
            assertTrue(registry.deregister(Protocol.EST, "endpoint").isEmpty());
            assertTrue(registry.find(Protocol.EST, "endpoint").isEmpty());
            assertThrows(IllegalStateException.class, () -> registry.requireCurrent(endpoints.getFirst()));
            EnrollmentEndpointRegistry.Snapshot reinstated = registry.register(endpoints.getFirst());
            assertEquals(original.revision() + 2, reinstated.revision());
            assertNotEquals(original.commitment(), reinstated.commitment());
            assertThrows(IllegalStateException.class, () -> opened.store().mutateProtocol(List.of(
                    new ServerControlStore.ProtocolMutation(stale, Optional.of(original.commitment())))));
            registry.deregister(Protocol.CMP, "endpoint");
        }
        java.nio.file.Files.write(log, new byte[] { 1, 2, 3 }, java.nio.file.StandardOpenOption.APPEND);
        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(
                log, OptionalLong.of(1_048_576)))) {
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(reopened, new EnrollmentProfileService(reopened));
            assertEquals(endpoints.get(0), registry.find(Protocol.EST, "endpoint").orElseThrow());
            assertEquals(endpoints.get(1), registry.find(Protocol.SCEP, "endpoint").orElseThrow());
            assertTrue(registry.find(Protocol.CMP, "endpoint").isEmpty());
            assertEquals(List.of(endpoints.get(0)), registry.list(Protocol.EST));
            assertTrue(registry.list(Protocol.CMP).isEmpty());
        }
    }

    @Test
    void uncertainAcknowledgementNeverReturnsSuccessAndReopensTheCommittedRecord() throws Exception {
        Path log = directory.resolve("uncertain.log");
        DurableTransactionalMetadataStore durable = DurableTransactionalMetadataStore.create(log, ServerTestSupport.STORE_ID);
        AtomicBoolean uncertain = new AtomicBoolean();
        TransactionalMetadataStore delegated = mock(TransactionalMetadataStore.class, delegatesTo(durable));
        doAnswer(invocation -> {
            MetadataTransaction transaction = durable.beginTransaction();
            MetadataTransaction wrapped = mock(MetadataTransaction.class, delegatesTo(transaction));
            doAnswer(commit -> {
                MetadataCommitResult result = transaction.commit();
                if (uncertain.get()) {
                    return new MetadataCommitResult(result.transactionId(), MetadataCommitResult.Outcome.UNKNOWN,
                            OptionalLong.empty(), Optional.of(MetadataCommitResult.FailureCategory.STORAGE_FAILURE));
                }
                return result;
            }).when(wrapped).commit();
            return wrapped;
        }).when(delegated).beginTransaction();
        try (ServerControlStore control = new ServerControlStore(delegated)) {
            EnrollmentProfileService profiles = profiles(control);
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(control, profiles);
            uncertain.set(true);
            assertThrows(IllegalStateException.class, () -> registry.register(endpoints().getFirst()));
        }
        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(log))) {
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(reopened, new EnrollmentProfileService(reopened));
            assertEquals(endpoints().getFirst(), registry.find(Protocol.EST, "endpoint").orElseThrow());
            assertEquals(1, registry.requireCurrent(endpoints().getFirst()).revision());
        }
    }

    @Test
    void enforcesMandatoryCurrentPolicyOnRegistrationAndAdmission() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            EnrollmentProfileService profiles = new EnrollmentProfileService(opened.store());
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(opened.store(), profiles);
            EnrollmentEndpoint endpoint = endpoints().getFirst();
            assertThrows(IllegalStateException.class, () -> registry.register(endpoint));
            profiles.register(policy(EnrollmentProfileState.SUSPENDED, "certificate", Set.of("authority")));
            assertThrows(IllegalStateException.class, () -> registry.register(endpoint));
            profiles.setState("policy", EnrollmentProfileState.ACTIVE);
            registry.register(endpoint);
            profiles.setState("policy", EnrollmentProfileState.SUSPENDED);
            assertThrows(IllegalStateException.class, () -> registry.requireCurrent(endpoint));
            // Suspended policy remains administratively recoverable after restart.
            EnrollmentEndpointRegistry recovered = new EnrollmentEndpointRegistry(opened.store(), profiles);
            assertTrue(recovered.find(Protocol.EST, "endpoint").isPresent());
            assertThrows(IllegalStateException.class, () -> profiles.update(
                    policy(EnrollmentProfileState.ACTIVE, "other-certificate", Set.of("authority"))));
            assertThrows(IllegalStateException.class, () -> profiles.update(
                    policy(EnrollmentProfileState.ACTIVE, "certificate", Set.of("other-authority"))));
            assertThrows(IllegalStateException.class, () -> registry.requireCurrent(endpoint));
            new EnrollmentEndpointRegistry(opened.store(), profiles);
            profiles.update(policy(EnrollmentProfileState.ACTIVE, "certificate", Set.of("authority")));
            registry.requireCurrent(endpoint);
            EstEndpoint replacement = new EstEndpoint("endpoint", "authority", "certificate", "policy",
                    new KeygenPolicy(true, List.of("RSA"), 2048, false));
            registry.register(replacement);
            assertThrows(IllegalStateException.class, () -> registry.requireCurrent(endpoint));
            assertEquals(replacement, registry.requireCurrent(replacement).endpoint());
        }
    }

    @Test
    void validatesEveryEndpointFieldInApprovalCommitment() {
        ScepEndpoint original = new ScepEndpoint("endpoint", "authority", "certificate", "policy", "a".repeat(64));
        ScepEndpoint changedSecret = new ScepEndpoint("endpoint", "authority", "certificate", "policy", "b".repeat(64));
        ScepEndpoint changedPolicy = new ScepEndpoint("endpoint", "authority", "certificate", "other-policy", "a".repeat(64));
        assertNotEquals(EnrollmentEndpointRegistry.commitment(original), EnrollmentEndpointRegistry.commitment(changedSecret));
        assertNotEquals(EnrollmentEndpointRegistry.commitment(original), EnrollmentEndpointRegistry.commitment(changedPolicy));
        assertNotEquals(EnrollmentEndpointRegistry.commitment(endpoints().getFirst()),
                EnrollmentEndpointRegistry.commitment(new EstEndpoint("endpoint", "authority", "certificate", "policy",
                        new KeygenPolicy(true, List.of("RSA"), 2048, false))));
    }

    @Test
    void incompatibleProfileUpdateAndEndpointRegistrationCannotBothCommit() throws Exception {
        Path log;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory);
                java.util.concurrent.ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            log = opened.log();
            EnrollmentProfileService profiles = profiles(opened.store());
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(opened.store(), profiles);
            CountDownLatch ready = new CountDownLatch(2);
            CountDownLatch start = new CountDownLatch(1);
            Future<Boolean> registration = executor.submit(() -> {
                ready.countDown();
                start.await();
                try { registry.register(endpoints().getFirst()); return true; }
                catch (IllegalStateException conflict) { return false; }
            });
            Future<Boolean> update = executor.submit(() -> {
                ready.countDown();
                start.await();
                try { profiles.update(policy(EnrollmentProfileState.ACTIVE, "other-certificate", Set.of("authority"))); return true; }
                catch (IllegalStateException conflict) { return false; }
            });
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            boolean registered = registration.get(5, TimeUnit.SECONDS);
            boolean updated = update.get(5, TimeUnit.SECONDS);
            assertTrue(registered ^ updated, "Exactly one incompatible change may commit");
        }
        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(log))) {
            new EnrollmentEndpointRegistry(reopened, new EnrollmentProfileService(reopened));
        }
    }

    @Test
    void tombstoningAllowsExplicitPolicyReconfiguration() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            EnrollmentProfileService profiles = profiles(opened.store());
            EnrollmentEndpointRegistry registry = new EnrollmentEndpointRegistry(opened.store(), profiles);
            registry.register(endpoints().getFirst());
            assertThrows(IllegalStateException.class, () -> profiles.update(
                    policy(EnrollmentProfileState.ACTIVE, "other-certificate", Set.of("authority"))));
            registry.deregister(Protocol.EST, "endpoint");
            profiles.update(policy(EnrollmentProfileState.ACTIVE, "other-certificate", Set.of("authority")));
            EstEndpoint replacement = new EstEndpoint("endpoint", "authority", "other-certificate", "policy", KeygenPolicy.DISABLED);
            assertEquals(3, registry.register(replacement).revision());
            assertEquals(replacement, registry.requireCurrent(replacement).endpoint());
        }
    }

    @Test
    void rejectsUnsupportedAndCorruptEndpointPayloadAtStartup() throws Exception {
        for (int variant = 0; variant < 4; variant++) {
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(
                    java.nio.file.Files.createDirectory(directory.resolve("case-" + variant)))) {
                EnrollmentProfileService profiles = profiles(opened.store());
                new EnrollmentEndpointRegistry(opened.store(), profiles).register(endpoints().getFirst());
                ServerControlStore.ProtocolRecord original = opened.store().protocolRecord(
                        ServerControlStore.ENROLLMENT_ENDPOINT, "EST:endpoint").orElseThrow();
                byte[] bytes = original.payload();
                if (variant == 0) ByteBuffer.wrap(bytes).putInt(2);
                if (variant == 1) ByteBuffer.wrap(bytes).putLong(4, 0);
                if (variant == 2) bytes[12] = 2;
                String digest = variant == 3 ? "0".repeat(64)
                        : HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
                opened.store().mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                        new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_ENDPOINT,
                                original.recordId(), digest, bytes), Optional.of(original.commitment()))));
                assertThrows(IllegalStateException.class, () -> new EnrollmentEndpointRegistry(opened.store(), profiles));
            }
        }
    }

    @Test
    void rejectsMissingMandatoryProfileAtPublicDtoBoundary() {
        assertThrows(IllegalArgumentException.class, () -> new EstEndpoint("endpoint", "authority", "certificate", "", KeygenPolicy.DISABLED));
        assertThrows(IllegalArgumentException.class, () -> new ScepEndpoint("endpoint", "authority", "certificate", null, "a".repeat(64)));
        assertThrows(IllegalArgumentException.class, () -> new CmpEndpoint("endpoint", "authority", "certificate", " ",
                CmpProtectionPolicy.SIGNATURE_BASED));
    }

    private static EnrollmentProfileService profiles(ServerControlStore control) {
        EnrollmentProfileService profiles = new EnrollmentProfileService(control);
        profiles.register(policy(EnrollmentProfileState.ACTIVE, "certificate", Set.of("authority")));
        return profiles;
    }

    private static EnrollmentProfile policy(EnrollmentProfileState state, String certificate, Set<String> authorities) {
        return new EnrollmentProfile("policy", "Policy", state, certificate, authorities, Optional.empty(), List.of(), false);
    }

    private static List<EnrollmentEndpoint> endpoints() {
        return List.of(new EstEndpoint("endpoint", "authority", "certificate", "policy", KeygenPolicy.DISABLED),
                new ScepEndpoint("endpoint", "authority", "certificate", "policy", "a".repeat(64)),
                new CmpEndpoint("endpoint", "authority", "certificate", "policy", CmpProtectionPolicy.SIGNATURE_BASED));
    }
}
