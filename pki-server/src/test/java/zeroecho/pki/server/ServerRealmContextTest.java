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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import org.mockito.Answers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.application.CredentialConfirmationProofRuntimePolicy;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.confirmation.SignatureKeyPossessionProofProvider;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;

/** Realm composition, one-session lifecycle and exposure-policy tests. */
class ServerRealmContextTest {
    @TempDir Path temporaryDirectory;

    @Test
    void incompatibleEnrollmentPolicyUpdateCannotPreventRealmRestart() throws Exception {
        ServerRealmConfiguration config = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        zeroecho.pki.server.enrollment.EnrollmentProfile original = new zeroecho.pki.server.enrollment.EnrollmentProfile(
                "policy", "Policy", zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE,
                "certificate", Set.of("authority"), Optional.empty(), List.of(), false);
        zeroecho.pki.server.est.EstEndpoint endpoint = new zeroecho.pki.server.est.EstEndpoint(
                "endpoint", "authority", "certificate", "policy", zeroecho.pki.server.est.KeygenPolicy.DISABLED);
        try (ServerRealmContext context = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            context.enrollmentProfiles().register(original);
            context.enrollmentEndpoints().register(endpoint);
            assertThrows(IllegalStateException.class, () -> context.enrollmentProfiles().update(
                    new zeroecho.pki.server.enrollment.EnrollmentProfile("policy", "Policy",
                            zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE, "other-certificate",
                            Set.of("authority"), Optional.empty(), List.of(), false)));
            context.enrollmentProfiles().setState("policy", zeroecho.pki.server.enrollment.EnrollmentProfileState.SUSPENDED);
        }
        try (ServerRealmContext reopened = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertEquals(original.withState(zeroecho.pki.server.enrollment.EnrollmentProfileState.SUSPENDED),
                    reopened.enrollmentProfiles().find("policy").orElseThrow());
            reopened.enrollmentProfiles().setState("policy", zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE);
            assertEquals(endpoint, reopened.enrollmentEndpoints().requireCurrent(endpoint).endpoint());
        }
    }

    @Test
    void enrollmentRegistryIsInstalledAndRejectsCorruptPolicyBeforeRealmReadiness() throws Exception {
        ServerRealmConfiguration config = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        try (ServerRealmContext context = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertTrue(context.gateway().operationAvailable(ServerControlOperation.ListEnrollmentProfiles.NAME));
        }
        try (ServerControlStore control = new ServerControlStore(
                zeroecho.pki.impl.fs.DurableTransactionalMetadataStore.open(config.controlLogPath(),
                        java.util.OptionalLong.of(1_048_576)))) {
            control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(
                    new ServerControlStore.ProtocolRecord(ServerControlStore.ENROLLMENT_PROFILE,
                            "invalid-profile", "0".repeat(64), new byte[] { 1 }), Optional.empty())));
        }
        assertThrows(IllegalStateException.class, () -> ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom()));
        // A failed realm startup releases the control owner; a subsequent exact open is possible.
        try (ServerControlStore control = new ServerControlStore(
                zeroecho.pki.impl.fs.DurableTransactionalMetadataStore.open(config.controlLogPath(),
                        java.util.OptionalLong.of(1_048_576)))) {
            assertTrue(control.protocolRecord(ServerControlStore.ENROLLMENT_PROFILE, "invalid-profile").isPresent());
        }
    }

    @Test
    void dashboardCountsRealPendingApprovalsAndRecordsSafeScheduleFailures() throws Exception {
        ServerRealmConfiguration config = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        try (ServerRealmContext context = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertEquals(0, context.pendingApprovalCount(ServerTestSupport.CLOCK.instant()));
            context.createPrincipal(ServerTestSupport.principal("requester"), "system");
            Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty());
            ApprovalService.Policy policy = new ApprovalService.Policy("metrics", 1, Set.of("approver"),
                    Set.of(), true, Duration.ofHours(1), true);
            context.approvals().request("pending-metric", "ca.intermediate.create", ServerTestSupport.DIGEST,
                    scope, "requester", policy);
            assertEquals(1, context.pendingApprovalCount(ServerTestSupport.CLOCK.instant()));
            assertEquals(0, context.pendingApprovalCount(ServerTestSupport.CLOCK.instant().plusSeconds(3600)));
            assertEquals(0, context.adminRequestsTotal());
            context.recordAdminRequest();
            assertEquals(1, context.adminRequestsTotal());
            assertEquals(0, context.scheduleFailureTotal());
            context.recordScheduleFailure("STATUS_SCHEDULE_FAILED");
            assertEquals(1, context.scheduleFailureTotal());
            assertEquals(0, context.auditProjectionFailureTotal());
        }
        try (ServerRealmContext context = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertEquals(1, context.pendingApprovalCount(ServerTestSupport.CLOCK.instant()));
            assertEquals(0, context.adminRequestsTotal(), "Process-local request count restarts at zero");
        }
    }

    @Test
    void concurrentCloseSharesOneSuccessfulAttemptAndClosesExactlyOnce() throws Exception {
        PkiSession session = mock(PkiSession.class);
        ServerControlStore control = mock(ServerControlStore.class);
        ServerRealmContext context = closeContext(session, control);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            release.await();
            return null;
        }).when(session).close();

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, context, null);
            assertTrue(entered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, context, joiningThread);
            awaitWaiting(joiningThread);
            release.countDown();
            owner.get(2, TimeUnit.SECONDS);
            joiner.get(2, TimeUnit.SECONDS);
        }
        context.close();
        assertEquals(ServerRealmContext.State.CLOSED, context.state());
        verify(session, times(1)).close();
        verify(control, times(1)).close();
    }

    @Test
    void concurrentFailureIsSharedAndOneLaterRetryClosesRemainingResources() throws Exception {
        PkiSession session = mock(PkiSession.class);
        ServerControlStore control = mock(ServerControlStore.class);
        ServerRealmContext context = closeContext(session, control);
        CountDownLatch firstEntered = new CountDownLatch(1);
        CountDownLatch firstRelease = new CountDownLatch(1);
        CountDownLatch retryEntered = new CountDownLatch(1);
        CountDownLatch retryRelease = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        IllegalStateException exact = new IllegalStateException("SESSION_DRAIN_TIMEOUT");
        doAnswer(invocation -> {
            if (calls.incrementAndGet() == 1) {
                firstEntered.countDown();
                firstRelease.await();
                throw exact;
            }
            retryEntered.countDown();
            retryRelease.await();
            return null;
        }).when(session).close();

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, context, null);
            assertTrue(firstEntered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, context, joiningThread);
            awaitWaiting(joiningThread);
            firstRelease.countDown();
            assertSame(exact, cause(owner));
            assertSame(exact, cause(joiner));
        }
        assertEquals(ServerRealmContext.State.CLOSING, context.state());
        verify(control, never()).close();

        try (ExecutorService callers = Executors.newFixedThreadPool(2)) {
            Future<?> owner = submitClose(callers, context, null);
            assertTrue(retryEntered.await(2, TimeUnit.SECONDS));
            AtomicReference<Thread> joiningThread = new AtomicReference<>();
            Future<?> joiner = submitClose(callers, context, joiningThread);
            awaitWaiting(joiningThread);
            retryRelease.countDown();
            owner.get(2, TimeUnit.SECONDS);
            joiner.get(2, TimeUnit.SECONDS);
        }
        assertEquals(ServerRealmContext.State.CLOSED, context.state());
        verify(session, times(2)).close();
        verify(control, times(1)).close();
    }

    @Test
    void serverWorkerOnlyQuiescesAndRequestsExternalRetry() throws Exception {
        PkiSession session = mock(PkiSession.class);
        ServerControlStore control = mock(ServerControlStore.class);
        ServerRealmContext context = closeContext(session, control);

        IllegalStateException retry = assertThrows(IllegalStateException.class,
                () -> context.closeFromServerWorker(true));
        assertTrue(retry.getMessage().contains("SERVER_CLOSE_RETRY_REQUIRED"));
        assertEquals(ServerRealmContext.State.CLOSING, context.state());
        verify(session, never()).close();
        verify(control, never()).close();

        context.close();
        assertEquals(ServerRealmContext.State.CLOSED, context.state());
        verify(session, times(1)).close();
        verify(control, times(1)).close();
    }

    @Test
    void opensOneLongLivedSessionClosesAndRecoversControlState() throws Exception {
        System.out.println("opensOneLongLivedSessionClosesAndRecoversControlState");
        ServerRealmConfiguration configuration = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        try (ServerRealmContext context = ServerRealmContext.open(configuration,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertSame(context.session(), context.session());
            assertSame(context.session().confirmations(), context.session().confirmations());
            PkiOperationOutcome first = context.session().operations().execute(new PkiOperation.ValidateConfiguration(),
                    zeroecho.core.io.CancellationSignal.NONE);
            PkiOperationOutcome second = context.session().operations().execute(new PkiOperation.ValidateConfiguration(),
                    zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(PkiOperationOutcome.Completed.class, first.getClass());
            assertEquals(PkiOperationOutcome.Completed.class, second.getClass());
            context.createPrincipal(ServerTestSupport.principal("auditor"), "bootstrap");
            assertEquals(ServerRealmContext.State.OPEN, context.state());
            System.out.println("...session-reused=true");
        }
        try (ServerRealmContext reopened = ServerRealmContext.open(configuration,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            assertThrows(IllegalStateException.class,
                    () -> reopened.createPrincipal(ServerTestSupport.principal("auditor"), "bootstrap"));
            assertEquals(ServerRealmContext.State.OPEN, reopened.state());
            System.out.println("...control-recovered=true");
        }
        System.out.println("...ok");
    }

    @Test
    void composesExactNondefaultProofRuntimeWithoutMutableRegistration() {
        ServerRealmConfiguration configured = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        CredentialConfirmationProofPolicy proof = new CredentialConfirmationProofPolicy(
                configured.confirmationProofPolicy().audience(), Duration.ofSeconds(45L), 4_096);
        ServerRealmConfiguration nondefault = new ServerRealmConfiguration(configured.realmId(),
                configured.displayName(), proof, configured.pkiSessionConfiguration(),
                configured.authorityExposure(), configured.authorizationCommitment(),
                configured.approvalCommitment(), configured.extendedApprovalCommitment(),
                configured.disclosureCommitment(),
                configured.disclosureDefaults(), configured.controlLogPath(), configured.controlStoreId(),
                configured.approvalPolicies());

        PkiSessionRuntimeDependencies runtime = ServerRealmContext.confirmationProofRuntime(
                nondefault, PkiSessionRuntimeDependencies.none());
        CredentialConfirmationProofRuntimePolicy policy = runtime
                .credentialConfirmationProofPolicy().orElseThrow();
        assertEquals(new ConfirmationRealmBinding(nondefault.realmId().value()), policy.realm());
        assertEquals(proof.audience(), policy.audience());
        assertEquals(proof.challengeTimeToLive(), policy.challengeTimeToLive());
        assertEquals(4_096, policy.proofSuiteBinding().rsaMaximumModulusBits());
        SignatureKeyPossessionProofProvider provider = assertInstanceOf(
                SignatureKeyPossessionProofProvider.class,
                runtime.keyPossessionProofProviders().getFirst());
        KeyPossessionProofDescriptor descriptor = provider.descriptor(4_096);
        assertEquals(descriptor.proofSuiteBinding(), policy.proofSuiteBinding());
        assertThrows(UnsupportedOperationException.class,
                () -> runtime.keyPossessionProofProviders().clear());
    }

    @Test
    void supportsExplicitOneAuthorityAndRejectsOtherAuthority() {
        System.out.println("supportsExplicitOneAuthorityAndRejectsOtherAuthority");
        AuthorityExposurePolicy exposure = new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES, Set.of(ServerTestSupport.AUTHORITY), false);
        assertEquals(true, exposure.allows(ServerTestSupport.AUTHORITY));
        assertEquals(false, exposure.allows(new PkiId("ca-b")));
        assertThrows(IllegalArgumentException.class, () -> new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES, Set.of(), false));
        System.out.println("...visible-authorities=" + exposure.authorityIds().size());
        System.out.println("...ok");
    }

    @Test
    void rejectsChangedRealmCommitmentOnReopen() throws Exception {
        System.out.println("rejectsChangedRealmCommitmentOnReopen");
        ServerRealmConfiguration original = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        {
            ServerRealmContext ignored = ServerRealmContext.open(original, PkiSessionRuntimeDependencies.none(),
                ServerTestSupport.CLOCK, deterministicRandom());
            try (ignored) {
                System.out.println("...initial-open=true");
            }
        }
        String changed = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        ServerRealmConfiguration incompatible = new ServerRealmConfiguration(original.realmId(),
                original.displayName(), original.confirmationProofPolicy(), original.pkiSessionConfiguration(),
                original.authorityExposure(), changed,
                original.approvalCommitment(), original.extendedApprovalCommitment(),
                original.disclosureCommitment(), original.disclosureDefaults(),
                original.controlLogPath(), original.controlStoreId(), original.approvalPolicies());
        assertThrows(IllegalStateException.class, () -> ServerRealmContext.open(incompatible,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom()));
        System.out.println("...changed-commitment=rejected");
        System.out.println("...ok");
    }

    @Test
    void auditAnchorDetectsAuditLogRewriteAcrossReopen() throws Exception {
        System.out.println("auditAnchorDetectsAuditLogRewriteAcrossReopen");
        Path auditDir = temporaryDirectory.resolve("audit");
        ServerRealmConfiguration config = fileAuditConfiguration(auditDir);
        try (ServerRealmContext context = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom())) {
            context.createPrincipal(ServerTestSupport.principal("auditor"), "bootstrap");
        }
        // Clean reopen verifies the durable anchor against the intact log and succeeds.
        {
            ServerRealmContext reopened = ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom());
            try (reopened) {
                assertEquals(ServerTestSupport.REALM, config.realmId());
            }
        }
        // Simulate a full audit-log rewrite by removing the log; the separately stored anchor no longer matches.
        deleteRecursively(auditDir);
        assertThrows(IllegalStateException.class, () -> ServerRealmContext.open(config,
                PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom()));
        System.out.println("...ok");
    }

    private ServerRealmConfiguration fileAuditConfiguration(Path auditDir) {
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                Set.of(), true, Duration.ofHours(1), true);
        PkiSessionConfiguration pki = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("pki-store-audit").toString())),
                new ProviderConfig("file", Map.of("root", auditDir.toString())), Optional.empty(),
                List.of(), List.of());
        return new ServerRealmConfiguration(ServerTestSupport.REALM, "Production",
                ServerTestSupport.CONFIRMATION_PROOF_POLICY, pki,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                ServerTestSupport.DIGEST, approval.commitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(
                        Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval)),
                ServerTestSupport.DIGEST, DisclosureService.Defaults.recommended(),
                temporaryDirectory.resolve("control-audit.log"), ServerTestSupport.STORE_ID,
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval));
    }

    private static void deleteRecursively(Path dir) throws java.io.IOException {
        if (!java.nio.file.Files.exists(dir)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = java.nio.file.Files.walk(dir)) {
            walk.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    java.nio.file.Files.deleteIfExists(path);
                } catch (java.io.IOException failure) {
                    throw new java.io.UncheckedIOException(failure);
                }
            });
        }
    }

    private ServerRealmConfiguration configuration(AuthorityExposurePolicy exposure) {
        ApprovalService.Policy approval = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                Set.of(), true, Duration.ofHours(1), true);
        PkiSessionConfiguration pki = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("pki-store").toString())),
                new ProviderConfig("memory", Map.of("size", "128")), Optional.empty(), List.of(), List.of());
        return new ServerRealmConfiguration(ServerTestSupport.REALM, "Production",
                ServerTestSupport.CONFIRMATION_PROOF_POLICY, pki, exposure,
                ServerTestSupport.DIGEST, approval.commitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(
                        Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval)),
                ServerTestSupport.DIGEST,
                DisclosureService.Defaults.recommended(), temporaryDirectory.resolve("control.log"),
                ServerTestSupport.STORE_ID,
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approval));
    }

    @Test
    void pendingRestoreRejectsNestedControlBeforeOpeningOrMutatingAnyStore() throws Exception {
        ServerRealmConfiguration original = configuration(new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true));
        Path root = temporaryDirectory.resolve("pki-store");
        Files.createDirectories(root);
        Path nested = root.resolve("server-control.log");
        Files.writeString(nested, "preserved control authority");
        Path coordinator = temporaryDirectory.resolve(".pki-store.restore-control");
        Files.createDirectories(coordinator);
        Files.writeString(coordinator.resolve("journal"), "pending journal sentinel");
        ServerRealmConfiguration configured = new ServerRealmConfiguration(original.realmId(),
                original.displayName(), original.confirmationProofPolicy(), original.pkiSessionConfiguration(),
                original.authorityExposure(), original.authorizationCommitment(), original.approvalCommitment(),
                original.extendedApprovalCommitment(), original.disclosureCommitment(), original.disclosureDefaults(),
                nested, original.controlStoreId(), original.approvalPolicies());
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, () ->
                ServerRealmContext.open(configured, PkiSessionRuntimeDependencies.none(), ServerTestSupport.CLOCK, deterministicRandom()));
        assertEquals("RESTORE_COLOCATED_SERVER_AUTHORITY", failure.getMessage());
        assertEquals("preserved control authority", Files.readString(nested));
        assertEquals("pending journal sentinel", Files.readString(coordinator.resolve("journal")));
        assertTrue(Files.notExists(root.resolve("VERSION")));
    }

    private static ServerRealmContext closeContext(PkiSession session, ServerControlStore control)
            throws Exception {
        ServerRealmContext context = mock(ServerRealmContext.class, Answers.CALLS_REAL_METHODS);
        ServerRealmConfiguration configuration = mock(ServerRealmConfiguration.class);
        when(configuration.realmId()).thenReturn(ServerTestSupport.REALM);
        setField(context, "configuration", configuration);
        setField(context, "session", session);
        setField(context, "control", control);
        setField(context, "audit", mock(SafeAudit.class));
        setField(context, "state", new AtomicReference<>(ServerRealmContext.State.OPEN));
        setField(context, "closeGate", new RetryableCloseGate());
        setField(context, "closeAuditAttempted", new AtomicBoolean());
        setField(context, "sessionClosed", new AtomicBoolean());
        setField(context, "controlClosed", new AtomicBoolean());
        setField(context, "auditIntegrity", new AtomicReference<>());
        setField(context, "auditAnchorCommitment", new AtomicReference<>());
        return context;
    }

    private static void setField(ServerRealmContext context, String name, Object value) throws Exception {
        Field field = ServerRealmContext.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(context, value);
    }

    private static Future<?> submitClose(ExecutorService callers, ServerRealmContext context,
            AtomicReference<Thread> thread) {
        return callers.submit(() -> {
            if (thread != null) thread.set(Thread.currentThread());
            context.close();
            return null;
        });
    }

    private static void awaitWaiting(AtomicReference<Thread> selected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L);
        while (selected.get() == null && System.nanoTime() < deadline) Thread.onSpinWait();
        Thread thread = selected.get();
        assertTrue(thread != null);
        while (thread.getState() != Thread.State.WAITING && System.nanoTime() < deadline) {
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1L));
        }
        assertEquals(Thread.State.WAITING, thread.getState());
    }

    private static Throwable cause(Future<?> future) {
        return assertThrows(ExecutionException.class, () -> future.get(2, TimeUnit.SECONDS)).getCause();
    }

    private static SecureRandom deterministicRandom() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 });
        return random;
    }
}
