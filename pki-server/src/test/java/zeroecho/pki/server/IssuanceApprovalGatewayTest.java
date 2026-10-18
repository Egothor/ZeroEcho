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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationExecutor;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiResourceScopeResolver;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Profile-driven issuance approval enforcement through the packaged administrative
 * gateway: the certificate profile selects the approval rule, the durable
 * {@link ApprovalService} carries the attributable decisions, and the gateway
 * binds each approval to the exact issuance commitment before signing.
 */
class IssuanceApprovalGatewayTest {
    @TempDir Path temporaryDirectory;

    private static final PkiId ISSUER = ServerTestSupport.AUTHORITY;
    private static final PkiId REQUEST_ID = new PkiId("request-1");
    private static final String PROFILE = "server-tls";

    @Test
    void thresholdProfileGatesIssuanceUntilQuorumApprovesThenExecutesExactlyOnce() throws Exception {
        System.out.println("thresholdProfileGatesIssuanceUntilQuorumApprovesThenExecutesExactlyOnce");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());

            ServerOperationGateway.Outcome required = gateway.execute(issueRequest(Optional.empty()),
                    CancellationSignal.NONE);
            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    required).operationCommitment();
            assertEquals(0, executor.calls.get());

            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-1", issueOp().name(), commitment, issueScope(), "officer", thresholdPolicy());
            approvals.decide("approval-1", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-a");
            ApprovalService.Request approved = approvals.decide("approval-1", "approver-b",
                    ApprovalService.Choice.APPROVE, "reviewed-b");
            assertEquals(ApprovalService.State.APPROVED, approved.state());

            ServerOperationGateway.Outcome executed = gateway.execute(issueRequest(Optional.of("approval-1")),
                    CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, executed);
            assertEquals(ApprovalService.State.EXECUTED, approvals.requireCurrent("approval-1").state());
            assertEquals(1, executor.calls.get());

            // Replay: the same approval cannot drive a second issuance.
            assertThrows(IllegalStateException.class, () -> gateway.execute(issueRequest(Optional.of("approval-1")),
                    CancellationSignal.NONE));
            assertEquals(1, executor.calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void issuanceWithoutApprovalIsHeldAndSingleApprovalProfileRequiresOneDecision() throws Exception {
        System.out.println("issuanceWithoutApprovalIsHeldAndSingleApprovalProfileRequiresOneDecision");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, singlePolicies(),
                    profileId -> IssuanceApprovalRequirement.SINGLE, ServerTestSupport.CLOCK, opened.audit());

            ServerOperationGateway.Outcome required = gateway.execute(issueRequest(Optional.empty()),
                    CancellationSignal.NONE);
            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    required).operationCommitment();
            assertEquals(0, executor.calls.get());

            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-single", issueOp().name(), commitment, issueScope(), "officer",
                    singlePolicy());
            assertEquals(ApprovalService.State.APPROVED, approvals.decide("approval-single", "approver-a",
                    ApprovalService.Choice.APPROVE, "reviewed").state());

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(issueRequest(Optional.of("approval-single")), CancellationSignal.NONE));
            assertEquals(1, executor.calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void noneProfileIssuesWithoutApproval() throws Exception {
        System.out.println("noneProfileIssuesWithoutApproval");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.NONE, ServerTestSupport.CLOCK, opened.audit());

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(issueRequest(Optional.empty()), CancellationSignal.NONE));
            assertEquals(1, executor.calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void rejectedApprovalPreventsIssuance() throws Exception {
        System.out.println("rejectedApprovalPreventsIssuance");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());

            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(issueRequest(Optional.empty()), CancellationSignal.NONE)).operationCommitment();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-reject", issueOp().name(), commitment, issueScope(), "officer",
                    thresholdPolicy());
            assertEquals(ApprovalService.State.REJECTED, approvals.decide("approval-reject", "approver-a",
                    ApprovalService.Choice.REJECT, "not authorised").state());

            assertThrows(IllegalStateException.class, () -> gateway.execute(
                    issueRequest(Optional.of("approval-reject")), CancellationSignal.NONE));
            assertEquals(0, executor.calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void expiredApprovalPreventsIssuance() throws Exception {
        System.out.println("expiredApprovalPreventsIssuance");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            CountingExecutor probe = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, probe, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());
            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(issueRequest(Optional.empty()), CancellationSignal.NONE)).operationCommitment();
            ApprovalService.Request request = approvals.request("approval-expire", issueOp().name(), commitment,
                    issueScope(), "officer", thresholdPolicy());
            approvals.decide("approval-expire", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-a");
            approvals.decide("approval-expire", "approver-b", ApprovalService.Choice.APPROVE, "reviewed-b");

            CountingExecutor executor = new CountingExecutor();
            Clock afterExpiry = Clock.fixed(request.expiresAt(), ZoneOffset.UTC);
            ServerOperationGateway expiredGateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, afterExpiry, opened.audit());

            assertThrows(IllegalStateException.class, () -> expiredGateway.execute(
                    issueRequest(Optional.of("approval-expire")), CancellationSignal.NONE));
            assertEquals(ApprovalService.State.EXPIRED,
                    new ApprovalService(opened.store(), afterExpiry, opened.audit())
                            .requireCurrent("approval-expire").state());
            assertEquals(0, executor.calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void approvalSurvivesRestartAndStillGatesIssuance() throws Exception {
        System.out.println("approvalSurvivesRestartAndStillGatesIssuance");
        String commitment;
        Path log;
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            log = opened.log();
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());
            commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(issueRequest(Optional.empty()), CancellationSignal.NONE)).operationCommitment();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-restart", issueOp().name(), commitment, issueScope(), "officer",
                    thresholdPolicy());
            approvals.decide("approval-restart", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-a");
            approvals.decide("approval-restart", "approver-b", ApprovalService.Choice.APPROVE, "reviewed-b");
            opened.store().validateAll();
        }

        try (ServerControlStore reopened = new ServerControlStore(DurableTransactionalMetadataStore.open(log,
                OptionalLong.of(1_048_576)))) {
            reopened.validateAll();
            assertEquals(ApprovalService.State.APPROVED,
                    reopened.requireApproval("approval-restart").state());
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(reopened, new ServerTestSupport.RecordingAudit(), executor,
                    thresholdPolicies(), profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(issueRequest(Optional.of("approval-restart")), CancellationSignal.NONE));
            assertEquals(1, executor.calls.get());
            assertEquals(ApprovalService.State.EXECUTED, reopened.requireApproval("approval-restart").state());
        }
        System.out.println("...ok");
    }

    @Test
    void concurrentIssuanceClaimsExecuteExactlyOnce() throws Exception {
        System.out.println("concurrentIssuanceClaimsExecuteExactlyOnce");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());
            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(issueRequest(Optional.empty()), CancellationSignal.NONE)).operationCommitment();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-race", issueOp().name(), commitment, issueScope(), "officer",
                    thresholdPolicy());
            approvals.decide("approval-race", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-a");
            approvals.decide("approval-race", "approver-b", ApprovalService.Choice.APPROVE, "reviewed-b");

            int racers = 4;
            ExecutorService pool = Executors.newFixedThreadPool(racers);
            CountDownLatch start = new CountDownLatch(1);
            List<Object> outcomes = new CopyOnWriteArrayList<>();
            try {
                for (int i = 0; i < racers; i++) {
                    pool.submit(() -> {
                        try {
                            start.await();
                            outcomes.add(gateway.execute(issueRequest(Optional.of("approval-race")),
                                    CancellationSignal.NONE));
                        } catch (RuntimeException | InterruptedException failure) {
                            outcomes.add(failure);
                        }
                    });
                }
                start.countDown();
                pool.shutdown();
                pool.awaitTermination(30, TimeUnit.SECONDS);
            } finally {
                pool.shutdownNow();
            }

            long executed = outcomes.stream()
                    .filter(ServerOperationGateway.Outcome.Executed.class::isInstance).count();
            assertEquals(1, executed);
            assertEquals(1, executor.calls.get());
            assertEquals(ApprovalService.State.EXECUTED, approvals.requireCurrent("approval-race").state());
        }
        System.out.println("...ok");
    }

    @Test
    void issuanceApprovalIsCreatableThroughTheAdministrativeApi() throws Exception {
        System.out.println("issuanceApprovalIsCreatableThroughTheAdministrativeApi");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            enrolIssuanceOfficerAndApprovers(opened);
            opened.store().createGrant(ServerTestSupport.grant("request-approval", "officer",
                    Permission.Effect.ALLOW, Permission.Action.REQUEST_SUBMIT, Permission.ResourceType.APPROVAL,
                    issueScope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            CountingExecutor executor = new CountingExecutor();
            ServerOperationGateway gateway = gateway(opened, executor, thresholdPolicies(),
                    profileId -> IssuanceApprovalRequirement.THRESHOLD, ServerTestSupport.CLOCK, opened.audit());

            ServerControlOperation.RequestApproval requestApproval = new ServerControlOperation.RequestApproval(
                    "approval-api", new AdministrativeOperation.Signing(issueOp()), issueResource());
            Permission.Resource approvalResource = new Permission.Resource(Permission.ResourceType.APPROVAL,
                    issueScope(), Optional.empty(), Optional.empty());
            ServerOperationGateway.Request create = new ServerOperationGateway.Request(ServerTestSupport.REALM,
                    "officer", new AdministrativeOperation.Control(requestApproval), approvalResource,
                    Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "correlation-create");
            assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class,
                    gateway.execute(create, CancellationSignal.NONE));

            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            assertEquals(ApprovalService.State.PENDING, approvals.requireCurrent("approval-api").state());
            approvals.decide("approval-api", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-a");
            approvals.decide("approval-api", "approver-b", ApprovalService.Choice.APPROVE, "reviewed-b");

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(issueRequest(Optional.of("approval-api")), CancellationSignal.NONE));
            assertEquals(1, executor.calls.get());
        }
        System.out.println("...ok");
    }

    private static void enrolIssuanceOfficerAndApprovers(ServerTestSupport.OpenedStore opened) {
        opened.store().createPrincipal(ServerTestSupport.principal("officer"));
        opened.store().createPrincipal(ServerTestSupport.principal("approver-a"));
        opened.store().createPrincipal(ServerTestSupport.principal("approver-b"));
        opened.store().createGrant(ServerTestSupport.grant("issue", "officer", Permission.Effect.ALLOW,
                Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE, issueScope(),
                Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
    }

    private static PkiSigningOperation.IssueCredential issueOp() {
        return new PkiSigningOperation.IssueCredential(ISSUER, REQUEST_ID, PROFILE);
    }

    private static Permission.Scope issueScope() {
        return new Permission.Scope(ServerTestSupport.REALM, Optional.of(ISSUER), Optional.empty(),
                Optional.of(PROFILE));
    }

    private static Permission.Resource issueResource() {
        return new Permission.Resource(Permission.ResourceType.CERTIFICATE, issueScope(), Optional.empty(),
                Optional.empty());
    }

    private static ServerOperationGateway.Request issueRequest(Optional<String> approvalId) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, "officer",
                new AdministrativeOperation.Signing(issueOp()), issueResource(),
                Permission.Relationship.ANY, Permission.Context.empty(), approvalId, "correlation-issue");
    }

    private static ApprovalService.Policy thresholdPolicy() {
        return new ApprovalService.Policy("issuance-threshold", 2, Set.of("approver-a", "approver-b"), Set.of(),
                true, Duration.ofHours(1), true);
    }

    private static ApprovalService.Policy singlePolicy() {
        return new ApprovalService.Policy("issuance-single", 1, Set.of("approver-a", "approver-b"), Set.of(),
                true, Duration.ofHours(1), true);
    }

    private static Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> thresholdPolicies() {
        return Map.of(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_THRESHOLD, thresholdPolicy());
    }

    private static Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> singlePolicies() {
        return Map.of(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE, singlePolicy());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, CountingExecutor executor,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            Function<String, IssuanceApprovalRequirement> requirements, Clock clock, AuditSink auditSink) {
        return gateway(opened.store(), auditSink, executor, policies, requirements, clock);
    }

    private static ServerOperationGateway gateway(ServerControlStore store, AuditSink auditSink,
            CountingExecutor executor,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            Function<String, IssuanceApprovalRequirement> requirements, Clock clock) {
        AuthorizationEngine authorization = new AuthorizationEngine(clock);
        ApprovalService approvals = new ApprovalService(store, clock, auditSink);
        BreakGlassService breakGlass = new BreakGlassService(store, clock, auditSink);
        DisclosureService disclosure = new DisclosureService(ServerTestSupport.REALM, store,
                DisclosureService.Defaults.recommended(), clock, new SecureRandom(), auditSink);
        AuditorViews auditorViews = new AuditorViews(clock, auditSink);
        CredentialPublicationGate publication = new CredentialPublicationGate(mock(PkiRepository.class),
                mock(ProfileService.class), mock(CredentialConfirmationService.class), disclosure, clock, () -> { });
        return new ServerOperationGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                store, RoleTemplateCatalog.load(IssuanceApprovalGatewayTest.class.getClassLoader()),
                authorization, approvals, breakGlass, disclosure, publication, auditorViews, Optional.empty(),
                new OperationSecurityDescriptors(), executor, (request, evidence, cancellation) -> {
                    executor.calls.incrementAndGet();
                    return new PkiOperationOutcome.Completed(new PkiOperationResult(request.operation().name(),
                            Map.of("safe", new PkiOperationValue.BooleanValue(true))));
                }, new EmptyScopeResolver(), policies, requirements,
                clock, auditSink, () -> { });
    }

    private static final class CountingExecutor implements PkiOperationExecutor {
        private final AtomicInteger calls = new AtomicInteger();

        @Override
        public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
            calls.incrementAndGet();
            return new PkiOperationOutcome.Completed(new PkiOperationResult(operation.name(),
                    Map.of("safe", new PkiOperationValue.BooleanValue(true))));
        }
    }

    private static final class EmptyScopeResolver implements PkiResourceScopeResolver {
        @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) { return Optional.empty(); }
        @Override public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) { return Optional.empty(); }
        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) { return Optional.empty(); }
    }
}
