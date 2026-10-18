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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.PkiTestRuntime;
import zeroecho.pki.testkit.SemanticIssuanceFixture;

final class PkiOperationAdministrationTest {
    @Test
    void indexedSelectionComposesLegacyFiltersAndAuthorizationAcrossBothExecutorPaths(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString(), "credentialSearch", "h2",
                        "credentialSearchCacheKiB", "1024", "credentialSearchQueryTimeoutMillis", "5000",
                        "credentialSearchMaximumCertificateBytes", "1048576")),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
        try (PkiSession session = DefaultPkiSession.open(configuration, IntermediateCreationFixture.CLOCK, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            Credential credential = bootstrap.store.getCredential(fixture.first().credentialId()).orElseThrow();
            PkiSelectionExecutor selection = (PkiSelectionExecutor) session.operations();
            assertTrue(selection.credentialSearchAvailable());
            PkiOperation.SearchCredentials query = new PkiOperation.SearchCredentials(ROOT, 20, Optional.empty(),
                    Optional.of(credential.subjectRef().value().toUpperCase(java.util.Locale.ROOT)),
                    Optional.of(credential.serialOrUniqueId()), Optional.of(credential.credentialId().value()),
                    Optional.of(credential.status().name()), Optional.of("profile"));
            PkiOperationOutcome local = session.operations().execute(query, CancellationSignal.NONE);
            assertInstanceOf(PkiOperationOutcome.Completed.class, local);
            assertEquals(local, selection.executeSelection(query, row -> true, CancellationSignal.NONE));
            assertEquals(new PkiOperationValue.IntegerValue(1),
                    ((PkiOperationOutcome.Completed) local).result().fields().get("count"));
            java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
            PkiOperationOutcome cancelledOutcome = selection.executeSelection(query,
                    row -> { cancelled.set(true); return true; }, cancelled::get);
            assertEquals(PkiOperationFailure.CANCELLED,
                    assertInstanceOf(PkiOperationOutcome.Failed.class, cancelledOutcome).classification());
            PkiOperationResult denied = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    selection.executeSelection(query, row -> false, CancellationSignal.NONE)).result();
            assertEquals(new PkiOperationValue.IntegerValue(0), denied.fields().get("count"));
            PkiOperation.SearchCredentials mismatch = new PkiOperation.SearchCredentials(ROOT, 20, Optional.empty(),
                    Optional.of("does-not-match"), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            PkiOperationResult empty = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    selection.executeSelection(mismatch, row -> true, CancellationSignal.NONE)).result();
            assertEquals(new PkiOperationValue.IntegerValue(0), empty.fields().get("count"));
        }
    }

    @Test
    void dashboardPublicationsAreScopedByAuthoritativeSourceAndExpiredCredentialsAreNotActive(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture authority = fixture(bootstrap.store);
            Credential first = bootstrap.store.getCredential(authority.first().credentialId()).orElseThrow();
            Credential second = new Credential(new PkiId("binary-child"), new FormatId("publication-test-binary"),
                    new IssuerRef(CHILD), new SubjectRef("CN=child"), first.validity(), "binary-child", first.publicKeyId(),
                    first.profileBinding(), CredentialStatus.ISSUED, PkiTestRuntime.fixtureReference(bootstrap.store.stagedContent(),
                    zeroecho.pki.api.Encoding.DER, new byte[]{1, 2, 3}), new SimpleAttributeSet());
            bootstrap.store.putCredential(second);
            for (Credential credential : List.of(first, second)) {
                bootstrap.store.createPublicationRecord(new zeroecho.pki.api.publication.PublicationRecord(
                        new PkiId("publication:" + credential.issuerRef().caId().value()), zeroecho.pki.api.publication.PublicationSourceType.CREDENTIAL,
                        credential.credentialId(), credential.content(), new zeroecho.pki.api.publication.PublicationTarget(
                                zeroecho.pki.api.publication.PublicationTargetType.HTTP, "destination"),
                        zeroecho.pki.api.publication.PublicationStatus.PENDING, 0, Optional.empty(),
                        IntermediateCreationFixture.CLOCK.instant(), IntermediateCreationFixture.CLOCK.instant(), Optional.empty(), Optional.empty()));
            }
            for (PkiId ca : List.of(ROOT, CHILD)) {
                PkiOperationResult result = completed(session.operations(), new PkiOperation.QueryPublicationMetrics(ca));
                assertEquals(new PkiOperationValue.IntegerValue(1), result.fields().get("publicationsPendingTotal"));
                assertEquals(new PkiOperationValue.IntegerValue(0), result.fields().get("publicationsTerminalFailureTotal"));
                PkiOperationResult certificates = completed(session.operations(), new PkiOperation.QueryCertificateMetrics(ca));
                assertFalse(certificates.fields().containsKey("pendingRequestsTotal"));
                assertTrue(certificates.fields().get("metricStates").toString().contains("CA_REQUEST_LIFECYCLE_UNAVAILABLE"));
            }
        }
        try (PkiSession session = open(temporary, bootstrap, java.time.Clock.fixed(SemanticIssuanceFixture.AFTER,
                java.time.ZoneOffset.UTC))) {
            PkiOperationResult expired = completed(session.operations(), new PkiOperation.QueryCertificateMetrics(ROOT));
            assertEquals(new PkiOperationValue.IntegerValue(0), expired.fields().get("activeTotal"));
            assertEquals(new PkiOperationValue.IntegerValue(3), expired.fields().get("expiredTotal"));
        }
    }

    private static final PkiId ROOT = new PkiId("admin-root");
    private static final PkiId CHILD = new PkiId("admin-child");
    private static final PkiId MISSING = new PkiId("missing-admin-object");

    @Test
    void transitionsEveryStatePreservingRecordAndReadsThePostWriteState(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            CaRecord expected = fixture.root();
            for (CaState state : CaState.values()) {
                bootstrap.calls.clear();
                CaState previous = expected.state();
                expected = withState(expected, state);
                PkiOperation operation = new PkiOperation.TransitionAuthority(ROOT, state, "operator decision");
                assertEquals(new PkiOperationResult("ca.transition", authorityFields(expected)),
                        completed(session.operations(), operation));
                assertEquals(previous == state ? List.of("getCa", "getCa")
                        : List.of("getCa", "replaceCa", "getCa"), bootstrap.calls);
                assertEquals(expected, bootstrap.store.getCa(ROOT).orElseThrow());
                bootstrap.calls.clear();
                completed(session.operations(), operation);
                assertEquals(List.of("getCa", "getCa"), bootstrap.calls, "Same-state transition must not write");
            }
            bootstrap.afterReplace = CaState.COMPROMISED;
            assertEquals(text("COMPROMISED"), completed(session.operations(),
                    new PkiOperation.TransitionAuthority(ROOT, CaState.ACTIVE, "restore")).fields().get("state"));
            assertEquals(withState(expected, CaState.COMPROMISED), bootstrap.store.getCa(ROOT).orElseThrow());
        }
    }

    @Test
    void selectionOnDisabledAuthorityChangesKeyAndSelectionOnlyAndKeepsSameSelectionWrite(@TempDir Path temporary)
            throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            CaRecord disabled = withState(fixture.root(), CaState.DISABLED);
            bootstrap.store.putCa(disabled);
            PkiOperation operation = new PkiOperation.SelectIssuancePath(ROOT, fixture.second().issuerId(),
                    fixture.secondPath().pathId(), "select rotated key");
            CaRecord expected = new CaRecord(ROOT, disabled.kind(), disabled.state(), fixture.second().signingKeyRef(),
                    disabled.subjectRef(), disabled.issuerIds(), fixture.second().issuerId(), fixture.secondPath().pathId());
            for (int attempt = 0; attempt < 2; attempt++) {
                bootstrap.calls.clear();
                assertEquals(new PkiOperationResult("issuer.path.select", Map.of("caId", text(ROOT.value()),
                        "issuerId", text(fixture.second().issuerId().value()),
                        "pathId", text(fixture.secondPath().pathId().value()))), completed(session.operations(), operation));
                assertEquals(List.of("getCa", "getIssuerGeneration", "getIssuerChainPath", "replaceCa"), bootstrap.calls);
                assertEquals(expected, bootstrap.store.getCa(ROOT).orElseThrow());
            }
            assertFalse(disabled.issuerKeyRef().equals(expected.issuerKeyRef()));
        }
    }

    @Test
    void registersAlternateLeafToAnchorPathForInactiveGenerationWithoutChangingAuthority(@TempDir Path temporary)
            throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            IssuerChainPath expected = IssuerChainPath.create(CHILD, fixture.childGeneration().issuerId(),
                    List.of(fixture.childGeneration().credentialId(), fixture.second().credentialId()));
            PkiOperation operation = new PkiOperation.RegisterIssuerChainPath(CHILD,
                    fixture.childGeneration().issuerId(), fixture.secondPath().pathId());
            bootstrap.calls.clear();
            assertEquals(new PkiOperationResult("issuer.path.register", Map.of(
                    "pathId", text(expected.pathId().value()), "authorityId", text(CHILD.value()),
                    "issuerId", text(expected.issuerId().value()), "pathCommitment", text(expected.pathCommitment()),
                    "count", new PkiOperationValue.IntegerValue(2),
                    "orderedCredentialIds", new PkiOperationValue.ListValue(List.of(
                            text(fixture.childGeneration().credentialId().value()), text(fixture.second().credentialId().value()))))),
                    completed(session.operations(), operation));
            assertEquals(List.of("getCa", "getIssuerGeneration", "getIssuerChainPath", "putIssuerChainPath"), bootstrap.calls);
            assertEquals(expected, bootstrap.store.getIssuerChainPath(expected.pathId()).orElseThrow());
            assertEquals(fixture.child(), bootstrap.store.getCa(CHILD).orElseThrow());
            assertFailure(session.operations(), operation, PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
            assertEquals(fixture.child(), bootstrap.store.getCa(CHILD).orElseThrow());
        }
    }

    @Test
    void missingCoordinatesAndPolicyViolationsRemainSafeAndPerformNoWrites(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            for (PkiOperation operation : List.of(
                    new PkiOperation.TransitionAuthority(MISSING, CaState.DISABLED, "disable"),
                    new PkiOperation.SelectIssuancePath(MISSING, MISSING, MISSING, "select"),
                    new PkiOperation.SelectIssuancePath(ROOT, MISSING, fixture.firstPath().pathId(), "select"),
                    new PkiOperation.SelectIssuancePath(ROOT, fixture.first().issuerId(), MISSING, "select"),
                    new PkiOperation.RegisterIssuerChainPath(MISSING, MISSING, MISSING),
                    new PkiOperation.RegisterIssuerChainPath(ROOT, MISSING, fixture.firstPath().pathId()),
                    new PkiOperation.RegisterIssuerChainPath(ROOT, fixture.first().issuerId(), MISSING))) {
                assertFailure(session.operations(), operation, PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
            }
            for (PkiOperation operation : List.of(
                    new PkiOperation.SelectIssuancePath(ROOT, fixture.childGeneration().issuerId(), fixture.childPath().pathId(), "select"),
                    new PkiOperation.SelectIssuancePath(CHILD, fixture.childGeneration().issuerId(), fixture.childPath().pathId(), "select"),
                    new PkiOperation.SelectIssuancePath(ROOT, fixture.second().issuerId(), fixture.firstPath().pathId(), "select"),
                    new PkiOperation.RegisterIssuerChainPath(ROOT, fixture.childGeneration().issuerId(), fixture.firstPath().pathId()))) {
                assertFailure(session.operations(), operation, PkiOperationFailure.POLICY_REJECTION, "PKI_POLICY_REJECTED");
            }
            assertFalse(bootstrap.calls.contains("replaceCa"));
            assertFalse(bootstrap.calls.contains("putIssuerChainPath"));
            assertEquals(fixture.root(), bootstrap.store.getCa(ROOT).orElseThrow());
            assertEquals(fixture.child(), bootstrap.store.getCa(CHILD).orElseThrow());
        }
    }

    @Test
    void bothConditionalMutationsReturnConflictWithoutOverwritingTheConcurrentWinner(@TempDir Path temporary)
            throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            List<PkiOperation> operations = List.of(new PkiOperation.TransitionAuthority(ROOT, CaState.DISABLED, "disable"),
                    new PkiOperation.SelectIssuancePath(ROOT, fixture.second().issuerId(), fixture.secondPath().pathId(), "select"));
            for (int index = 0; index < operations.size(); index++) {
                CaRecord before = bootstrap.store.getCa(ROOT).orElseThrow();
                bootstrap.concurrentState = index == 0 ? CaState.RETIRED : CaState.COMPROMISED;
                CaRecord winner = withState(before, bootstrap.concurrentState);
                bootstrap.calls.clear();
                assertFailure(session.operations(), operations.get(index), PkiOperationFailure.CONFLICT, "OPERATION_CONFLICT");
                assertEquals(1L, bootstrap.calls.stream().filter("replaceCa"::equals).count());
                assertEquals(winner, bootstrap.store.getCa(ROOT).orElseThrow());
            }
        }
    }

    @Test
    void pathRegistrationRetainsStructuralAndDepthLimits(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            Fixture fixture = fixture(bootstrap.store);
            PkiOperation duplicateCredential = new PkiOperation.RegisterIssuerChainPath(CHILD,
                    fixture.childGeneration().issuerId(), fixture.childPath().pathId());
            assertFailure(session.operations(), duplicateCredential, PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
            assertFalse(bootstrap.calls.contains("putIssuerChainPath"));
            // A controlled depth-32 metadata return isolates the executor's child-depth boundary.
            List<PkiId> credentials = new ArrayList<>();
            for (int index = 0; index < IssuerChainPath.MAX_CERTIFICATES; index++) credentials.add(new PkiId("depth-" + index));
            bootstrap.parentOverride = IssuerChainPath.create(ROOT, fixture.first().issuerId(), credentials);
            bootstrap.calls.clear();
            assertFailure(session.operations(), new PkiOperation.RegisterIssuerChainPath(CHILD,
                    fixture.childGeneration().issuerId(), fixture.firstPath().pathId()),
                    PkiOperationFailure.VALIDATION_FAILURE, "OPERATION_INPUT_INVALID");
            assertFalse(bootstrap.calls.contains("putIssuerChainPath"));
            bootstrap.parentOverride = null;
            // A real foreign parent has valid certificates but cannot satisfy this child's issuer relationship.
            IntermediateCreationFixture foreign = new IntermediateCreationFixture();
            foreign.initialize(bootstrap.store, 1);
            CaRecord foreignRoot = bootstrap.store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            assertFailure(session.operations(), new PkiOperation.RegisterIssuerChainPath(CHILD,
                    fixture.childGeneration().issuerId(), foreignRoot.issuanceChainPathId()),
                    PkiOperationFailure.RESOURCE_FAILURE, "PKI_RESOURCE_FAILED");
            assertEquals(fixture.child(), bootstrap.store.getCa(CHILD).orElseThrow());
        }
    }

    @Test
    void uncertainAdministrativeWriteUsesOneAttemptAndSafeRecoveryOutcome(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = open(temporary, bootstrap)) {
            fixture(bootstrap.store);
            bootstrap.uncertain = true;
            assertFailure(session.operations(), new PkiOperation.TransitionAuthority(ROOT, CaState.DISABLED, "disable"),
                    PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            assertEquals(List.of("getCa", "replaceCa"), bootstrap.calls);
        }
    }

    @Test
    void precancellationAndClosedSessionPerformNoStoreCalls(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        List<PkiOperation> operations = List.of(new PkiOperation.TransitionAuthority(ROOT, CaState.ACTIVE, "activate"),
                new PkiOperation.SelectIssuancePath(ROOT, MISSING, MISSING, "select"),
                new PkiOperation.RegisterIssuerChainPath(ROOT, MISSING, MISSING));
        PkiOperationExecutor executor;
        try (PkiSession session = open(temporary, bootstrap)) {
            executor = session.operations();
            bootstrap.calls.clear();
            for (PkiOperation operation : operations) {
                assertEquals(new PkiOperationOutcome.Failed(operation.name(), PkiOperationFailure.CANCELLED, "OPERATION_CANCELLED"),
                        executor.execute(operation, () -> true));
            }
            assertTrue(bootstrap.calls.isEmpty());
        }
        bootstrap.calls.clear();
        for (PkiOperation operation : operations) {
            assertThrows(IllegalStateException.class, () -> executor.execute(operation, CancellationSignal.NONE));
        }
        assertTrue(bootstrap.calls.isEmpty());
    }

    @Test
    void administrativeInputsRequireCoordinatesAndNonblankReasons() {
        assertThrows(NullPointerException.class, () -> new PkiOperation.TransitionAuthority(null, CaState.ACTIVE, "reason"));
        assertThrows(NullPointerException.class, () -> new PkiOperation.TransitionAuthority(ROOT, null, "reason"));
        assertThrows(NullPointerException.class, () -> new PkiOperation.SelectIssuancePath(null, MISSING, MISSING, "reason"));
        assertThrows(NullPointerException.class, () -> new PkiOperation.SelectIssuancePath(ROOT, null, MISSING, "reason"));
        assertThrows(NullPointerException.class, () -> new PkiOperation.SelectIssuancePath(ROOT, MISSING, null, "reason"));
        assertThrows(NullPointerException.class, () -> new PkiOperation.RegisterIssuerChainPath(null, MISSING, MISSING));
        assertThrows(NullPointerException.class, () -> new PkiOperation.RegisterIssuerChainPath(ROOT, null, MISSING));
        assertThrows(NullPointerException.class, () -> new PkiOperation.RegisterIssuerChainPath(ROOT, MISSING, null));
        for (String reason : new String[] { null, "", "  " }) {
            assertThrows(IllegalArgumentException.class, () -> new PkiOperation.TransitionAuthority(ROOT, CaState.ACTIVE, reason));
            assertThrows(IllegalArgumentException.class, () -> new PkiOperation.SelectIssuancePath(ROOT, MISSING, MISSING, reason));
        }
    }

    private static PkiOperationResult completed(PkiOperationExecutor executor, PkiOperation operation) {
        return assertInstanceOf(PkiOperationOutcome.Completed.class, executor.execute(operation, CancellationSignal.NONE)).result();
    }

    private static void assertFailure(PkiOperationExecutor executor, PkiOperation operation,
            PkiOperationFailure classification, String code) {
        assertEquals(new PkiOperationOutcome.Failed(operation.name(), classification, code),
                executor.execute(operation, CancellationSignal.NONE));
    }

    private static PkiOperationValue text(String value) { return new PkiOperationValue.Text(value); }

    private static Map<String, PkiOperationValue> authorityFields(CaRecord ca) {
        return Map.of("caId", text(ca.caId().value()), "kind", text(ca.kind().name()), "state", text(ca.state().name()),
                "issuerGenerationCount", new PkiOperationValue.IntegerValue(ca.issuerIds().size()),
                "currentIssuanceIssuerId", text(ca.currentIssuanceIssuerId().value()));
    }

    private static CaRecord withState(CaRecord ca, CaState state) {
        return new CaRecord(ca.caId(), ca.kind(), state, ca.issuerKeyRef(), ca.subjectRef(), ca.issuerIds(),
                ca.currentIssuanceIssuerId(), ca.issuanceChainPathId());
    }

    private static Fixture fixture(PkiStore store) throws Exception {
        IssuerGeneration first = generation(store, ROOT, 1, IssuerGenerationState.ACTIVE, null);
        IssuerChainPath firstPath = IssuerChainPath.create(ROOT, first.issuerId(), List.of(first.credentialId()));
        store.putIssuerChainPath(firstPath);
        IssuerGeneration second = generation(store, ROOT, 2, IssuerGenerationState.ACTIVE, null);
        IssuerChainPath secondPath = IssuerChainPath.create(ROOT, second.issuerId(), List.of(second.credentialId()));
        store.putIssuerChainPath(secondPath);
        CaRecord root = new CaRecord(ROOT, CaKind.ROOT, CaState.ACTIVE, first.signingKeyRef(),
                new SubjectRef("CN=Acceptance Issuer"), List.of(first.issuerId(), second.issuerId()),
                first.issuerId(), firstPath.pathId());
        store.putCa(root);
        IssuerGeneration child = generation(store, CHILD, 3, IssuerGenerationState.RETIRED,
                new IssuerRef(ROOT, first.issuerId(), firstPath.pathId()));
        IssuerChainPath childPath = IssuerChainPath.create(CHILD, child.issuerId(), List.of(child.credentialId(), first.credentialId()));
        store.putIssuerChainPath(childPath);
        CaRecord childCa = new CaRecord(CHILD, CaKind.INTERMEDIATE, CaState.DISABLED, child.signingKeyRef(),
                new SubjectRef("CN=Administration Child"), List.of(child.issuerId()), child.issuerId(), childPath.pathId());
        store.putCa(childCa);
        return new Fixture(root, first, firstPath, second, secondPath, childCa, child, childPath);
    }

    private static IssuerGeneration generation(PkiStore store, PkiId authority, int serial,
            IssuerGenerationState state, IssuerRef issuer) throws Exception {
        PkiId credentialId = new PkiId("admin-credential-" + serial);
        PkiId issuerId = IssuerGeneration.idFor(authority, credentialId);
        String subject = issuer == null ? "CN=Acceptance Issuer" : "CN=Administration Child";
        IssuerRef reference = issuer == null ? new IssuerRef(authority, issuerId,
                IssuerChainPath.create(authority, issuerId, List.of(credentialId)).pathId()) : issuer;
        byte[] certificate = SemanticIssuanceFixture.certificate(subject, BigInteger.valueOf(serial),
                SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER).getEncoded();
        store.putCredential(new Credential(credentialId, new FormatId("x509"), reference, new SubjectRef(subject),
                new Validity(SemanticIssuanceFixture.BEFORE, SemanticIssuanceFixture.AFTER), Integer.toString(serial),
                new PkiId("admin-public-key"), new CaProfileBinding(new CertificateProfileRef("profile", 1, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.stageCredential(store, certificate), new SimpleAttributeSet()));
        // Distinct provider key references can identify the same public key during administrative selection.
        IssuerGeneration generation = new IssuerGeneration(issuerId, authority, credentialId, new KeyRef("admin-key-" + serial),
                state, "1".repeat(64), "1".repeat(64));
        store.putIssuerGeneration(generation);
        return generation;
    }

    private record Fixture(CaRecord root, IssuerGeneration first, IssuerChainPath firstPath,
            IssuerGeneration second, IssuerChainPath secondPath, CaRecord child,
            IssuerGeneration childGeneration, IssuerChainPath childPath) { }

    private static PkiSession open(Path temporary, ObservedBootstrap bootstrap) {
        return open(temporary, bootstrap, IntermediateCreationFixture.CLOCK);
    }

    private static PkiSession open(Path temporary, ObservedBootstrap bootstrap, java.time.Clock clock) {
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
        PkiSession session = DefaultPkiSession.open(configuration, clock, bootstrap);
        bootstrap.calls.clear();
        return session;
    }

    /** Observes the executor boundary; all fixture and CAS work uses the unmodified filesystem store. */
    private static final class ObservedBootstrap implements DefaultPkiSession.Bootstrap {
        private PkiStore store;
        private final List<String> calls = new ArrayList<>();
        private CaState concurrentState;
        private CaState afterReplace;
        private boolean uncertain;
        private IssuerChainPath parentOverride;

        @Override public void validateStore(ProviderConfig configuration) { PkiBootstrap.validateStoreConfiguration(configuration); }
        @Override public void validateAudit(ProviderConfig configuration) { PkiBootstrap.validateAuditConfiguration(configuration); }
        @Override public PkiStore openStore(ProviderConfig configuration) {
            store = PkiBootstrap.openStore(configuration);
            return observedStore();
        }
        @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(configuration, dependencies);
            return observedStore();
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) { return PkiBootstrap.openAudit(configuration); }
        @Override public SigningProvider openSigning(ProviderConfig configuration, SigningProviderRuntimeDependencies dependencies) {
            throw new AssertionError("Administrative operations must not open signing providers");
        }

        private PkiStore observedStore() {
            return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        calls.add(method.getName());
                        if (method.getName().equals("getIssuerChainPath") && parentOverride != null) return Optional.of(parentOverride);
                        if (method.getName().equals("replaceCa")) {
                            if (uncertain) throw new PkiException("private write coordinates", PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
                            if (concurrentState != null) {
                                CaRecord expected = (CaRecord) arguments[0];
                                assertTrue(store.replaceCa(expected, withState(expected, concurrentState)));
                                concurrentState = null;
                            }
                        }
                        try {
                            Object result = method.invoke(store, arguments);
                            if (method.getName().equals("replaceCa") && afterReplace != null) {
                                assertEquals(Boolean.TRUE, result);
                                CaRecord replacement = (CaRecord) arguments[1];
                                assertTrue(store.replaceCa(replacement, withState(replacement, afterReplace)));
                                afterReplace = null;
                            }
                            return result;
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
        }
    }
}
