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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
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

final class PkiOperationInspectionTest {
    @Test
    void projectsExactMetadataFromRealStoreWithoutOtherExecutorIo(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(bootstrap.store, 2);
            fixture.intermediateParent(bootstrap.store, 1, false);
            CaRecord authority = bootstrap.store.getCa(new PkiId("middle-authority")).orElseThrow();
            IssuerGeneration generation = bootstrap.store.getIssuerGeneration(
                    authority.currentIssuanceIssuerId()).orElseThrow();
            IssuerChainPath path = bootstrap.store.getIssuerChainPath(authority.issuanceChainPathId()).orElseThrow();
            Credential caCredential = bootstrap.store.getCredential(generation.credentialId()).orElseThrow();
            CertificateProfileRef caProfile = assertInstanceOf(CaProfileBinding.class,
                    caCredential.profileBinding()).reference();
            Credential leaf = leaf(bootstrap.store, authority, path);
            StatusObject status = status(bootstrap.store, authority.caId(), "status-with-next",
                    Optional.of(IntermediateCreationFixture.NOW.plusSeconds(600)));
            StatusObject noNext = status(bootstrap.store, authority.caId(), "status-without-next", Optional.empty());

            PkiOperationExecutor executor = session.operations();
            assertProjection(bootstrap, executor, new PkiOperation.InspectAuthority(authority.caId()), "ca.inspect",
                    "getCa", authority.caId(), Map.of(
                            "caId", text("middle-authority"), "kind", text("INTERMEDIATE"), "state", text("ACTIVE"),
                            "issuerGenerationCount", integer(1),
                            "currentIssuanceIssuerId", text(generation.issuerId().value())));
            assertProjection(bootstrap, executor, new PkiOperation.InspectCredential(caCredential.credentialId()),
                    "credential.inspect", "getCredential", caCredential.credentialId(),
                    credentialFields(caCredential, caProfile));
            assertProjection(bootstrap, executor, new PkiOperation.InspectCredential(leaf.credentialId()),
                    "credential.inspect", "getCredential", leaf.credentialId(), credentialFields(leaf,
                            assertInstanceOf(EndEntityProfileBinding.class, leaf.profileBinding()).reference()));
            assertProjection(bootstrap, executor, new PkiOperation.InspectIssuerGeneration(generation.issuerId()),
                    "issuer.generation.inspect", "getIssuerGeneration", generation.issuerId(), Map.of(
                            "issuerId", text(generation.issuerId().value()), "authorityId", text("middle-authority"),
                            "credentialId", text(caCredential.credentialId().value()), "state", text("ACTIVE"),
                            "profilePolicyCommitment", text(generation.profilePolicyCommitment()),
                            "x509BindingCommitment", text(generation.x509BindingCommitment()),
                            "profileId", text(caProfile.profileId())));
            assertEquals(2, path.orderedCredentialIds().size());
            CaRecord parent = bootstrap.store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            PkiId anchor = bootstrap.store.getIssuerGeneration(parent.currentIssuanceIssuerId())
                    .orElseThrow().credentialId();
            assertProjection(bootstrap, executor, new PkiOperation.InspectIssuerChainPath(path.pathId()),
                    "issuer.path.inspect", "getIssuerChainPath", path.pathId(), Map.of(
                            "pathId", text(path.pathId().value()), "authorityId", text("middle-authority"),
                            "issuerId", text(generation.issuerId().value()),
                            "pathCommitment", text(path.pathCommitment()), "count", integer(2),
                            "orderedCredentialIds", new PkiOperationValue.ListValue(List.of(
                                    text(caCredential.credentialId().value()), text(anchor.value())))));
            assertProjection(bootstrap, executor, new PkiOperation.InspectStatus(status.statusObjectId()),
                    "status.inspect", "getStatusObject", status.statusObjectId(), statusFields(status));
            assertProjection(bootstrap, executor, new PkiOperation.InspectStatus(noNext.statusObjectId()),
                    "status.inspect", "getStatusObject", noNext.statusObjectId(), statusFields(noNext));
            assertTrue(session.signing().isEmpty());
        }
    }

    @Test
    void allMissingKindsUseSafeNotFoundAfterExactlyOnePointLookup(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            for (Inspection inspection : inspections()) {
                bootstrap.observe(inspection.method(), MISSING);
                try {
                    PkiOperationOutcome.Failed failure = assertInstanceOf(PkiOperationOutcome.Failed.class,
                            session.operations().execute(inspection.operation(), CancellationSignal.NONE));
                    assertEquals(new PkiOperationOutcome.Failed(inspection.name(), PkiOperationFailure.NOT_FOUND,
                            "OBJECT_NOT_FOUND"), failure);
                    assertEquals(List.of(inspection.method()), bootstrap.calls);
                } finally {
                    bootstrap.stopObserving();
                }
            }
        }
    }

    @Test
    void precancelledInspectionsPerformNoStoreLookup(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            bootstrap.observe("no-store-call-permitted", MISSING);
            try {
                for (Inspection inspection : inspections()) {
                    assertEquals(new PkiOperationOutcome.Failed(inspection.name(), PkiOperationFailure.CANCELLED,
                            "OPERATION_CANCELLED"), session.operations().execute(inspection.operation(), () -> true));
                }
                assertTrue(bootstrap.calls.isEmpty());
            } finally {
                bootstrap.stopObserving();
            }
        }
    }

    @Test
    void retainedExecutorRejectsEveryInspectionAfterSessionClose(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        PkiOperationExecutor executor;
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            executor = session.operations();
        }
        bootstrap.observe("no-store-call-permitted", MISSING);
        try {
            for (Inspection inspection : inspections()) {
                assertThrows(IllegalStateException.class,
                        () -> executor.execute(inspection.operation(), CancellationSignal.NONE));
            }
            assertTrue(bootstrap.calls.isEmpty());
        } finally {
            bootstrap.stopObserving();
        }
    }

    @Test
    void inspectionRecordsRequireIdentifiersAndPreserveSemanticNames() {
        assertThrows(NullPointerException.class, () -> new PkiOperation.InspectAuthority(null));
        assertThrows(NullPointerException.class, () -> new PkiOperation.InspectCredential(null));
        assertThrows(NullPointerException.class, () -> new PkiOperation.InspectIssuerGeneration(null));
        assertThrows(NullPointerException.class, () -> new PkiOperation.InspectIssuerChainPath(null));
        assertThrows(NullPointerException.class, () -> new PkiOperation.InspectStatus(null));
        for (Inspection inspection : inspections()) assertEquals(inspection.name(), inspection.operation().name());
    }

    @Test
    void listsRealAuthoritiesStatusesAndIssuerPathsWithExactPrefixesAndScope(@TempDir Path temporary)
            throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            PkiOperationExecutor executor = session.operations();
            assertListing(bootstrap, executor, new PkiOperation.ListAuthorities(1), "selectAuthoritiesPage", null,
                    Map.of("count", integer(0), "truncated", bool(false), "authorities", list(List.of())));
            IntermediateCreationFixture fixture = new IntermediateCreationFixture();
            fixture.initialize(bootstrap.store, 2);
            fixture.intermediateParent(bootstrap.store, 1, false);
            PkiId middle = new PkiId("middle-authority");
            CaRecord middleCa = bootstrap.store.getCa(middle).orElseThrow();
            status(bootstrap.store, middle, "list-middle-one", Optional.empty());
            status(bootstrap.store, IntermediateCreationFixture.CA, "list-parent", Optional.empty());
            status(bootstrap.store, middle, "list-middle-two", Optional.of(IntermediateCreationFixture.NOW.plusSeconds(600)));
            List<PkiOperationValue> authorities = bootstrap.store.listCas().stream()
                    .<PkiOperationValue>map(ca -> inspectedValue(executor, new PkiOperation.InspectAuthority(ca.caId())))
                    .toList();
            List<PkiOperationValue> statuses = bootstrap.store.listStatusObjects(middle).stream()
                    .sorted(java.util.Comparator.comparing(value -> value.statusObjectId().value()))
                    .<PkiOperationValue>map(status -> inspectedValue(executor,
                            new PkiOperation.InspectStatus(status.statusObjectId()))).toList();
            assertEquals(2, authorities.size());
            assertEquals(2, statuses.size());
            for (int limit : new int[] { 1, 2, 3 }) {
                int count = Math.min(limit, 2);
                assertListing(bootstrap, executor, new PkiOperation.ListAuthorities(limit), "selectAuthoritiesPage", null,
                        Map.of("count", integer(count), "truncated", bool(limit < 2),
                                "authorities", list(authorities.subList(0, count))));
                assertListing(bootstrap, executor, new PkiOperation.ListStatus(middle, limit), "listStatusObjectsPage", middle,
                        Map.of("issuerCaId", text(middle.value()), "count", integer(count), "truncated", bool(limit < 2),
                                "statusObjects", list(statuses.subList(0, count))));
            }
            PkiId issuer = middleCa.currentIssuanceIssuerId();
            List<IssuerChainPath> paths = bootstrap.store.listIssuerChainPaths(issuer);
            assertEquals(1, paths.size());
            assertListing(bootstrap, executor, new PkiOperation.ListIssuerChainPaths(issuer), "listIssuerChainPaths", issuer,
                    Map.of("issuerId", text(issuer.value()), "count", integer(1), "paths", list(List.of(
                            inspectedValue(executor, new PkiOperation.InspectIssuerChainPath(paths.getFirst().pathId()))))));
            assertListing(bootstrap, executor, new PkiOperation.ListStatus(MISSING, 1), "listStatusObjectsPage", MISSING,
                    Map.of("issuerCaId", text(MISSING.value()), "count", integer(0), "truncated", bool(false),
                            "statusObjects", list(List.of())));
            assertListing(bootstrap, executor, new PkiOperation.ListIssuerChainPaths(MISSING), "listIssuerChainPaths", MISSING,
                    Map.of("issuerId", text(MISSING.value()), "count", integer(0), "paths", list(List.of())));

            String firstCa = ((PkiOperationValue.Text) ((PkiOperationValue.ObjectValue) authorities.getFirst()).fields().get("caId")).value();
            assertListing(bootstrap, executor, new PkiOperation.ListAuthorities(1, Optional.of(firstCa)), "selectAuthoritiesPage", null,
                    Map.of("count", integer(1), "truncated", bool(false), "authorities", list(List.of(authorities.getLast()))));
            String firstStatus = ((PkiOperationValue.Text) ((PkiOperationValue.ObjectValue) statuses.getFirst()).fields().get("statusObjectId")).value();
            assertListing(bootstrap, executor, new PkiOperation.ListStatus(middle, 1, Optional.of(firstStatus)), "listStatusObjectsPage", middle,
                    Map.of("issuerCaId", text(middle.value()), "count", integer(1), "truncated", bool(false),
                            "statusObjects", list(List.of(statuses.getLast()))));
        }
    }

    @Test
    void pathListingProjectsAllReturnedPathsInStoreOrderWithoutHiddenCap(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            PkiId authority = new PkiId("path-authority");
            PkiId credential = new PkiId("path-credential");
            PkiId issuer = IssuerGeneration.idFor(authority, credential);
            List<IssuerChainPath> paths = new ArrayList<>();
            List<PkiOperationValue> expected = new ArrayList<>();
            // Controlled store output isolates projection ordering and size from cryptographic fixture cost.
            for (int index = 1000; index >= 0; index--) {
                IssuerChainPath path = IssuerChainPath.create(authority, issuer,
                        List.of(credential, new PkiId("anchor-" + index)));
                paths.add(path);
                expected.add(new PkiOperationValue.ObjectValue(Map.of(
                        "pathId", text(path.pathId().value()), "authorityId", text(authority.value()),
                        "issuerId", text(issuer.value()), "pathCommitment", text(path.pathCommitment()),
                        "count", integer(2), "orderedCredentialIds", list(List.of(
                                text(credential.value()), text("anchor-" + index))))));
            }
            bootstrap.listResult = List.copyOf(paths);
            try {
                assertListing(bootstrap, session.operations(), new PkiOperation.ListIssuerChainPaths(issuer),
                        "listIssuerChainPaths", issuer, Map.of("issuerId", text(issuer.value()),
                                "count", integer(1001), "paths", list(expected)));
            } finally {
                bootstrap.listResult = null;
            }
        }
    }

    @Test
    void listingFailuresAreNotConvertedToPartialResults(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            for (Inspection listing : listings()) {
                bootstrap.observe(listing.method(), listing.operation() instanceof PkiOperation.ListAuthorities ? null : MISSING);
                bootstrap.failList = true;
                try {
                    assertEquals(new PkiOperationOutcome.Failed(listing.name(), PkiOperationFailure.RESOURCE_FAILURE,
                            "PKI_RESOURCE_FAILED"), session.operations().execute(listing.operation(), CancellationSignal.NONE));
                    assertEquals(List.of(listing.method()), bootstrap.calls);
                } finally {
                    bootstrap.failList = false;
                    bootstrap.stopObserving();
                }
            }
        }
    }

    @Test
    void listingsRespectPreCancellationAndClosedSessionWithoutStoreCalls(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        PkiOperationExecutor executor;
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            executor = session.operations();
            bootstrap.observe("no-store-call-permitted", MISSING);
            try {
                for (Inspection listing : listings()) {
                    assertEquals(new PkiOperationOutcome.Failed(listing.name(), PkiOperationFailure.CANCELLED,
                            "OPERATION_CANCELLED"), executor.execute(listing.operation(), () -> true));
                }
                assertTrue(bootstrap.calls.isEmpty());
            } finally {
                bootstrap.stopObserving();
            }
        }
        bootstrap.observe("no-store-call-permitted", MISSING);
        try {
            for (Inspection listing : listings()) {
                assertThrows(IllegalStateException.class,
                        () -> executor.execute(listing.operation(), CancellationSignal.NONE));
            }
            assertTrue(bootstrap.calls.isEmpty());
        } finally {
            bootstrap.stopObserving();
        }
    }

    @Test
    void traversesMoreThanOneThousandRequestsAndAuthorizesBeforeLookahead(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary), IntermediateCreationFixture.CLOCK, bootstrap)) {
            List<String> expected = new ArrayList<>();
            for (int index = 1004; index >= 0; index--) {
                String id = "request-" + String.format(java.util.Locale.ROOT, "%04d", index);
                expected.add(id);
                bootstrap.store.putRequest(new zeroecho.pki.api.request.ParsedCertificationRequest(new PkiId(id),
                        new FormatId("x509"), new SubjectRef("private-person"),
                        new zeroecho.pki.api.EncodedObject(Encoding.DER, new byte[] { 1 }), Optional.empty(), Optional.of("profile-a"),
                        new SimpleAttributeSet()));
            }
            expected.sort(String::compareTo);
            PkiSelectionExecutor executor = assertInstanceOf(PkiSelectionExecutor.class, session.operations());
            List<String> seen = new ArrayList<>();
            Optional<String> after = Optional.empty();
            do {
                PkiOperationResult page = assertInstanceOf(PkiOperationOutcome.Completed.class,
                        executor.executeSelection(new PkiOperation.ListRequests(127, after), row -> true, CancellationSignal.NONE)).result();
                PkiOperationValue.ListValue rows = (PkiOperationValue.ListValue) page.fields().get("requests");
                assertTrue(rows.values().size() <= 127);
                for (PkiOperationValue row : rows.values()) {
                    PkiOperationValue.ObjectValue value = (PkiOperationValue.ObjectValue) row;
                    assertEquals(java.util.Set.of("requestId", "formatId", "profileId"), value.fields().keySet());
                    seen.add(((PkiOperationValue.Text) value.fields().get("requestId")).value());
                }
                after = Optional.ofNullable(page.fields().get("nextCursor")).map(value -> ((PkiOperationValue.Text) value).value());
            } while (after.isPresent());
            assertEquals(expected, seen);
            java.util.concurrent.atomic.AtomicInteger visited = new java.util.concurrent.atomic.AtomicInteger();
            PkiOperationResult filtered = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    executor.executeSelection(new PkiOperation.ListRequests(1, Optional.empty()), row -> {
                        visited.incrementAndGet();
                        return ((PkiOperationValue.Text) row.fields().get("requestId")).value().compareTo("request-1002") >= 0;
                    }, CancellationSignal.NONE)).result();
            assertEquals(1005, visited.get(), "Sparse authorization uses one directory scan");
            assertEquals(text("request-1002"), filtered.fields().get("nextCursor"));
            java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
            PkiOperationOutcome.Failed cancelled = assertInstanceOf(PkiOperationOutcome.Failed.class,
                    executor.executeSelection(new PkiOperation.ListRequests(1, Optional.empty()), row -> {
                        cancel.set(true); return false;
                    }, cancel::get));
            assertEquals(PkiOperationFailure.CANCELLED, cancelled.classification());
        }
    }

    @Test
    void knownKeyMetadataCursorCancellationRetainsCancellationClassification(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary), IntermediateCreationFixture.CLOCK, bootstrap)) {
            new IntermediateCreationFixture().initialize(bootstrap.store, 2);
            java.util.concurrent.atomic.AtomicInteger checks = new java.util.concurrent.atomic.AtomicInteger();
            assertThrows(java.util.concurrent.CancellationException.class,
                    () -> bootstrap.store.visitAuthorityKeyReferences(key -> { throw new AssertionError("Cancelled cursor must not yield keys"); },
                            () -> checks.incrementAndGet() >= 2));
            assertTrue(checks.get() >= 2);
        }
    }

    @Test
    void listingInputsValidateExistingBoundsAndSemanticNames() {
        for (int limit : new int[] { 0, 1001 }) {
            assertThrows(IllegalArgumentException.class, () -> new PkiOperation.ListAuthorities(limit));
            assertThrows(IllegalArgumentException.class, () -> new PkiOperation.ListStatus(MISSING, limit));
        }
        for (int limit : new int[] { 1, 1000 }) {
            assertEquals(limit, new PkiOperation.ListAuthorities(limit).limit());
            assertEquals(limit, new PkiOperation.ListStatus(MISSING, limit).limit());
        }
        assertThrows(NullPointerException.class, () -> new PkiOperation.ListStatus(null, 1));
        assertThrows(NullPointerException.class, () -> new PkiOperation.ListIssuerChainPaths(null));
        for (Inspection listing : listings()) assertEquals(listing.name(), listing.operation().name());
    }

    @Test
    void mapsTypedStoreDurabilityUncertaintyToSafeRecoveryOutcomeWithoutRetry(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            bootstrap.observe("getCa", MISSING);
            bootstrap.failure = new PkiException("private storage coordinates must stay internal",
                    PkiFailureReason.STORE_DURABILITY_UNCONFIRMED,
                    new IllegalStateException("private storage cause"));
            try {
                assertEquals(new PkiOperationOutcome.Failed("ca.inspect", PkiOperationFailure.RECOVERY_REQUIRED,
                        "RECOVERY_REQUIRED"), session.operations().execute(new PkiOperation.InspectAuthority(MISSING),
                                CancellationSignal.NONE));
                assertEquals(List.of("getCa"), bootstrap.calls);
            } finally {
                bootstrap.failure = null;
                bootstrap.stopObserving();
            }
        }
    }

    @Test
    void preservesPolicyClassificationForMessageTokensWithNoTypedReason(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            bootstrap.observe("getCa", MISSING);
            bootstrap.failure = new PkiException("STORE_DURABILITY_UNCONFIRMED RECOVERY_REQUIRED");
            try {
                assertEquals(new PkiOperationOutcome.Failed("ca.inspect", PkiOperationFailure.POLICY_REJECTION,
                        "PKI_POLICY_REJECTED"), session.operations().execute(new PkiOperation.InspectAuthority(MISSING),
                                CancellationSignal.NONE));
                assertEquals(List.of("getCa"), bootstrap.calls);
            } finally {
                bootstrap.failure = null;
                bootstrap.stopObserving();
            }
        }
    }

    @Test
    void mapsTypedPkiExceptionReasonByItsClassification(@TempDir Path temporary) throws Exception {
        ObservedBootstrap bootstrap = new ObservedBootstrap();
        try (PkiSession session = DefaultPkiSession.open(configuration(temporary),
                IntermediateCreationFixture.CLOCK, bootstrap)) {
            bootstrap.observe("getCa", MISSING);
            bootstrap.failure = new PkiException("internal", PkiFailureReason.REVOCATION_RECOVERY_REQUIRED);
            try {
                assertEquals(new PkiOperationOutcome.Failed("ca.inspect", PkiOperationFailure.RECOVERY_REQUIRED,
                        "RECOVERY_REQUIRED"), session.operations().execute(new PkiOperation.InspectAuthority(MISSING),
                                CancellationSignal.NONE));
                assertEquals(List.of("getCa"), bootstrap.calls);
            } finally {
                bootstrap.failure = null;
                bootstrap.stopObserving();
            }
        }
    }

    private static List<Inspection> listings() {
        return List.of(new Inspection(new PkiOperation.ListAuthorities(1), "ca.list", "selectAuthoritiesPage"),
                new Inspection(new PkiOperation.ListStatus(MISSING, 1), "inventory.status", "listStatusObjectsPage"),
                new Inspection(new PkiOperation.ListIssuerChainPaths(MISSING), "issuer.path.list", "listIssuerChainPaths"));
    }

    private static void assertListing(ObservedBootstrap bootstrap, PkiOperationExecutor executor,
            PkiOperation operation, String method, PkiId id, Map<String, PkiOperationValue> expected) {
        Map<String, PkiOperationValue> fields = new java.util.LinkedHashMap<>(expected);
        if (new PkiOperationValue.BooleanValue(true).equals(fields.get("truncated"))) {
            String collection = operation instanceof PkiOperation.ListAuthorities ? "authorities" : "statusObjects";
            String identity = operation instanceof PkiOperation.ListAuthorities ? "caId" : "statusObjectId";
            PkiOperationValue.ListValue rows = (PkiOperationValue.ListValue) fields.get(collection);
            fields.put("nextCursor", ((PkiOperationValue.ObjectValue) rows.values().getLast()).fields().get(identity));
        }
        assertProjection(bootstrap, executor, operation, operation.name(), method, id, fields);
    }

    private static PkiOperationValue inspectedValue(PkiOperationExecutor executor, PkiOperation operation) {
        return new PkiOperationValue.ObjectValue(assertInstanceOf(PkiOperationOutcome.Completed.class,
                executor.execute(operation, CancellationSignal.NONE)).result().fields());
    }

    private static PkiOperationValue list(List<PkiOperationValue> values) { return new PkiOperationValue.ListValue(values); }
    private static PkiOperationValue bool(boolean value) { return new PkiOperationValue.BooleanValue(value); }

    private static final PkiId MISSING = new PkiId("missing-inspection-object");

    private static List<Inspection> inspections() {
        return List.of(
                new Inspection(new PkiOperation.InspectAuthority(MISSING), "ca.inspect", "getCa"),
                new Inspection(new PkiOperation.InspectCredential(MISSING), "credential.inspect", "getCredential"),
                new Inspection(new PkiOperation.InspectIssuerGeneration(MISSING), "issuer.generation.inspect",
                        "getIssuerGeneration"),
                new Inspection(new PkiOperation.InspectIssuerChainPath(MISSING), "issuer.path.inspect",
                        "getIssuerChainPath"),
                new Inspection(new PkiOperation.InspectStatus(MISSING), "status.inspect", "getStatusObject"));
    }

    private static void assertProjection(ObservedBootstrap bootstrap, PkiOperationExecutor executor,
            PkiOperation operation, String name, String method, PkiId id, Map<String, PkiOperationValue> expected) {
        bootstrap.observe(method, id);
        try {
            PkiOperationResult result = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    executor.execute(operation, CancellationSignal.NONE)).result();
            assertEquals(new PkiOperationResult(name, expected), result);
            assertEquals(operation instanceof PkiOperation.InspectIssuerGeneration
                    ? List.of(method, "getCredential") : List.of(method), bootstrap.calls);
        } finally {
            bootstrap.stopObserving();
        }
    }

    private static Map<String, PkiOperationValue> credentialFields(Credential credential,
            CertificateProfileRef profile) {
        return Map.ofEntries(Map.entry("credentialId", text(credential.credentialId().value())),
                Map.entry("formatId", text(credential.formatId().value())),
                Map.entry("authorityId", text(credential.issuerRef().caId().value())),
                Map.entry("issuerId", text(credential.issuerRef().issuerId().value())),
                Map.entry("publicKeyId", text(credential.publicKeyId().value())),
                Map.entry("subjectRef", text(credential.subjectRef().value())),
                Map.entry("serialOrUniqueId", text(credential.serialOrUniqueId())),
                Map.entry("profileId", text(profile.profileId())),
                Map.entry("profileVersion", integer(profile.profileVersion())),
                Map.entry("status", text("ISSUED")),
                Map.entry("notBefore", text(credential.validity().notBefore().toString())),
                Map.entry("notAfter", text(credential.validity().notAfter().toString())));
    }

    private static Map<String, PkiOperationValue> statusFields(StatusObject status) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(Map.of(
                "statusObjectId", text(status.statusObjectId().value()), "issuerCaId", text("middle-authority"),
                "type", text("OCSP"), "formatId", text("inspection-format"),
                "thisUpdate", text(IntermediateCreationFixture.NOW.toString()),
                "contentLength", integer(status.content().length()), "contentSha256", text(status.content().sha256())));
        status.nextUpdate().ifPresent(next -> fields.put("nextUpdate", text(next.toString())));
        return fields;
    }

    private static Credential leaf(PkiStore store, CaRecord authority, IssuerChainPath path) throws Exception {
        // A generic expired credential proves that inspection does not reinterpret stored inventory status.
        Credential credential = new Credential(new PkiId("inspection-leaf"), new FormatId("inspection-format"),
                new IssuerRef(authority.caId(), authority.currentIssuanceIssuerId(), path.pathId()),
                new SubjectRef("inspection subject"), new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(60)),
                "inspection-serial", new PkiId("inspection-public-key"),
                new EndEntityProfileBinding(new CertificateProfileRef("inspection-profile", 7, new byte[32])),
                CredentialStatus.ISSUED, PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.BINARY,
                        new byte[] { 3, 2, 1 }), new SimpleAttributeSet());
        store.putCredential(credential);
        return credential;
    }

    private static StatusObject status(PkiStore store, PkiId authority, String id, Optional<Instant> next)
            throws Exception {
        DurableContentReference content = PkiTestRuntime.fixtureReference(store.stagedContent(), Encoding.BINARY,
                new byte[] { 9, 8, 7, 6 });
        StatusObject status = new StatusObject(new PkiId(id), new FormatId("inspection-format"), authority,
                StatusObjectType.OCSP, IntermediateCreationFixture.NOW, next, content, new SimpleAttributeSet());
        store.putStatusObject(status);
        return status;
    }

    private static PkiOperationValue text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue integer(long value) { return new PkiOperationValue.IntegerValue(value); }

    private static PkiSessionConfiguration configuration(Path temporary) {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporary.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());
    }

    private record Inspection(PkiOperation operation, String name, String method) { }

    /** Observes executor calls while preserving real store integrity checks and ownership. */
    private static final class ObservedBootstrap implements DefaultPkiSession.Bootstrap {
        private PkiStore store;
        private String expectedMethod;
        private PkiId expectedId;
        private PkiId generationCredentialId;
        private boolean reverseList;
        private boolean failList;
        private List<?> listResult;
        private RuntimeException failure;
        private final List<String> calls = new ArrayList<>();

        private void observe(String method, PkiId id) {
            calls.clear();
            expectedMethod = method;
            expectedId = id;
        }

        private void stopObserving() { expectedMethod = null; }

        @Override public void validateStore(ProviderConfig configuration) {
            PkiBootstrap.validateStoreConfiguration(configuration);
        }
        @Override public void validateAudit(ProviderConfig configuration) {
            PkiBootstrap.validateAuditConfiguration(configuration);
        }
        @Override public PkiStore openStore(ProviderConfig configuration) {
            store = PkiBootstrap.openStore(configuration);
            return observedStore();
        }
        @Override public PkiStore openStore(ProviderConfig configuration, PkiStoreRuntimeDependencies dependencies) {
            store = PkiBootstrap.openStore(configuration, dependencies);
            return observedStore();
        }
        @Override public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }
        @Override public SigningProvider openSigning(ProviderConfig configuration,
                SigningProviderRuntimeDependencies dependencies) {
            throw new AssertionError("Metadata inspections must not allocate a signing provider");
        }

        private PkiStore observedStore() {
            return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                    (proxy, method, arguments) -> {
                        if (expectedMethod != null) {
                            calls.add(method.getName());
                            if (expectedMethod.equals("getIssuerGeneration") && method.getName().equals("getCredential")) {
                                assertEquals(generationCredentialId, arguments[0], "Generation profile must come from its stored credential");
                            } else {
                                assertEquals(expectedMethod, method.getName(), "Inspection must use its authoritative metadata path");
                                if (method.getName().equals("selectAuthoritiesPage")) {
                                    assertInstanceOf(Optional.class, arguments[0]);
                                    assertTrue((int) arguments[1] <= 1001);
                                } else { assertEquals(expectedId, arguments == null ? null : arguments[0]); }
                            }
                            if (failure != null) throw failure;
                            if (failList) throw new IllegalStateException("Injected complete-list validation failure");
                        }
                        try {
                            Object result = method.invoke(store, arguments);
                            if (method.getName().equals("getIssuerGeneration") && result instanceof Optional<?> value
                                    && value.orElse(null) instanceof IssuerGeneration generation) {
                                generationCredentialId = generation.credentialId();
                            }
                            if (expectedMethod != null && result instanceof List<?> values) {
                                if (listResult != null) return listResult;
                                if (reverseList) {
                                    List<?> reversed = new ArrayList<>(values);
                                    Collections.reverse(reversed);
                                    return reversed;
                                }
                            }
                            return result;
                        } catch (InvocationTargetException failure) {
                            throw failure.getCause();
                        }
                    });
        }
    }
}
