/*
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
 */
package zeroecho.pki.application;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.IntermediateIssuanceFixture;

/**
 * Mandatory inventory regression: actual filesystem pages work without the optional search index.
 */
class CredentialInventoryTest {
    /**
     * Pages ca and leaf metadata before authorization limit without search.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void pagesCaAndLeafMetadataBeforeAuthorizationLimitWithoutSearch(@TempDir Path root) throws Exception { exercise(root); }
    /**
     * Requires a fixture invariant without relying on enabled JVM assertions.
     *
     * @param condition condition that must hold for the fixture assertion to succeed
     * @param message diagnostic attached to a failed fixture assertion
     * @throws AssertionError if the required condition is false
     */
    static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    /**
     * Requires successful operation completion and extracts its structured fields.
     *
     * @param value typed operation outcome or structured inventory result to inspect
     * @return copied structured operation result fields
     * @throws AssertionError if the operation did not complete successfully
     */
    static PkiOperationValue.ObjectValue result(PkiOperationOutcome value) {
        check(value instanceof PkiOperationOutcome.Completed, "Inventory failed: " + value);
        return new PkiOperationValue.ObjectValue(((PkiOperationOutcome.Completed) value).result().fields());
    }
    /**
     * Extracts ordered credential identities from the structured inventory result.
     *
     * @param value typed operation outcome or structured inventory result to inspect
     * @return immutable list of credential identifiers in result order
     */
    static List<String> ids(PkiOperationValue.ObjectValue value) {
        return ((PkiOperationValue.ListValue) value.fields().get("credentials")).values().stream()
                .map(row -> ((PkiOperationValue.Text) ((PkiOperationValue.ObjectValue) row).fields().get("credentialId")).value()).toList();
    }
    /**
     * Runs the complete actual-store scenario and its persisted-state assertions in the supplied root.
     *
     * @param root filesystem root retaining the test store and keyring artifacts
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    static void exercise(Path root) throws Exception {
        try (var store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            var fixture = new IntermediateIssuanceFixture(); fixture.initialize(store);
            var issuer = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            var parentCredential = store.getIssuerGeneration(issuer.currentIssuanceIssuerId()).orElseThrow().credentialId();
            var parent = store.getCredential(parentCredential).orElseThrow();
            // Metadata-only inventory must not assume all formats or profile bindings are X.509 CA records.
            var leafId = new PkiId("inventory:leaf");
            byte[] tbs = zeroecho.pkix.Pkix.certificateBuilder().serialNumber(java.math.BigInteger.valueOf(17))
                    .issuer(new javax.security.auth.x500.X500Principal(parent.subjectRef().value()))
                    .subject(new javax.security.auth.x500.X500Principal("CN=Inventory Leaf"))
                    .publicKeyInfo(fixture.base.childKey.getPublic().getEncoded())
                    .validity(parent.validity().notBefore(), parent.validity().notAfter())
                    .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(), true)
                    .buildTbs(zeroecho.pkix.Pkix.subjectPublicKeyAlgorithm(fixture.base.parentKey.getPublic().getEncoded()));
            byte[] leafDer = zeroecho.pkix.Pkix.assembleCertificateOrCrl(tbs,
                    fixture.base.signature(tbs, IntermediateCreationFixture.PARENT_KEY).bytes(), false);
            store.putCredential(new Credential(leafId, parent.formatId(), parent.issuerRef(), new zeroecho.pki.api.SubjectRef("CN=Inventory Leaf"), parent.validity(), "17",
                    new PkiId("spki:inventory-leaf"), new EndEntityProfileBinding(store.requireActiveProfile("server-tls").reference()),
                    parent.status(), zeroecho.pki.testkit.PkiTestRuntime.stageCredential(store, leafDer), parent.attributes()));
            var opaqueId = new PkiId("inventory:opaque");
            store.putCredential(new Credential(opaqueId, new FormatId("opaque-format"), parent.issuerRef(), parent.subjectRef(), parent.validity(), "18",
                    parent.publicKeyId(), new EndEntityProfileBinding(store.requireActiveProfile("server-tls").reference()),
                    parent.status(), parent.content(), parent.attributes()));
            check(!store.credentialSearchAvailable(), "Fixture unexpectedly enabled H2 search");
            var pureStore = PkiOperationValidationTest.readOnly(store);
            var audit = PkiOperationValidationTest.unreachable(AuditSink.class);
            ProfileService profiles = new DefaultProfileService(pureStore, IntermediateCreationFixture.CLOCK, audit);
            RevocationService revocations = new DefaultRevocationService(pureStore, IntermediateCreationFixture.CLOCK, audit);
            var executor = new DefaultPkiOperationExecutor(new DefaultPkiOperationExecutor.ConfigurationSummary(1, "fs", "memory"),
                    pureStore, profiles, revocations, Optional.empty(), Optional.empty(),
                    PkiOperationValidationTest.unreachable(CredentialConfirmationService.class), fixture.base.bindings, () -> { },
                    (limit, after, cancellation) -> { throw new AssertionError("Unexpected configuration scan"); },
                    IntermediateCreationFixture.CLOCK, DashboardLiveSource.NONE);
            List<String> collected = new ArrayList<>(); Optional<String> after = Optional.empty();
            do {
                var page = result(executor.execute(new PkiOperation.ListCredentials(issuer.caId(), 1, after), CancellationSignal.NONE));
                var current = ids(page); check(current.size() == 1, "Page was not bounded to one"); collected.addAll(current);
                boolean more = ((PkiOperationValue.BooleanValue) page.fields().get("truncated")).value();
                after = more ? Optional.of(((PkiOperationValue.Text) page.fields().get("nextCursor")).value()) : Optional.empty();
            } while (after.isPresent());
            check(collected.size() == 4 && collected.equals(collected.stream().distinct().sorted().toList()), "Inventory skipped or repeated credentials: " + collected);
            check(collected.contains(leafId.value()) && collected.contains(opaqueId.value()), "Leaf/opaque metadata absent");
            check(ids(result(executor.execute(new PkiOperation.ListCredentials(IntermediateIssuanceFixture.SUBJECT, 10, Optional.empty()), CancellationSignal.NONE))).isEmpty(),
                    "Intermediate's parent-issued CA certificate was attributed to child ownership");
            AtomicInteger authorizationCalls = new AtomicInteger();
            var authorized = result(executor.executeSelection(new PkiOperation.ListCredentials(issuer.caId(), 1, Optional.empty()), row -> {
                authorizationCalls.incrementAndGet();
                return ((PkiOperationValue.Text) row.fields().get("credentialId")).value().equals(opaqueId.value());
            }, CancellationSignal.NONE));
            check(ids(authorized).equals(List.of(opaqueId.value())) && authorizationCalls.get() > 1, "Denied earlier records consumed page capacity");
            check(ids(result(executor.executeSelection(new PkiOperation.ListCredentials(issuer.caId(), 10, Optional.empty()), row -> false, CancellationSignal.NONE))).isEmpty(),
                    "Unauthorized metadata leaked");
            var cancelled = executor.execute(new PkiOperation.ListCredentials(issuer.caId(), 1, Optional.empty()), () -> true);
            check(cancelled instanceof PkiOperationOutcome.Failed failure && failure.classification() == PkiOperationFailure.CANCELLED, "Cancellation ignored");
            check(result(executor.execute(new PkiOperation.ListCredentials(issuer.caId(), 1000, Optional.of("zzzz")), CancellationSignal.NONE))
                    .fields().get("truncated").equals(new PkiOperationValue.BooleanValue(false)), "Empty final page has a continuation");
            var resolver = new DefaultPkiResourceScopeResolver(pureStore, () -> { });
            check(resolver.credentialReadScope(parentCredential).orElseThrow().authorityId().equals(issuer.caId()), "CA scope missing");
            check(resolver.credentialScope(leafId).orElseThrow().authorityId().equals(issuer.caId()), "Leaf scope missing");
            var child = store.getCa(IntermediateIssuanceFixture.SUBJECT).orElseThrow();
            var childCredential = store.getIssuerGeneration(child.currentIssuanceIssuerId()).orElseThrow().credentialId();
            check(resolver.credentialReadScope(childCredential).orElseThrow().authorityId().equals(issuer.caId()), "Intermediate certificate scope changed from issuing parent");
            for(var caCredential:List.of(parentCredential,childCredential)) {
                try {resolver.credentialScope(caCredential);throw new AssertionError("CA became eligible for legacy lifecycle scope");}
                catch(IllegalStateException expected) { }
            }
            check(resolver.credentialReadScope(leafId).equals(resolver.credentialScope(leafId)),"Leaf read and legacy coordinates differ");
            check(!executor.credentialSearchAvailable(), "Mandatory inventory enabled advanced search");
            for (int badLimit : new int[]{0,1001}) {
                try { new PkiOperation.ListCredentials(issuer.caId(), badLimit, Optional.empty()); throw new AssertionError("Invalid bound accepted"); }
                catch (IllegalArgumentException expected) { }
            }
        }
        System.out.println("PASS no-H2 credential.list CA+leaf+opaque metadata, keyset pages, auth-before-limit, cancellation, CA/leaf canonical scope; advanced search stays disabled");
    }
    /**
     * Runs the standalone fixture scenario using a newly created temporary directory.
     *
     * @param args unused console arguments; the fixture creates its own temporary root
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public static void main(String[] args) throws Exception { exercise(Files.createTempDirectory("zeroecho-inventory-")); }
}
