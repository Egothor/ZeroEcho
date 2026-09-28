/*******************************************************************************
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

package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.LocalPkiSessionConfiguration;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.core.signing.SigningStepExecutor;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Real process interruption followed exclusively by the installed public CLI. */
@Tag("packaged-local-recovery")
public class PkiPackagedLocalRecoveryTest {
    private static final int SIGNATURE_HALT = 73;
    private static final int CLAIM_HALT = 74;

    @Test
    @Timeout(180)
    void durableSignatureSurvivesProcessHaltAndRequiresExplicitPackagedCompletion() throws Exception {
        Path directory = runDirectory("signed-");
        Path configuration = PkiLocalGateFixture.configuration(directory, PkiLocalGateFixture.rsaKey());
        byte[] originalKeyring = Files.readAllBytes(directory.resolve("keys.bin"));
        PkiLocalGateFixture.ProcessResult stopped = PkiLocalGateFixture.child(getClass(), directory, "halt-after-signature", "signed", configuration.toString());
        assertEquals(SIGNATURE_HALT, stopped.exit(), stopped.errors());
        PkiId id = selected(directory);
        Snapshot before = snapshot(configuration, id);
        assertEquals(SignWorkflowStore.State.SUCCEEDED, before.signing().state());
        assertEquals(DomainContinuationStore.State.SIGNING, before.outer().state());
        assertEquals(0, before.authorities());
        assertTrue(before.signing().result().isPresent());
        Files.writeString(directory.resolve("before-inspection.txt"), before.evidence());

        PkiLocalGateFixture.ProcessResult inspection = PkiLocalGateFixture.cli(executable(), configuration, directory, "inspect",
                "signing.operation.inspect", "--operation-id", id.value());
        assertEquals(0, inspection.exit(), inspection.output());
        assertUnchanged(before, snapshot(configuration, id));
        assertArrayEquals(originalKeyring, Files.readAllBytes(directory.resolve("keys.bin")), "Inspection changed the keyring");
        PkiLocalGateFixture.ProcessResult completed = PkiLocalGateFixture.cli(executable(), configuration, directory, "complete",
                "signing.operation.complete", "--operation-id", id.value());
        assertEquals(0, completed.exit(), completed.output());
        assertEquals(id.value(), PkiCliConfiguration.text(PkiLocalGateFixture.firstStep(completed).fields().get("operationId")));
        Snapshot after = snapshot(configuration, id);
        assertArrayEquals(originalKeyring, Files.readAllBytes(directory.resolve("keys.bin")), "Completion changed the keyring");
        Files.writeString(directory.resolve("after-completion.txt"), after.evidence());
        assertEquals(SignWorkflowStore.State.RETIRED, after.signing().state());
        assertEquals(before.signing().revision() + 1, after.signing().revision());
        assertEquals(before.signing().fence(), after.signing().fence());
        assertEquals(before.signing().providerUpdatedAt(), after.signing().providerUpdatedAt());
        assertEquals(before.signing().initialAttemptPhase(), after.signing().initialAttemptPhase());
        assertEquals(before.signing().stage(), after.signing().stage());
        assertArrayEquals(before.signing().result().orElseThrow().bytes(), after.signing().result().orElseThrow().bytes());
        assertEquals(DomainContinuationStore.State.COMPLETED, after.outer().state());
        assertEquals(1, after.authorities());
        try (PkiStore store = PkiBootstrap.openStore(PkiCliConfiguration.read(configuration).store())) {
            CaRecord authority = store.listCas().getFirst();
            IssuerGeneration generation = store.getIssuerGeneration(authority.currentIssuanceIssuerId()).orElseThrow();
            Credential credential = store.getCredential(generation.credentialId()).orElseThrow();
            try (RepeatableContent content = store.stagedContent().openContent(credential.content()); InputStream input = content.openStream()) {
                X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
                assertArrayEquals(before.signing().result().orElseThrow().bytes(), certificate.getSignature());
                certificate.verify(certificate.getPublicKey());
            }
        }
        // Deterministic RSA signature equality is publication evidence, not a provider-call counter.
        // LocalPkiSessionTest.durableSignatureResumesPublicationOnlyAfterExplicitEligibleCompletion
        // independently verifies that the dispatch counter remains exactly one across reopening.
    }

    @Test
    @Timeout(180)
    void lostInFlightResultFailsExplicitCompletionWithoutPublishingAnAuthority() throws Exception {
        Path directory = runDirectory("claimed-");
        Path configuration = PkiLocalGateFixture.configuration(directory, PkiLocalGateFixture.rsaKey());
        byte[] originalKeyring = Files.readAllBytes(directory.resolve("keys.bin"));
        PkiLocalGateFixture.ProcessResult stopped = PkiLocalGateFixture.child(getClass(), directory, "halt-after-claim", "claimed", configuration.toString());
        assertEquals(CLAIM_HALT, stopped.exit(), stopped.errors());
        PkiId id = selected(directory);
        Snapshot before = snapshot(configuration, id);
        assertEquals(SignWorkflowStore.State.DISPATCHED, before.signing().state());
        assertTrue(before.signing().result().isEmpty());
        assertEquals(0, before.authorities());
        PkiLocalGateFixture.ProcessResult inspection = PkiLocalGateFixture.cli(executable(), configuration, directory, "inspect",
                "signing.operation.inspect", "--operation-id", id.value());
        assertEquals(0, inspection.exit(), inspection.output());
        assertUnchanged(before, snapshot(configuration, id));
        assertArrayEquals(originalKeyring, Files.readAllBytes(directory.resolve("keys.bin")), "Inspection changed the keyring");
        Instant eligibility = before.signing().leaseUntil().orElseThrow();
        Duration remaining = Duration.between(Instant.now(), eligibility.plusMillis(50));
        assertTrue(remaining.compareTo(PkiLocalGateFixture.CLAIM_LEASE.plusSeconds(1)) < 0);
        if (remaining.isPositive()) { Thread.sleep(remaining); }
        PkiLocalGateFixture.ProcessResult completed = PkiLocalGateFixture.cli(executable(), configuration, directory, "complete",
                "signing.operation.complete", "--operation-id", id.value());
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, completed.exit(), completed.output());
        assertTrue(completed.output().contains("LOCAL_RESTART_UNRECOVERABLE"));
        Snapshot after = snapshot(configuration, id);
        assertArrayEquals(originalKeyring, Files.readAllBytes(directory.resolve("keys.bin")), "Completion changed the keyring");
        assertEquals(0, after.authorities());
        assertTrue(after.signing().result().isEmpty());
        assertEquals(DomainContinuationStore.State.FAILED, after.outer().state());
        Files.writeString(directory.resolve("before-inspection.txt"), before.evidence());
        Files.writeString(directory.resolve("after-completion.txt"), after.evidence());
    }

    /** Test child exits without shutdown hooks at an existing public durability callback. */
    public static void main(String[] arguments) throws Exception {
        String mode = arguments[0];
        Path configuration = Path.of(arguments[1]);
        LocalPkiSessionConfiguration local = PkiCliConfiguration.read(configuration);
        PkiId id;
        try (PkiSession session = PkiSession.openLocal(local, PkiLocalGateFixture.dependencies())) {
            PkiLocalGateFixture.seedProfile(session);
            id = PkiLocalGateFixture.accept(session, "Local Process Recovery");
        }
        Files.writeString(configuration.getParent().resolve("operation-id.txt"), id.value());
        try (PkiStore store = PkiBootstrap.openStore(local.store());
                SigningProvider provider = PkiBootstrap.openConfiguredSigningProvider(local.signing().orElseThrow().provider(),
                        SigningProviderRuntimeDependencies.withKeyringUnlockProvider(PkiLocalGateFixture::unlock))) {
            SignWorkflowStore.Workflow intent = store.getSignWorkflow(id).orElseThrow();
            if (mode.equals("claimed")) {
                SignWorkflowStore.Workflow claimed = store.claimSignStep(id, intent.revision(), PkiLocalGateFixture.CLAIM_LEASE).orElseThrow();
                if (claimed.state() != SignWorkflowStore.State.DISPATCHED) { throw new IllegalStateException("Claim did not dispatch"); }
                Runtime.getRuntime().halt(CLAIM_HALT);
            } else if (mode.equals("signed")) {
                SigningStepExecutor executor = new SigningStepExecutor(store, provider, PkiLocalGateFixture.CALL_TIMEOUT,
                        ignored -> { throw new AssertionError("Child must halt before outer publication"); });
                executor.advance(intent, workflow -> store.claimSignStep(id, workflow.revision(), PkiLocalGateFixture.CLAIM_LEASE),
                        CancellationSignal.NONE, () -> {
                            if (store.getSignWorkflow(id).orElseThrow().state() == SignWorkflowStore.State.SUCCEEDED) {
                                Runtime.getRuntime().halt(SIGNATURE_HALT);
                            }
                        });
            }
            throw new AssertionError("Expected crash checkpoint was not reached");
        }
    }

    private static Path runDirectory(String prefix) throws Exception {
        return PkiLocalGateFixture.privateDirectory(Path.of(System.getProperty("pki.validation.output")), prefix);
    }

    private static Path executable() { return Path.of(System.getProperty("pki.validation.executable")); }
    private static PkiId selected(Path directory) throws Exception { return new PkiId(Files.readString(directory.resolve("operation-id.txt"))); }

    private static Snapshot snapshot(Path configuration, PkiId id) throws Exception {
        try (PkiStore store = PkiBootstrap.openStore(PkiCliConfiguration.read(configuration).store())) {
            return new Snapshot(store.getSignWorkflow(id).orElseThrow(), store.getDomainContinuation(id).orElseThrow(), store.listCas().size());
        }
    }

    private static void assertUnchanged(Snapshot expected, Snapshot actual) {
        assertEquals(expected.evidence(), actual.evidence(), "Inspection must not advance either authoritative record");
    }

    private static String encoded(Optional<EncodedObject> value) {
        return value.map(object -> object.encoding() + ":" + HexFormat.of().formatHex(object.bytes())).orElse("absent");
    }

    private record Snapshot(SignWorkflowStore.Workflow signing, DomainContinuationStore.Record outer, int authorities) {
        String evidence() {
            SignWorkflowStore.MutableState state = signing.mutableState();
            // Include all mutable workflow fields and every outer field; encode arrays by value.
            return List.of(state.operationId(), state.state(), state.revision(), state.fence(), state.leaseUntil(),
                    state.downstreamOperationId(), state.detailCode(), encoded(state.result()), state.providerUpdatedAt(),
                    state.failureCount(), state.nextEligibleAt(), state.reconciliationFailureClass(), state.initialAttemptPhase(),
                    state.stage(), state.proofOutcome(), outer.operationId(), outer.version(), outer.kind(), outer.correlationId(),
                    outer.state(), outer.revision(), outer.createdAt(), outer.deadline(), encoded(Optional.of(outer.command())),
                    outer.commandCommitment(), outer.signingContent(), encoded(outer.result()), outer.detailCode(), authorities).toString();
        }
    }
}
