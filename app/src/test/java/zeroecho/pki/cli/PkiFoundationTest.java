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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.LocalPkiSessionConfiguration;
import zeroecho.pki.application.LocalSigningConfiguration;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSigningOperation;

class PkiFoundationTest {
    private static final String CONFIGURATION = """
            {"version":1,"mode":"local","operatorId":"local-admin",
            "store":{"provider":"fs","properties":{"root":"store"}},
            "audit":{"provider":"memory","properties":{"size":"16"}},
            "publishers":[],"bindingProviders":[]%s}
            """;
    private static final String SIGNING = """
            ,"signing":{"provider":{"provider":"zeroecho-lib","properties":{"keyringPath":"keys.zek"}},
            "signatureAlgorithm":"SHA256withRSA","signingTtlSeconds":30,
            "claimLeaseMillis":5000,"providerCallTimeoutMillis":1000,
            "unlockEnvironmentVariable":"PKI_UNLOCK","pureEdDsaMaximumTbsBytes":65536}
            """;
    @TempDir Path temporaryDirectory;

    @Test
    void localConfigurationCarriesIdentityAndExactFiniteSigningBounds() throws IOException {
        LocalPkiSessionConfiguration unsigned = read(CONFIGURATION.formatted(""));
        assertEquals("local-admin", unsigned.operatorId());
        assertTrue(unsigned.signing().isEmpty());
        assertTrue(unsigned.publishers().isEmpty());
        LocalSigningConfiguration signing = read(CONFIGURATION.formatted(SIGNING)).signing().orElseThrow();
        assertEquals("zeroecho-lib", signing.provider().backendId());
        assertEquals(Duration.ofSeconds(30), signing.signingTtl());
        assertEquals(Duration.ofMillis(5000), signing.claimLease());
        assertEquals(Duration.ofMillis(1000), signing.providerCallTimeout());
        assertEquals(Optional.of("PKI_UNLOCK"), signing.unlockEnvironmentVariable());
        assertEquals(65536, signing.pureEdDsaMaximumTbsBytes().orElseThrow());
    }

    @Test
    void localConfigurationRejectsUnknownDuplicateMissingAndInvalidFields() throws IOException {
        String valid = CONFIGURATION.formatted(SIGNING);
        List<String> invalid = List.of(
                valid.replace("\"mode\":\"local\"", "\"mode\":\"remote\""),
                valid.replace("\"operatorId\":\"local-admin\"", "\"operatorId\":\" \""),
                valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
                valid.replace("\"mode\":\"local\",", ""),
                valid.replace("\"publishers\":[],", ""),
                valid.replace("\"bindingProviders\":[]", "\"bindingProviders\":[],\"extra\":true"),
                valid.replace("\"provider\":\"memory\"", "\"provider\":\"stdout\""),
                valid.replace("zeroecho-lib", "zeroecho-remote"),
                valid.replace("\"claimLeaseMillis\":5000", "\"claimLeaseMillis\":1000"),
                valid.replace("\"providerCallTimeoutMillis\":1000", "\"providerCallTimeoutMillis\":0"),
                valid.replace("\"signingTtlSeconds\":30", "\"signingTtlSeconds\":0"),
                valid.replace("\"signingTtlSeconds\":30", "\"signingTtlSeconds\":1.5"),
                valid.replace("\"pureEdDsaMaximumTbsBytes\":65536", "\"pureEdDsaMaximumTbsBytes\":0"),
                valid.replace("\"signatureAlgorithm\":", "\"queueCapacity\":4,\"signatureAlgorithm\":"),
                valid.replace("\"PKI_UNLOCK\"", "\"secret=value\""));
        for (String document : invalid) {
            Path path = write(document);
            assertThrows(IllegalArgumentException.class, () -> PkiCliConfiguration.read(path));
        }
        Path oversized = write(" ".repeat(PkiCliJson.MAXIMUM_DOCUMENT_BYTES + 1));
        assertThrows(IOException.class, () -> PkiCliConfiguration.read(oversized));
        Path link = temporaryDirectory.resolve("config-link.json");
        try {
            Files.createSymbolicLink(link, write(valid));
            assertThrows(IOException.class, () -> PkiCliConfiguration.read(link));
        } catch (java.nio.file.FileSystemException e) {
            assumeTrue(false, "Symlink creation not supported on this platform: " + e.getMessage());
        }
    }

    @Test
    void catalogMatchesEveryCurrentCoreAndSharedSigningOperation() throws ReflectiveOperationException {
        Set<String> expected = new HashSet<>(Set.of(PkiLocalCommand.INSPECT, PkiLocalCommand.COMPLETE));
        for (Class<?> type : PkiOperation.class.getPermittedSubclasses()) {
            expected.add((String) type.getField("NAME").get(null));
        }
        for (Class<?> type : PkiSigningOperation.class.getPermittedSubclasses()) {
            expected.add((String) type.getField("NAME").get(null));
        }
        assertEquals(expected, new PkiOperationRegistry().names());
    }

    @Test
    void allTenSigningBindingsUseSharedValidatedCommands() throws IOException {
        Map<String, String> cases = Map.of(
                "ca.create", "{\"formatId\":\"x509\",\"subjectRef\":\"CN=Root\",\"profileId\":\"root-ca\",\"keyRef\":\"fixture:root.prv\"}",
                "ca.intermediate.create", "{\"formatId\":\"x509\",\"issuerCaId\":\"root\",\"subjectRef\":\"CN=Intermediate\",\"profileId\":\"intermediate-ca\",\"keyRef\":\"fixture:intermediate.prv\"}",
                "ca.intermediate.issue", "{\"formatId\":\"x509\",\"issuerCaId\":\"root\",\"subjectCaId\":\"intermediate\",\"profileId\":\"intermediate-ca\"}",
                "ca.rollover", "{\"caId\":\"root\"}",
                "ca.rotate", "{\"caId\":\"root\",\"newKeyRef\":\"fixture:replacement.prv\"}",
                "credential.issue", "{\"issuerCaId\":\"root\",\"requestId\":\"csr\",\"profileId\":\"tls-server\"}",
                "credential.renew", "{\"credentialId\":\"certificate\"}",
                "credential.replace", "{\"existingCredentialId\":\"certificate\",\"requestId\":\"csr\",\"profileId\":\"tls-server\"}",
                "credential.reissue", "{\"credentialId\":\"certificate\"}",
                "status.generate", "{\"issuerCaId\":\"root\",\"type\":\"CRL\",\"formatId\":\"x509\"}");
        PkiOperationRegistry registry = new PkiOperationRegistry();
        for (Map.Entry<String, String> item : cases.entrySet()) {
            PkiLocalCommand.Signing bound = assertInstanceOf(PkiLocalCommand.Signing.class,
                    registry.bind(item.getKey(), arguments(item.getValue()), temporaryDirectory));
            assertEquals(item.getKey(), bound.operation().name());
            assertTrue(registry.executable(item.getKey()));
        }
    }

    @Test
    void currentCoreFieldsAndConfirmationCasRemainTyped() throws IOException {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        PkiOperation.SearchCredentials search = assertInstanceOf(PkiOperation.SearchCredentials.class,
                core(registry.bind("credential.search", arguments("""
                        {"authorityId":"root","limit":20,"after":"certificate","sanFilter":"DNS_NAME:API.EXAMPLE.TEST"}
                        """), temporaryDirectory)));
        assertEquals(new PkiId("root"), search.authorityId());
        assertEquals(Optional.of("certificate"), search.after());
        assertEquals(Optional.of("DNS_NAME:API.EXAMPLE.TEST"), search.sanFilter());
        String commitment = "a".repeat(64);
        PkiOperation.CompleteCredentialConfirmationProof proof = assertInstanceOf(
                PkiOperation.CompleteCredentialConfirmationProof.class,
                core(registry.bind("credential.confirmation.proof.complete", arguments("""
                        {"credentialId":"credential","expectedLifecycleRevision":1,
                        "expectedLifecycleRecordCommitment":"%s","expectedChallengeRecordCommitment":"%s",
                        "response":"AQ"}
                        """.formatted(commitment, commitment)), temporaryDirectory)));
        assertEquals(1, proof.submission().proofCas().expectedLifecycleRevision());
        assertEquals(commitment, proof.submission().proofCas().expectedLifecycleRecordCommitment());
        assertEquals(commitment, proof.submission().proofCas().expectedChallengeRecordCommitment());
        assertEquals(1, proof.submission().response()[0]);
        assertThrows(IllegalArgumentException.class, () -> registry.bind("credential.confirmation.proof.complete",
                arguments("""
                        {"credentialId":"credential","expectedLifecycleRevision":7,
                        "expectedLifecycleRecordCommitment":"%s","expectedChallengeRecordCommitment":"%s",
                        "response":"AQ"}
                        """.formatted(commitment, commitment)), temporaryDirectory));
        for (String invalidResponse : List.of("AQ==", "AR", "AQ+", "AQ/", " ", "A".repeat(21_847))) {
            assertThrows(IllegalArgumentException.class, () -> registry.bind("credential.confirmation.proof.complete",
                    arguments("""
                            {"credentialId":"credential","expectedLifecycleRevision":1,
                            "expectedLifecycleRecordCommitment":"%s","expectedChallengeRecordCommitment":"%s",
                            "response":"%s"}
                            """.formatted(commitment, commitment, invalidResponse)), temporaryDirectory));
        }
        assertThrows(IllegalArgumentException.class, () -> registry.bind("credential.confirmation.pending.list",
                arguments("{\"authorityId\":\"root\",\"limit\":10,\"cutoffInclusive\":\"invalid\"}"), temporaryDirectory));

    }

    @Test
    void controlsAcceptExactlyOneIdentityAndRequireSigningCapability() throws IOException {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        String storePath = temporaryDirectory.resolve("store").toString().replace("\\", "/");
        Path config = write(CONFIGURATION.formatted("").replace("\"root\":\"store\"",
                "\"root\":\"" + storePath + "\""));
        for (String command : List.of(PkiLocalCommand.INSPECT, PkiLocalCommand.COMPLETE)) {
            PkiLocalCommand bound = registry.bind(command, arguments("{\"operationId\":\"signing-id\"}"), temporaryDirectory);
            assertTrue(bound instanceof PkiLocalCommand.Inspect || bound instanceof PkiLocalCommand.Complete);
            assertThrows(IllegalArgumentException.class, () -> registry.bind(command,
                    arguments("{\"operationId\":\"signing-id\",\"limit\":1}"), temporaryDirectory));
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            assertEquals(4, PkiCli.execute(new String[] { command, "--operation-id", "signing-id", "--config",
                    config.toString(), "--output", "json" }, output,
                    configuration -> zeroecho.pki.application.PkiSession.openLocal(configuration,
                            zeroecho.pki.application.PkiSessionRuntimeDependencies.none()), () -> false));
            assertTrue(output.toString(StandardCharsets.UTF_8).startsWith("{"));
        }
    }

    @Test
    void receiptOutputDoesNotInventDomainCompletion() throws IOException {
        PkiPlanExecution.StepResult step = PkiPlanExecution.StepResult.failure("command", "ca.create",
                PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED").withOperationId(new PkiId("signing-id"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new PkiOutputRenderer().render(new PkiPlanExecution(List.of(step)), PkiOutputMode.JSON, false, output);
        String json = output.toString(StandardCharsets.UTF_8);
        assertTrue(json.contains("\"version\":1"));
        assertTrue(json.contains("\"operationId\":\"signing-id\""));
        assertFalse(json.contains("SUCCEEDED"));
        assertFalse(json.contains("\"output\""));
        assertEquals(6, PkiExitCodes.from(new PkiPlanExecution(List.of(step))));
    }

    @Test
    void ordinaryLocalPendingTransportIsCalledExactlyOnce() throws IOException {
        PkiPlan plan = new PkiPlan(1, PkiPlan.FailurePolicy.FAIL_FAST,
                List.of(new PkiPlan.Step("command", "configuration.validate", arguments("{}"))), temporaryDirectory);
        AtomicInteger calls = new AtomicInteger();
        PkiPlanExecution execution = new PkiPlanExecutor(new PkiOperationRegistry()).execute(plan,
                (operation, cancellation) -> {
                    calls.incrementAndGet();
                    return new PkiLocalResult(new zeroecho.pki.application.PkiOperationOutcome.Pending(
                            "configuration.validate", new PkiId("id")), java.util.Optional.empty());
                }, () -> false);
        assertEquals(1, calls.get());
        assertEquals(7, PkiExitCodes.from(execution));
    }

    private static PkiOperation core(PkiLocalCommand command) {
        return assertInstanceOf(PkiLocalCommand.Core.class, command).operation();
    }
    private static PkiOperationValue.ObjectValue arguments(String json) {
        return PkiCliConfiguration.object(PkiCliJson.parse(json.getBytes(StandardCharsets.UTF_8)));
    }
    private LocalPkiSessionConfiguration read(String document) throws IOException {
        return PkiCliConfiguration.read(write(document));
    }
    private Path write(String document) throws IOException {
        Path path = Files.createTempFile(temporaryDirectory, "config-", ".json");
        Files.writeString(path, document);
        return path;
    }
}
