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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.LocalPkiSessionConfiguration;

class PkiCliTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void helpListsCompletedSafeAdministrationFamilies() {
        System.out.println("helpListsCompletedSafeAdministrationFamilies");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "--help" }, output);
        String help = output.toString(StandardCharsets.UTF_8);
        System.out.println("...helpBytes=" + help.length());
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertTrue(help.contains("profile.register"));
        assertTrue(help.contains("ca.list"));
        assertTrue(help.contains("request.inspect"));
        assertTrue(help.contains("revocation.snapshot"));
        assertTrue(help.contains("inventory.status"));
        assertTrue(help.contains("publication.list"));
        assertTrue(help.contains("ca.create"));
        assertTrue(help.contains("credential.issue"));
        assertTrue(help.contains("status.generate"));
        assertTrue(help.contains("publication.process"));
        System.out.println("...ok");
    }

    @Test
    void unconfiguredSigningFailsAtItsStepAndStopsDependents() throws IOException {
        System.out.println("unconfiguredSigningFailsAtItsStepAndStopsDependents");
        Path configuration = configuration("capability-workflow");
        Path request = temporaryDirectory.resolve("request.der");
        Files.write(request, new byte[] { 0x30, 0x00 });
        Path workflow = plan("capability-workflow.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"first","operation":"configuration.validate","arguments":{}},
                  {"id":"ca","operation":"ca.create","arguments":{"formatId":"x509","subjectRef":"CN=Root","profileId":"root-ca","keyRef":"managed:root.prv"}},
                  {"id":"request","operation":"request.import","arguments":{"formatId":"x509","encoding":"DER","requestFile":"request.der"}},
                  {"id":"issue","operation":"credential.issue","arguments":{"issuerCaId":"${ca.caId}","requestId":"${request.requestId}","profileId":"server"}},
                  {"id":"publish","operation":"publication.register","arguments":{"publicationId":"publication-1","sourceType":"CREDENTIAL","sourceId":"${issue.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
                  {"id":"process","operation":"publication.process","arguments":{"publicationId":"${publish.publicationId}"}}
                ]}
                """);
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "run", workflow.toString(), "--config", configuration.toString(),
                "--output", "json" }, output, opener, () -> false);
        System.out.println("...operations=" + opener.operationTypes.size());
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, code);
        assertEquals(1, opener.sessions.get());
        assertEquals(1, opener.closes.get());
        assertEquals(List.of(PkiOperation.ValidateConfiguration.class), opener.operationTypes);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("CAPABILITY_NOT_CONFIGURED"));
        System.out.println("...ok");
    }

    @Test
    void productionProfileWorkflowUsesTypedOperationsAndDurableStore() throws IOException {
        System.out.println("productionProfileWorkflowUsesTypedOperationsAndDurableStore");
        Path configuration = configuration("profile-workflow");
        BuiltInCertificateProfileTemplate template = BuiltInCertificateProfileCatalog
                .load(getClass().getClassLoader()).get(0);
        Path profile = temporaryDirectory.resolve("profile.json");
        Files.write(profile, template.canonicalJson());
        ByteArrayOutputStream registered = new ByteArrayOutputStream();
        int registerCode = PkiCli.execute(new String[] { "profile.register", "--profile-file", profile.toString(),
                "--config", configuration.toString(), "--output", "json" }, registered);
        ByteArrayOutputStream activated = new ByteArrayOutputStream();
        int activateCode = PkiCli.execute(new String[] { "profile.activate", "--profile-id",
                template.definition().profileId(), "--profile-version",
                Long.toString(template.definition().profileVersion()), "--config", configuration.toString(),
                "--output", "json" }, activated);
        ByteArrayOutputStream inspected = new ByteArrayOutputStream();
        int inspectCode = PkiCli.execute(new String[] { "profile.inspect", "--profile-id",
                template.definition().profileId(), "--profile-version",
                Long.toString(template.definition().profileVersion()), "--config", configuration.toString(),
                "--output", "json" }, inspected);
        String rendered = registered.toString(StandardCharsets.UTF_8)
                + activated.toString(StandardCharsets.UTF_8) + inspected.toString(StandardCharsets.UTF_8);
        System.out.println("...profileId=" + template.definition().profileId());
        assertEquals(PkiExitCodes.SUCCESS, registerCode);
        assertEquals(PkiExitCodes.SUCCESS, activateCode);
        assertEquals(PkiExitCodes.SUCCESS, inspectCode);
        assertTrue(rendered.contains("\"profileVersion\":" + template.definition().profileVersion()));
        assertFalse(rendered.contains("canonicalJson"));
        System.out.println("...ok");
    }

    @Test
    void productionSessionExecutesMachineAndHumanSingleCommands() throws IOException {
        System.out.println("productionSessionExecutesMachineAndHumanSingleCommands");
        Path configuration = configuration("production");
        ByteArrayOutputStream machine = new ByteArrayOutputStream();
        int first = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString(),
                "--output", "json" }, machine);
        ByteArrayOutputStream human = new ByteArrayOutputStream();
        int second = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString() },
                human);
        String json = machine.toString(StandardCharsets.UTF_8);
        System.out.println("...machineBytes=" + json.length());
        assertEquals(0, first);
        assertEquals(0, second);
        assertTrue(json.contains("\"mode\":\"single\""));
        assertTrue(json.contains("\"storeProvider\":\"fs\""));
        assertTrue(human.toString(StandardCharsets.UTF_8).contains("configuration.validate SUCCEEDED"));
        System.out.println("...ok");
    }

    @Test
    void bindingAdministrationUsesDirectAndBatchTypedExecution() throws IOException {
        System.out.println("bindingAdministrationUsesDirectAndBatchTypedExecution");
        Path configuration = configuration("bindings");
        ByteArrayOutputStream listed = new ByteArrayOutputStream();
        int listCode = PkiCli.execute(new String[] { "algorithm.binding.list", "--limit", "64", "--config",
                configuration.toString(), "--output", "json" }, listed);
        String bindingId = "zeroecho.private.sphincs-plus-default.certificate-signature.v1";
        Path workflow = plan("binding-workflow.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"binding","operation":"algorithm.binding.inspect","arguments":{"bindingId":"%s"}},
                  {"id":"validate","operation":"algorithm.binding.validate","arguments":{"bindingId":"${binding.bindingId}","bindingCommitment":"${binding.bindingCommitment}"}}
                ]}
                """.formatted(bindingId));
        ByteArrayOutputStream batch = new ByteArrayOutputStream();
        int batchCode = PkiCli.execute(new String[] { "run", workflow.toString(), "--config",
                configuration.toString(), "--output", "json" }, batch);
        String output = listed.toString(StandardCharsets.UTF_8) + batch.toString(StandardCharsets.UTF_8);
        System.out.println("...outputBytes=" + output.length());
        assertEquals(PkiExitCodes.SUCCESS, listCode);
        assertEquals(PkiExitCodes.SUCCESS, batchCode);
        assertTrue(output.contains("1.3.6.1.4.1.31424.1.1.3"));
        assertTrue(output.contains("ZEROECHO_PRIVATE"));
        assertFalse(output.contains("codecClass"));
        System.out.println("...ok");
    }

    @Test
    void legacyConfigurationsAreRejectedWithoutAdapters() throws IOException {
        for (int version = 1; version <= 6; version++) {
            Path configuration = plan("legacy-" + version + ".json", """
                    {"version":%d,"store":{"provider":"fs","properties":{"root":"store"}},
                    "audit":{"provider":"memory","properties":{"size":"16"}},
                    "publishers":[],"bindingProviders":[]}
                    """.formatted(version));
            assertThrows(IllegalArgumentException.class, () -> PkiCliConfiguration.read(configuration));
        }
    }

    @Test
    void singleAndBatchUseTheSameTypedExecutorAndSessionLifecycle() throws IOException {
        System.out.println("singleAndBatchUseTheSameTypedExecutorAndSessionLifecycle");
        Path configuration = configuration("shared");
        Path plan = plan("shared.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"validate","operation":"configuration.validate","arguments":{}}
                ]}
                """);
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream single = new ByteArrayOutputStream();
        int singleCode = PkiCli.execute(new String[] { "configuration.validate", "--config",
                configuration.toString(), "--output", "json" }, single, opener, () -> false);
        ByteArrayOutputStream batch = new ByteArrayOutputStream();
        int batchCode = PkiCli.execute(new String[] { "run", plan.toString(), "--config", configuration.toString(),
                "--output", "json" }, batch, opener, () -> false);
        System.out.println("...sessions=" + opener.sessions.get());
        assertEquals(0, singleCode);
        assertEquals(0, batchCode);
        assertEquals(List.of(PkiOperation.ValidateConfiguration.class, PkiOperation.ValidateConfiguration.class),
                opener.operationTypes);
        assertEquals(2, opener.sessions.get());
        assertEquals(2, opener.closes.get());
        System.out.println("...ok");
    }

    @Test
    void directMutationUsesTheSharedTypedExecutor() throws IOException {
        System.out.println("directMutationUsesTheSharedTypedExecutor");
        Path configuration = configuration("mutation");
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "credential.revoke", "--credential-id", "credential-1",
                "--reason", "KEY_COMPROMISE", "--justification", "ticket-100", "--config",
                configuration.toString(), "--output", "json" },
                output, opener, () -> false);
        String rendered = output.toString(StandardCharsets.UTF_8);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertEquals(List.of(PkiOperation.RevokeCredential.class), opener.operationTypes);
        assertEquals(java.util.Optional.of("ticket-100"),
                ((PkiOperation.RevokeCredential) opener.operations.get(0)).operatorJustification());
        assertTrue(rendered.contains("\"state\":\"PERMANENTLY_REVOKED\""));
        assertEquals(1, opener.closes.get());
        System.out.println("...ok");
    }

    @Test
    void directSigningRequiresConfiguredCapability() throws IOException {
        System.out.println("directSigningRequiresConfiguredCapability");
        Path configuration = configuration("direct-ca");
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "ca.create", "--format-id", "x509", "--subject-ref",
                "CN=Root", "--profile-id", "root-ca", "--key-ref", "managed:root.prv", "--config",
                configuration.toString(), "--output", "json" }, output, opener, () -> false);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.VALIDATION_OR_POLICY, code);
        assertEquals(1, opener.sessions.get());
        assertEquals(1, opener.closes.get());
        assertTrue(opener.operationTypes.isEmpty());
        System.out.println("...ok");
    }

    @Test
    void resolvesEarlierFieldsAndContinuesOnlyIndependentSteps() throws IOException {
        System.out.println("resolvesEarlierFieldsAndContinuesOnlyIndependentSteps");
        Path configuration = configuration("references");
        Path plan = plan("references.json", """
                {"version":1,"failurePolicy":"CONTINUE_INDEPENDENT","operations":[
                  {"id":"config","operation":"configuration.validate","arguments":{}},
                  {"id":"inspect","operation":"credential.inspect","arguments":{"credentialId":"${config.storeProvider}"}},
                  {"id":"unknown-field","operation":"credential.inspect","arguments":{"credentialId":"${config.absentField}"}},
                  {"id":"missing","operation":"publication.inspect","arguments":{"publicationId":"missing"}},
                  {"id":"independent","operation":"configuration.validate","arguments":{}},
                  {"id":"dependent","operation":"credential.inspect","arguments":{"credentialId":"${missing.sourceId}"}}
                ]}
                """);
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "run", plan.toString(), "--config", configuration.toString(),
                "--output", "json" }, output, opener, () -> false);
        String json = output.toString(StandardCharsets.UTF_8);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.NOT_FOUND_OR_CONFLICT, code);
        assertTrue(json.contains("\"id\":\"independent\",\"operation\":\"configuration.validate\",\"status\":\"SUCCEEDED\""));
        assertTrue(json.contains("\"id\":\"unknown-field\",\"operation\":\"credential.inspect\",\"status\":\"FAILED\""));
        assertTrue(json.contains("\"id\":\"dependent\",\"operation\":\"credential.inspect\",\"status\":\"SKIPPED\""));
        assertEquals(1, opener.sessions.get());
        assertEquals(1, opener.closes.get());
        System.out.println("...ok");
    }

    @Test
    void rejectsFutureReferencesScriptsInterpolationAndSecretArgumentsBeforeOpening() throws IOException {
        System.out.println("rejectsFutureReferencesScriptsInterpolationAndSecretArgumentsBeforeOpening");
        Path configuration = configuration("hostile");
        Path plan = plan("hostile.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"first","operation":"credential.inspect","arguments":{"credentialId":"${later.credentialId}"}},
                  {"id":"later","operation":"configuration.validate","arguments":{}}
                ]}
                """);
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int future = PkiCli.execute(new String[] { "run", plan.toString(), "--config", configuration.toString(),
                "--output", "json" }, output, opener, () -> false);
        int script = PkiCli.execute(new String[] { "java.lang.Runtime", "--config", configuration.toString() },
                new ByteArrayOutputStream(), opener, () -> false);
        int secret = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString(),
                "--password", "do-not-print" }, new ByteArrayOutputStream(), opener, () -> false);
        System.out.println("...rejections=3");
        assertEquals(PkiExitCodes.INVALID_INVOCATION, future);
        assertEquals(PkiExitCodes.INVALID_INVOCATION, script);
        assertEquals(PkiExitCodes.INVALID_INVOCATION, secret);
        assertEquals(0, opener.sessions.get());
        assertFalse(output.toString(StandardCharsets.UTF_8).contains("later.credentialId"));
        System.out.println("...ok");
    }

    @Test
    void failFastCancellationAndCloseFailuresRemainExplicit() throws IOException {
        System.out.println("failFastCancellationAndCloseFailuresRemainExplicit");
        Path configuration = configuration("failures");
        Path plan = plan("fail-fast.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"missing","operation":"publication.inspect","arguments":{"publicationId":"missing"}},
                  {"id":"later","operation":"configuration.validate","arguments":{}}
                ]}
                """);
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream failed = new ByteArrayOutputStream();
        int failFast = PkiCli.execute(new String[] { "run", plan.toString(), "--config", configuration.toString(),
                "--output", "json" }, failed, opener, () -> false);
        ByteArrayOutputStream cancelled = new ByteArrayOutputStream();
        int cancel = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString(),
                "--output", "json" }, cancelled, opener, () -> true);
        opener.failClose = true;
        ByteArrayOutputStream close = new ByteArrayOutputStream();
        int closeCode = PkiCli.execute(new String[] { "configuration.validate", "--config",
                configuration.toString(), "--output", "json" }, close, opener, () -> false);
        System.out.println("...codes=" + failFast + "," + cancel + "," + closeCode);
        assertEquals(PkiExitCodes.NOT_FOUND_OR_CONFLICT, failFast);
        assertTrue(failed.toString(StandardCharsets.UTF_8).contains("\"code\":\"FAIL_FAST\""));
        assertEquals(PkiExitCodes.CANCELLED, cancel);
        assertEquals(PkiExitCodes.RESOURCE_FAILURE, closeCode);
        assertTrue(close.toString(StandardCharsets.UTF_8).contains("SESSION_CLOSE_FAILED"));
        System.out.println("...ok");
    }

    @Test
    void rejectsMalformedConfigurationAndNeverPrintsProviderExceptions() throws IOException {
        System.out.println("rejectsMalformedConfigurationAndNeverPrintsProviderExceptions");
        Path malformed = plan("bad-config.json",
                "{\"version\":1,\"store\":{},\"audit\":{},\"secret\":\"hidden\"}");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int invalid = PkiCli.execute(new String[] { "configuration.validate", "--config", malformed.toString(),
                "--output", "json" }, output, configuration -> {
                    throw new IllegalStateException("/sensitive/path provider-secret");
                }, () -> false);
        Path valid = configuration("provider-failure");
        ByteArrayOutputStream providerOutput = new ByteArrayOutputStream();
        int providerFailure = PkiCli.execute(new String[] { "configuration.validate", "--config", valid.toString(),
                "--output", "json" }, providerOutput, configuration -> {
                    throw new IllegalStateException("/sensitive/path provider-secret");
                }, () -> false);
        String rendered = output.toString(StandardCharsets.UTF_8)
                + providerOutput.toString(StandardCharsets.UTF_8);
        assertEquals(PkiExitCodes.CONFIGURATION_FAILURE, invalid);
        assertEquals(PkiExitCodes.RESOURCE_FAILURE, providerFailure);
        assertFalse(rendered.contains("hidden"));
        assertFalse(rendered.contains("sensitive"));
        assertFalse(rendered.contains("provider-secret"));
        System.out.println("...ok");
    }

    @Test
    void localAuthorityScopeAndOptionLookingValuesAreOperationArguments() throws IOException {
        Path configuration = configuration("scope");
        RecordingOpener opener = new RecordingOpener();
        assertEquals(0, PkiCli.execute(new String[] { "credential.search", "--authority-id", "root", "--limit", "10",
                "--config", configuration.toString() }, new ByteArrayOutputStream(), opener, () -> false));
        assertEquals(new zeroecho.pki.api.PkiId("root"),
                ((PkiOperation.SearchCredentials) opener.operations.get(0)).authorityId());
        assertEquals(0, PkiCli.execute(new String[] { "credential.inspect", "--credential-id", "--url",
                "--config", configuration.toString() }, new ByteArrayOutputStream(), opener, () -> false));
        assertEquals("--url", ((PkiOperation.InspectCredential) opener.operations.get(1)).credentialId().value());
    }

    @Test
    void publicationBatchPreservesCompletedReferencesAndSingleSession() throws IOException {
        Path configuration = configuration("publication");
        Path workflow = plan("publication.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                {"id":"inspect","operation":"credential.inspect","arguments":{"credentialId":"certificate"}},
                {"id":"register","operation":"publication.register","arguments":{"publicationId":"publication",
                "sourceType":"CREDENTIAL","sourceId":"${inspect.credentialId}","targetType":"FILESYSTEM","targetId":"local"}},
                {"id":"process","operation":"publication.process","arguments":{"publicationId":"${register.publicationId}"}}]}
                """);
        RecordingOpener opener = new RecordingOpener();
        assertEquals(0, PkiCli.execute(new String[] { "run", workflow.toString(), "--config", configuration.toString() },
                new ByteArrayOutputStream(), opener, () -> false));
        assertEquals(1, opener.sessions.get());
        assertEquals(1, opener.closes.get());
        assertEquals("certificate", ((PkiOperation.RegisterPublication) opener.operations.get(1)).sourceId().value());
        assertEquals("publication", ((PkiOperation.ProcessPublication) opener.operations.get(2)).publicationId().value());
    }

    @Test
    void signingReceiptsSurviveFailuresCancellationAndSessionClose() throws IOException {
        Path configuration = configuration("signing-receipt");
        RecordingOpener opener = new RecordingOpener();
        SigningExecutor executor = new SigningExecutor();
        opener.signing = executor;
        for (PkiOperationFailure failure : List.of(PkiOperationFailure.RECOVERY_REQUIRED, PkiOperationFailure.CANCELLED,
                PkiOperationFailure.RESOURCE_FAILURE)) {
            executor.failure = failure;
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            int exit = PkiCli.execute(new String[] { "ca.create", "--format-id", "x509", "--subject-ref", "CN=Root",
                    "--profile-id", "root-ca", "--key-ref", "key", "--config", configuration.toString(),
                    "--output", "json" }, output, opener, () -> false);
            assertEquals(failure == PkiOperationFailure.RECOVERY_REQUIRED ? 6
                    : failure == PkiOperationFailure.CANCELLED ? 130 : 8, exit);
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operationId\":\"accepted-id\""));
        }
        executor.failure = null;
        opener.failClose = true;
        ByteArrayOutputStream completed = new ByteArrayOutputStream();
        assertEquals(8, PkiCli.execute(new String[] { "signing.operation.complete", "--operation-id", "accepted-id",
                "--config", configuration.toString(), "--output", "json" }, completed, opener, () -> false));
        String json = completed.toString(StandardCharsets.UTF_8);
        assertTrue(json.contains("SESSION_CLOSE_FAILED"));
        assertTrue(json.contains("\"operationId\":\"accepted-id\""));
        assertTrue(json.contains("\"status\":\"SUCCEEDED\""));
        assertFalse(json.contains("sensitive-close-detail"));
    }

    @Test
    void controlFailuresAndPreStepCancellationRetainRequestedIdentity() throws IOException {
        Path configuration = configuration("control-receipt");
        RecordingOpener opener = new RecordingOpener();
        SigningExecutor executor = new SigningExecutor();
        opener.signing = executor;
        for (String command : List.of(PkiLocalCommand.INSPECT, PkiLocalCommand.COMPLETE)) {
            for (boolean cancelled : List.of(false, true)) {
                executor.throwFailure = true;
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                assertEquals(cancelled ? 130 : 9, PkiCli.execute(new String[] { command, "--operation-id", "requested-id",
                        "--config", configuration.toString(), "--output", "json" }, output, opener, () -> cancelled));
                assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operationId\":\"requested-id\""));
                assertFalse(output.toString(StandardCharsets.UTF_8).contains("sensitive-runtime-detail"));
            }
        }
    }

    @Test
    void signingPlansExposeOnlyCompletedReferencesAndRetainCancelledReferenceIdentity() throws IOException {
        PkiOperationRegistry registry = new PkiOperationRegistry();
        Path workflow = plan("signing-reference.json", """
                {"version":1,"failurePolicy":"CONTINUE_INDEPENDENT","operations":[
                  {"id":"created","operation":"ca.create","arguments":{"formatId":"x509","subjectRef":"CN=Root","profileId":"root-ca","keyRef":"key"}},
                  {"id":"inspect","operation":"signing.operation.inspect","arguments":{"operationId":"${created.operationId}"}},
                  {"id":"read","operation":"configuration.validate","arguments":{}}
                ]}
                """);
        PkiPlan plan = PkiPlanParser.read(workflow, registry.names());
        java.util.concurrent.atomic.AtomicBoolean cancel = new java.util.concurrent.atomic.AtomicBoolean();
        AtomicInteger calls = new AtomicInteger();
        PkiPlanExecution execution = new PkiPlanExecutor(registry).execute(plan, (command, cancellation) -> {
            calls.incrementAndGet();
            cancel.set(true);
            return new PkiLocalResult(new PkiOperationOutcome.Completed(new PkiOperationResult("signing.operation",
                    java.util.Map.of("operationId", new PkiOperationValue.Text("accepted-id")))),
                    java.util.Optional.of(new zeroecho.pki.api.PkiId("accepted-id")));
        }, cancel::get);
        assertEquals(1, calls.get());
        assertEquals("accepted-id", execution.steps().get(1).operationId().orElseThrow().value());
        assertEquals(java.util.Optional.of(PkiOperationFailure.CANCELLED), execution.steps().get(1).failure());
        assertEquals(PkiPlanExecution.StepStatus.SKIPPED, execution.steps().get(2).status());
        execution = new PkiPlanExecutor(registry).execute(plan, (command, cancellation) -> {
            if (command instanceof PkiLocalCommand.Signing) {
                return new PkiLocalResult(new PkiOperationOutcome.Failed("ca.create", PkiOperationFailure.RECOVERY_REQUIRED,
                        "RECOVERY_REQUIRED"), java.util.Optional.of(new zeroecho.pki.api.PkiId("accepted-id")));
            }
            return new PkiLocalResult(new PkiOperationOutcome.Completed(new PkiOperationResult("configuration.validate",
                    java.util.Map.of())), java.util.Optional.empty());
        }, () -> false);
        assertEquals(PkiPlanExecution.StepStatus.SKIPPED, execution.steps().get(1).status());
        assertEquals(PkiPlanExecution.StepStatus.SUCCEEDED, execution.steps().get(2).status());
        assertEquals(6, PkiExitCodes.from(execution));
    }

    private static final class SigningExecutor implements zeroecho.pki.application.LocalSigningExecutor {
        private PkiOperationFailure failure;
        private boolean throwFailure;
        private final zeroecho.pki.api.signing.SigningAcceptanceReceipt receipt =
                zeroecho.pki.api.signing.SigningAcceptanceReceipt.parse(new zeroecho.pki.api.PkiId("accepted-id"),
                        "accept-sign:v3:" + "a".repeat(64));
        @Override public zeroecho.pki.application.LocalSigningResult execute(
                zeroecho.pki.application.PkiSigningOperation operation, zeroecho.core.io.CancellationSignal cancellation) {
            return result();
        }
        @Override public zeroecho.pki.application.LocalSigningResult complete(zeroecho.pki.api.PkiId operationId,
                zeroecho.core.io.CancellationSignal cancellation) { return result(); }
        @Override public PkiOperationOutcome inspect(zeroecho.pki.api.PkiId operationId,
                zeroecho.core.io.CancellationSignal cancellation) {
            throw new IllegalStateException("sensitive-runtime-detail");
        }
        private zeroecho.pki.application.LocalSigningResult result() {
            if (throwFailure) throw new IllegalStateException("sensitive-runtime-detail");
            if (failure != null) return new zeroecho.pki.application.LocalSigningResult.Failed(
                    new PkiOperationOutcome.Failed("signing.operation", failure, failure.name()), java.util.Optional.of(receipt));
            return new zeroecho.pki.application.LocalSigningResult.Completed(new PkiOperationResult("signing.operation",
                    java.util.Map.of("credentialId", new PkiOperationValue.Text("credential"))), receipt);
        }
    }

    private Path configuration(String name) throws IOException {
        Path store = temporaryDirectory.resolve(name + "-store");
        String storePath = store.toString().replace("\\", "/");
        return plan(name + "-config.json", "{\"version\":1,\"mode\":\"local\",\"operatorId\":\"test-operator\",\"publishers\":[],\"bindingProviders\":[],\"store\":{\"provider\":\"fs\",\"properties\":{\"root\":\""
                + storePath + "\"}},\"audit\":{\"provider\":\"memory\",\"properties\":{\"size\":\"32\"}}}");
    }

    private Path plan(String name, String content) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        Files.writeString(path, content, StandardCharsets.UTF_8);
        return path;
    }

    @Test
    void localPendingWaitIsRejectedBeforeOpening() throws IOException {
        System.out.println("localPendingWaitIsRejectedBeforeOpening");
        Path configuration = configuration("pending-resolve");
        PendingOpener opener = new PendingOpener(2);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString(),
                "--pending-wait", "5", "--output", "json" }, output, opener, () -> false);
        System.out.println("...executions=" + opener.executions.get() + " code=" + code);
        assertEquals(PkiExitCodes.INVALID_INVOCATION, code);
        assertEquals(0, opener.executions.get());
        System.out.println("...ok");
    }

    @Test
    void unexpectedPendingOutcomeNeverResubmits() throws IOException {
        System.out.println("unexpectedPendingOutcomeNeverResubmits");
        Path configuration = configuration("pending-exit");
        PendingOpener opener = new PendingOpener(Integer.MAX_VALUE);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "configuration.validate", "--config", configuration.toString(),
                "--output", "json" }, output, opener, () -> false);
        System.out.println("...executions=" + opener.executions.get() + " code=" + code);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operationId\":\"signing:pending-1\""));
        // An unexpected pending core result must not cause mutation resubmission.
        assertEquals(PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN, code);
        assertEquals(1, opener.executions.get());
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("OPERATION_PENDING"));
        System.out.println("...ok");
    }

    /** Opener whose session returns Pending for the first N operation executions, then Completed. */
    private static final class PendingOpener implements PkiCli.SessionOpener {
        private final int pendingExecutions;
        private final AtomicInteger executions = new AtomicInteger();

        private PendingOpener(int pendingExecutions) {
            this.pendingExecutions = pendingExecutions;
        }

        @Override
        public PkiSession open(LocalPkiSessionConfiguration configuration) {
            return new PkiSession() {
                @Override public ProfileService profiles() { throw new UnsupportedOperationException(); }
                @Override public RevocationService revocations() { throw new UnsupportedOperationException(); }
                @Override public zeroecho.pki.api.confirmation.CredentialConfirmationService confirmations() {
                    throw new UnsupportedOperationException();
                }
                @Override public zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry algorithmBindings() {
                    throw new UnsupportedOperationException();
                }
                @Override public zeroecho.pki.application.PkiOperationExecutor operations() {
                    return (operation, cancellation) -> {
                        if (executions.incrementAndGet() <= pendingExecutions) {
                            return new PkiOperationOutcome.Pending(operation.name(),
                                    new zeroecho.pki.api.PkiId("signing:pending-1"));
                        }
                        return new PkiOperationOutcome.Completed(new PkiOperationResult(operation.name(),
                                new LinkedHashMap<>()));
                    };
                }
                @Override public zeroecho.pki.application.PkiRepository repository() {
                    throw new UnsupportedOperationException();
                }
                @Override public zeroecho.pki.api.credential.EffectiveCredentialStatusResolver credentialStatuses() {
                    throw new UnsupportedOperationException();
                }
                @Override public void close() { }
            };
        }
    }

    private static final class RecordingOpener implements PkiCli.SessionOpener {
        private final AtomicInteger sessions = new AtomicInteger();
        private final AtomicInteger closes = new AtomicInteger();
        private final List<Class<?>> operationTypes = new java.util.ArrayList<>();
        private final List<PkiOperation> operations = new java.util.ArrayList<>();
        private boolean failClose;
        private zeroecho.pki.application.LocalSigningExecutor signing;

        @Override
        public PkiSession open(LocalPkiSessionConfiguration configuration) {
            sessions.incrementAndGet();
            return new PkiSession() {
                @Override
                public java.util.Optional<zeroecho.pki.application.LocalSigningExecutor> localSigning() {
                    return java.util.Optional.ofNullable(signing);
                }

                @Override
                public ProfileService profiles() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public RevocationService revocations() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public zeroecho.pki.api.confirmation.CredentialConfirmationService confirmations() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry algorithmBindings() {
                    return new zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry() {
                        @Override
                        public java.util.List<zeroecho.pki.api.algorithm.X509AlgorithmBinding> bindings() {
                            return java.util.List.of();
                        }

                        @Override
                        public java.util.Optional<zeroecho.pki.api.algorithm.X509AlgorithmBinding> find(
                                String bindingId) {
                            return java.util.Optional.empty();
                        }

                        @Override
                        public java.util.Optional<zeroecho.pki.api.algorithm.X509AlgorithmBinding> standard(
                                zeroecho.core.spec.AlgorithmIdentity identity,
                                zeroecho.pki.api.algorithm.X509AlgorithmBinding.Role role) {
                            return java.util.Optional.empty();
                        }

                        @Override
                        public String commitment() {
                            return "test-registry";
                        }

                        @Override
                        public zeroecho.pki.api.algorithm.X509AlgorithmBinding require(String bindingId,
                                String expectedCommitment) {
                            throw new IllegalArgumentException("inactive test binding");
                        }
                    };
                }

                @Override
                public zeroecho.pki.application.PkiOperationExecutor operations() {
                    return (operation, cancellation) -> outcome(operation);
                }

                @Override
                public zeroecho.pki.application.PkiRepository repository() {
                    throw new UnsupportedOperationException();
                }
                @Override public zeroecho.pki.api.credential.EffectiveCredentialStatusResolver credentialStatuses() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void close() throws IOException {
                    closes.incrementAndGet();
                    if (failClose) {
                        throw new IOException("sensitive-close-detail");
                    }
                }
            };
        }

        private PkiOperationOutcome outcome(PkiOperation operation) {
            operationTypes.add(operation.getClass());
            operations.add(operation);
            if (operation instanceof PkiOperation.InspectPublication) {
                return new PkiOperationOutcome.Failed(operation.name(), PkiOperationFailure.NOT_FOUND,
                        "OBJECT_NOT_FOUND");
            }
            LinkedHashMap<String, PkiOperationValue> fields = new LinkedHashMap<>();
            if (operation instanceof PkiOperation.ValidateConfiguration) {
                fields.put("version", new PkiOperationValue.IntegerValue(1));
                fields.put("storeProvider", new PkiOperationValue.Text("fs"));
            } else if (operation instanceof PkiOperation.InspectCredential inspect) {
                fields.put("credentialId", new PkiOperationValue.Text(inspect.credentialId().value()));
            } else if (operation instanceof PkiOperation.RevokeCredential revoke) {
                fields.put("credentialId", new PkiOperationValue.Text(revoke.credentialId().value()));
                fields.put("state", new PkiOperationValue.Text("PERMANENTLY_REVOKED"));

            } else if (operation instanceof PkiOperation.ImportRequest) {
                fields.put("requestId", new PkiOperationValue.Text("request-1"));

            } else if (operation instanceof PkiOperation.RegisterPublication register) {
                fields.put("publicationId", new PkiOperationValue.Text(register.publicationId().value()));
            } else if (operation instanceof PkiOperation.ProcessPublication process) {
                fields.put("publicationId", new PkiOperationValue.Text(process.publicationId().value()));
                fields.put("status", new PkiOperationValue.Text("SUCCEEDED"));
            } else {
                fields.put("status", new PkiOperationValue.Text("OK"));
            }
            return new PkiOperationOutcome.Completed(new PkiOperationResult(operation.name(), fields));
        }
    }
}
