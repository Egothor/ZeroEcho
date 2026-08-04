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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
import zeroecho.pki.application.PkiSessionConfiguration;

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
    void signingAndPublicationFamiliesUseOneTypedBatchSession() throws IOException {
        System.out.println("signingAndPublicationFamiliesUseOneTypedBatchSession");
        Path configuration = configuration("capability-workflow");
        Path request = temporaryDirectory.resolve("request.der");
        Files.write(request, new byte[] { 0x30, 0x00 });
        Path workflow = plan("capability-workflow.json", """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
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
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertEquals(1, opener.sessions.get());
        assertEquals(List.of(PkiOperation.CreateAuthority.class, PkiOperation.ImportRequest.class,
                PkiOperation.IssueCredential.class, PkiOperation.RegisterPublication.class,
                PkiOperation.ProcessPublication.class), opener.operationTypes);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"operation\":\"publication.process\""));
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
    void versionTwoConfigurationKeepsCapabilitiesExplicit() throws IOException {
        System.out.println("versionTwoConfigurationKeepsCapabilitiesExplicit");
        Path configuration = temporaryDirectory.resolve("capabilities.json");
        Files.writeString(configuration, """
                {"version":2,
                 "store":{"provider":"fs","properties":{"root":"store"}},
                 "audit":{"provider":"memory","properties":{"size":"16"}},
                 "signing":{"workflow":{"provider":"zeroecho-lib","properties":{"keyringPath":"keys.zek","operationRoot":"signing-operations"}},
                            "framework":{"provider":"x509-bc","properties":{}},
                            "busPath":"signing-bus","signatureAlgorithm":"SHA256withRSA","signingTtlSeconds":30,
                            "unlockEnvironmentVariable":"ZEROECHO_TEST_UNLOCK"},
                 "publishers":[{"provider":"filesystem","properties":{"root":"published","targetId":"local"}}]}
                """);
        PkiSessionConfiguration parsed = PkiCliConfiguration.read(configuration);
        System.out.println("...publishers=" + parsed.publishers().size());
        assertTrue(parsed.signing().isPresent());
        assertEquals(1, parsed.publishers().size());
        System.out.println("...ok");
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
                "--reason", "KEY_COMPROMISE", "--config", configuration.toString(), "--output", "json" },
                output, opener, () -> false);
        String rendered = output.toString(StandardCharsets.UTF_8);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertEquals(List.of(PkiOperation.RevokeCredential.class), opener.operationTypes);
        assertTrue(rendered.contains("\"state\":\"PERMANENTLY_REVOKED\""));
        assertEquals(1, opener.closes.get());
        System.out.println("...ok");
    }

    @Test
    void directSigningDependentCommandUsesTheSharedTypedExecutor() throws IOException {
        System.out.println("directSigningDependentCommandUsesTheSharedTypedExecutor");
        Path configuration = configuration("direct-ca");
        RecordingOpener opener = new RecordingOpener();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int code = PkiCli.execute(new String[] { "ca.create", "--format-id", "x509", "--subject-ref",
                "CN=Root", "--profile-id", "root-ca", "--key-ref", "managed:root.prv", "--config",
                configuration.toString(), "--output", "json" }, output, opener, () -> false);
        System.out.println("...exit=" + code);
        assertEquals(PkiExitCodes.SUCCESS, code);
        assertEquals(List.of(PkiOperation.CreateAuthority.class), opener.operationTypes);
        assertTrue(output.toString(StandardCharsets.UTF_8).contains("\"caId\":\"ca-1\""));
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

    private Path configuration(String name) throws IOException {
        Path store = temporaryDirectory.resolve(name + "-store");
        return plan(name + "-config.json", "{\"version\":1,\"store\":{\"provider\":\"fs\",\"properties\":{\"root\":\""
                + store + "\"}},\"audit\":{\"provider\":\"memory\",\"properties\":{\"size\":\"32\"}}}");
    }

    private Path plan(String name, String content) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        Files.writeString(path, content, StandardCharsets.UTF_8);
        return path;
    }

    private static final class RecordingOpener implements PkiCli.SessionOpener {
        private final AtomicInteger sessions = new AtomicInteger();
        private final AtomicInteger closes = new AtomicInteger();
        private final List<Class<?>> operationTypes = new java.util.ArrayList<>();
        private boolean failClose;

        @Override
        public PkiSession open(PkiSessionConfiguration configuration) {
            sessions.incrementAndGet();
            return new PkiSession() {
                @Override
                public ProfileService profiles() {
                    throw new UnsupportedOperationException();
                }

                @Override
                public RevocationService revocations() {
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
                public void close() throws Exception {
                    closes.incrementAndGet();
                    if (failClose) {
                        throw new IOException("sensitive-close-detail");
                    }
                }
            };
        }

        private PkiOperationOutcome outcome(PkiOperation operation) {
            operationTypes.add(operation.getClass());
            if (operation instanceof PkiOperation.InspectPublication) {
                return new PkiOperationOutcome.Failure(operation.name(), PkiOperationFailure.NOT_FOUND,
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
            } else if (operation instanceof PkiOperation.CreateAuthority) {
                fields.put("caId", new PkiOperationValue.Text("ca-1"));
            } else if (operation instanceof PkiOperation.ImportRequest) {
                fields.put("requestId", new PkiOperationValue.Text("request-1"));
            } else if (operation instanceof PkiOperation.IssueCredential) {
                fields.put("credentialId", new PkiOperationValue.Text("credential-1"));
            } else if (operation instanceof PkiOperation.RegisterPublication register) {
                fields.put("publicationId", new PkiOperationValue.Text(register.publicationId().value()));
            } else if (operation instanceof PkiOperation.ProcessPublication process) {
                fields.put("publicationId", new PkiOperationValue.Text(process.publicationId().value()));
                fields.put("status", new PkiOperationValue.Text("SUCCEEDED"));
            } else {
                fields.put("status", new PkiOperationValue.Text("OK"));
            }
            return new PkiOperationOutcome.Success(new PkiOperationResult(operation.name(), fields));
        }
    }
}
