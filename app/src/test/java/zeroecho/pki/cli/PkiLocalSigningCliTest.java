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

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.application.PkiSigningOperation;

class PkiLocalSigningCliTest {
    private static final String ENVIRONMENT = "ZEROECHO_LOCAL_SIGNING_TEST_UNLOCK";
    private static final String PASSWORD = "local-signing-fixture-unlock";
    @TempDir Path directory;

    @Test
    void publicDispatcherCompletesRealKeyringCaLifecycleAndCrlPlan() throws Exception {
        Path configuration = fixture();
        Path plan = directory.resolve("bootstrap.json");
        Files.writeString(plan, """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"root-profile","operation":"profile.register","arguments":{"profileFile":"root-ca.json"}},
                  {"id":"root-active","operation":"profile.activate","arguments":{"profileId":"root-ca","profileVersion":1}},
                  {"id":"child-profile","operation":"profile.register","arguments":{"profileFile":"intermediate-ca.json"}},
                  {"id":"child-active","operation":"profile.activate","arguments":{"profileId":"intermediate-ca","profileVersion":1}},
                  {"id":"root","operation":"ca.create","arguments":{"formatId":"x509","subjectRef":"CN=CLI Root","profileId":"root-ca","keyRef":"zeroecho-lib:root.prv"}},
                  {"id":"certificate","operation":"credential.inspect","arguments":{"credentialId":"${root.credentialId}"}},
                  {"id":"rollover","operation":"ca.rollover","arguments":{"caId":"${certificate.authorityId}"}},
                  {"id":"rotate","operation":"ca.rotate","arguments":{"caId":"${certificate.authorityId}","newKeyRef":"zeroecho-lib:rotated.prv"}},
                  {"id":"inspect","operation":"signing.operation.inspect","arguments":{"operationId":"${root.operationId}"}}
                ]}
                """);
        Result result = invoke(configuration, PASSWORD, "run", plan.toString());
        assertEquals(0, result.exit(), result.output());
        PkiOperationValue.ObjectValue root = step(result, "root");
        String operationId = text(root, "operationId");
        assertTrue(object(root, "output").fields().containsKey("credentialId"));
        assertEquals("COMPLETED", text(object(step(result, "inspect"), "output"), "state"));
        Result completed = invoke(configuration, PASSWORD, "signing.operation.complete", "--operation-id", operationId);
        assertEquals(0, completed.exit(), completed.output());
        assertEquals(operationId, text(firstStep(completed), "operationId"));
        assertEquals(object(root, "output").fields(), object(firstStep(completed), "output").fields());
        String authority = text(object(step(result, "certificate"), "output"), "authorityId");
        Result current = invoke(configuration, PASSWORD, "credential.inspect", "--credential-id",
                text(object(step(result, "rotate"), "output"), "credentialId"));
        assertEquals(0, current.exit(), current.output());
        java.time.Instant validFrom = java.time.Instant.parse(text(object(firstStep(current), "output"), "notBefore"));
        java.time.Duration remaining = java.time.Duration.between(java.time.Instant.now(), validFrom);
        assertTrue(remaining.compareTo(java.time.Duration.ofSeconds(2)) < 0);
        // Issuer validity is rounded inward to whole seconds; do not race its notBefore.
        if (remaining.isPositive()) Thread.sleep(remaining);
        Path subordinatePlan = directory.resolve("subordinate.json");
        Files.writeString(subordinatePlan, """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"issuer","operation":"credential.inspect","arguments":{"credentialId":"%s"}},
                  {"id":"child","operation":"ca.intermediate.create","arguments":{"formatId":"x509","issuerCaId":"${issuer.authorityId}","subjectRef":"CN=CLI Child","profileId":"intermediate-ca","keyRef":"zeroecho-lib:child.prv"}},
                  {"id":"crl","operation":"status.generate","arguments":{"issuerCaId":"${issuer.authorityId}","type":"CRL","formatId":"x509"}},
                  {"id":"delta","operation":"status.generate","arguments":{"issuerCaId":"${issuer.authorityId}","type":"DELTA_CRL","formatId":"x509"}}
                ]}
                """.formatted(text(object(step(result, "rotate"), "output"), "credentialId")));
        Result subordinate = invoke(configuration, PASSWORD, "run", subordinatePlan.toString());
        assertEquals(0, subordinate.exit(), subordinate.output());
        assertTrue(object(step(subordinate, "crl"), "output").fields().containsKey("statusObjectId"));
        Result authorities = invoke(configuration, PASSWORD, "ca.list", "--limit", "10");
        assertEquals(0, authorities.exit(), authorities.output());
        List<PkiOperationValue> rows = ((PkiOperationValue.ListValue) object(firstStep(authorities), "output")
                .fields().get("authorities")).values();
        String child = rows.stream().map(PkiCliConfiguration::object)
                .filter(row -> text(row, "kind").equals("INTERMEDIATE"))
                .map(row -> text(row, "caId")).findFirst().orElseThrow();
        Result intermediate = invoke(configuration, PASSWORD, "ca.intermediate.issue", "--format-id", "x509",
                "--issuer-ca-id", authority, "--subject-ca-id", child, "--profile-id", "intermediate-ca");
        assertEquals(0, intermediate.exit(), intermediate.output());
        Path lifecycle = directory.resolve("credentials.json");
        Files.writeString(lifecycle, """
                {"version":1,"failurePolicy":"FAIL_FAST","operations":[
                  {"id":"profile","operation":"profile.register","arguments":{"profileFile":"vpn-client.json"}},
                  {"id":"active","operation":"profile.activate","arguments":{"profileId":"vpn-client","profileVersion":1}},
                  {"id":"request","operation":"request.import","arguments":{"formatId":"x509","encoding":"DER","requestFile":"request.der"}},
                  {"id":"issue","operation":"credential.issue","arguments":{"issuerCaId":"%s","requestId":"${request.requestId}","profileId":"vpn-client"}},
                  {"id":"renew","operation":"credential.renew","arguments":{"credentialId":"${issue.credentialId}"}},
                  {"id":"reissue","operation":"credential.reissue","arguments":{"credentialId":"${issue.credentialId}"}},
                  {"id":"replace","operation":"credential.replace","arguments":{"existingCredentialId":"${reissue.credentialId}","requestId":"${request.requestId}","profileId":"vpn-client"}}
                ]}
                """.formatted(authority));
        Result credentials = invoke(configuration, PASSWORD, "run", lifecycle.toString());
        assertEquals(0, credentials.exit(), credentials.output());
        for (String id : List.of("issue", "renew", "reissue", "replace")) {
            assertTrue(object(step(credentials, id), "output").fields().containsKey("credentialId"));
            assertTrue(step(credentials, id).fields().containsKey("operationId"));
        }
        String missingId = zeroecho.pki.api.orch.SigningSubmissionId.create(
                zeroecho.pki.api.orch.SigningSubmissionId.parse(new PkiId(operationId)).namespace(),
                java.time.Instant.now(), new java.security.SecureRandom()).id().value();
        Result missing = invoke(configuration, PASSWORD, "signing.operation.complete", "--operation-id", missingId);
        assertEquals(5, missing.exit(), missing.output());
        assertEquals(missingId, text(firstStep(missing), "operationId"));
    }

    @Test
    void publicInspectionLeavesAcceptedWorkPendingUntilExplicitCompletionAfterReopen() throws Exception {
        Path configuration = fixture();
        PkiId selected;
        PkiId unrelated;
        try (PkiSession session = PkiSession.openLocal(PkiCliConfiguration.read(configuration), dependencies())) {
            session.profiles().importProfile(Files.readAllBytes(directory.resolve("root-ca.json")));
            session.profiles().activateProfile("root-ca", 1);
            selected = accept(session, "root", "CN=Selected");
            unrelated = accept(session, "child", "CN=Unrelated");
        }
        Result inspected = invoke(configuration, PASSWORD, "signing.operation.inspect", "--operation-id", selected.value());
        assertEquals(0, inspected.exit(), inspected.output());
        assertEquals("SIGNING", text(object(firstStep(inspected), "output"), "state"));
        assertFalse(inspected.output().contains("credentialId"));
        Result completed = invoke(configuration, PASSWORD, "signing.operation.complete", "--operation-id", selected.value());
        assertEquals(0, completed.exit(), completed.output());
        assertEquals(selected.value(), text(firstStep(completed), "operationId"));
        Result stillPending = invoke(configuration, PASSWORD, "signing.operation.inspect", "--operation-id", unrelated.value());
        assertEquals(0, stillPending.exit(), stillPending.output());
        assertEquals("SIGNING", text(object(firstStep(stillPending), "output"), "state"));
        try (PkiSession session = PkiSession.openLocal(PkiCliConfiguration.read(configuration), dependencies())) {
            assertEquals("accepting-operator", session.semanticSigning().orElseThrow().find(selected).orElseThrow()
                    .scope().accessContext().principal().name());
        }
    }

    @Test
    void publicUnlockFailuresAreSafeResourceFailuresWithoutConsoleFallback() throws Exception {
        Path configuration = fixture();
        for (String value : Arrays.asList(null, "", "wrong-secret-value")) {
            Result failure = invoke(configuration, value, "configuration.validate");
            assertEquals(8, failure.exit(), failure.output());
            assertTrue(failure.output().contains("SESSION_OPEN_FAILED"));
            assertFalse(failure.output().contains(ENVIRONMENT));
            assertFalse(failure.output().contains(PASSWORD));
            assertFalse(failure.output().contains("wrong-secret-value"));
        }
        Files.writeString(configuration, Files.readString(configuration).replace(
                ",\"unlockEnvironmentVariable\":\"" + ENVIRONMENT + "\"", ""));
        assertEquals(8, invoke(configuration, PASSWORD, "configuration.validate").exit());
    }

    private Path fixture() throws Exception {
        Path keyring = directory.resolve("keys.bin");
        try (KeyringPassword password = new KeyringPassword(PASSWORD.toCharArray());
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            for (String name : List.of("root", "child", "rotated")) {
                KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
                keys.putPrivate(name + ".prv", "Ed25519", pair.getPrivate());
                keys.putPublic(name + ".pub", "Ed25519", pair.getPublic());
            }
        }
        for (String name : List.of("root-ca", "intermediate-ca", "vpn-client")) {
            try (InputStream input = getClass().getResourceAsStream("/zeroecho/pki/profiles/v1/" + name + ".json")) {
                String profile = new String(input.readAllBytes(), StandardCharsets.UTF_8)
                        .replace("PT87600H", "PT2400H").replace("PT43800H", "PT720H")
                        .replace("PT8760H", "PT24H").replace("\"minimumTotal\":1", "\"minimumTotal\":0")
                        .replace("\"allowEmpty\":true", "\"allowEmpty\":false")
                        .replace("\"approvalRequirement\":\"NONE\"", name.equals("vpn-client")
                                ? "\"approvalRequirement\":\"THRESHOLD\"" : "\"approvalRequirement\":\"NONE\"");
                Files.writeString(directory.resolve(name + ".json"), profile);
            }
        }
        KeyPair applicant = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        byte[] csr = zeroecho.pkix.Pkix.certificationRequestBuilder()
                .subject(new javax.security.auth.x500.X500Principal("CN=CLI Applicant"))
                .publicKey(applicant.getPublic()).build(zeroecho.pkix.Pkix.signer(applicant.getPrivate(),
                        zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11"))).encoded();
        Files.write(directory.resolve("request.der"), csr);
        Path configuration = directory.resolve("local.json");
        String storePath = directory.resolve("store").toString().replace("\\", "/");
        String keyringPath = keyring.toString().replace("\\", "/");
        Files.writeString(configuration, """
                {"version":1,"mode":"local","operatorId":"cli-root",
                "store":{"provider":"fs","properties":{"root":"%s"}},
                "audit":{"provider":"memory","properties":{"size":"128"}},
                "publishers":[],"bindingProviders":[],
                "signing":{"provider":{"provider":"zeroecho-lib","properties":{"keyringPath":"%s",
                "operationHorizon":"P90D","keyRefPrefix":"zeroecho-lib:","requireComponentSuffix":"true"}},
                "signatureAlgorithm":"%s","signingTtlSeconds":300,"claimLeaseMillis":10000,
                "providerCallTimeoutMillis":5000,"unlockEnvironmentVariable":"%s"}}
                """.formatted(storePath, keyringPath, BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(), ENVIRONMENT));
        return configuration;
    }

    private static PkiSessionRuntimeDependencies dependencies() {
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> new KeyringPassword(PASSWORD.toCharArray()));
    }

    private static PkiId accept(PkiSession session, String key, String subject) {
        PkiSigningOperation operation = new PkiSigningOperation.CreateAuthority(new FormatId("x509"),
                new SubjectRef(subject), "root-ca", new KeyRef("zeroecho-lib:" + key + ".prv"));
        AccessContext access = new AccessContext(new Principal("LOCAL_OPERATOR", "accepting-operator"),
                new Purpose(operation.name()), Optional.empty(), Optional.empty());
        PreparedSemanticSigningRequest prepared = session.signingCommands().orElseThrow().prepare(operation,
                access, Optional.empty(), CancellationSignal.NONE);
        return session.semanticSigning().orElseThrow().accept(prepared).receipt().operationId();
    }

    private Result invoke(Path configuration, String password, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", childClasspath(), "zeroecho.ZeroEcho", "pki", "--config", configuration.toString(), "--output", "json"));
        command.addAll(List.of(arguments));
        Path output = Files.createTempFile(directory, "cli-output-", ".json");
        Path errors = Files.createTempFile(directory, "cli-errors-", ".txt");
        ProcessBuilder builder = new ProcessBuilder(command).redirectOutput(output.toFile()).redirectError(errors.toFile());
        builder.environment().remove(ENVIRONMENT);
        if (password != null) builder.environment().put(ENVIRONMENT, password);
        Process process = builder.start();
        try {
            process.getOutputStream().close();
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "CLI process did not finish");
            String document = Files.readString(output);
            assertFalse(document.contains(PASSWORD));
            assertFalse(document.contains("wrong-secret-value"));
            String diagnostics = Files.readString(errors);
            assertFalse(diagnostics.contains(PASSWORD));
            assertFalse(diagnostics.contains("wrong-secret-value"));
            PkiCliJson.parse(document.getBytes(StandardCharsets.UTF_8));
            return new Result(process.exitValue(), document);
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(10, TimeUnit.SECONDS));
            }
        }
    }

    private static String childClasspath() throws Exception {
        Set<String> entries = new LinkedHashSet<>(Arrays.asList(System.getProperty("java.class.path").split(File.pathSeparator)));
        for (ClassLoader loader = PkiLocalSigningCliTest.class.getClassLoader(); loader != null; loader = loader.getParent()) {
            if (loader instanceof URLClassLoader urls) {
                for (URL url : urls.getURLs()) {
                    if (url.getProtocol().equals("file")) entries.add(Path.of(url.toURI()).toString());
                }
            }
        }
        return String.join(File.pathSeparator, entries);
    }

    private static PkiOperationValue.ObjectValue step(Result result, String id) throws Exception {
        return steps(result).stream().map(PkiCliConfiguration::object).filter(value -> text(value, "id").equals(id)).findFirst().orElseThrow();
    }
    private static PkiOperationValue.ObjectValue firstStep(Result result) throws Exception {
        return PkiCliConfiguration.object(steps(result).getFirst());
    }
    private static List<PkiOperationValue> steps(Result result) throws Exception {
        PkiOperationValue.ObjectValue root = PkiCliConfiguration.object(PkiCliJson.parse(result.output().getBytes(StandardCharsets.UTF_8)));
        return ((PkiOperationValue.ListValue) root.fields().get("steps")).values();
    }
    private static PkiOperationValue.ObjectValue object(PkiOperationValue.ObjectValue object, String name) {
        return PkiCliConfiguration.object(object.fields().get(name));
    }
    private static String text(PkiOperationValue.ObjectValue object, String name) {
        return PkiCliConfiguration.text(object.fields().get(name));
    }
    private record Result(int exit, String output) { }
}
