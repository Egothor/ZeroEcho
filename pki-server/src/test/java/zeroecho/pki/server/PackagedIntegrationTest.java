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

package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiOperationValue.ObjectValue;
import zeroecho.pki.application.PkiOperationValue.Text;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.StrictJson;

/** Opt-in gate for actual packaged server, nginx, SPA and remote CLI artifacts. */
@Tag("packaged-integration")
class PackagedIntegrationTest {
    private static final String PASSWORD = PackagedIntegrationTls.PASSWORD;
    private Path root;
    private Path directory;
    private Path tls;
    private int commandIndex;
    private String baseUrl;

    @Test
    void packagedDeploymentPreservesAuthenticationApprovalAndSubmitOnceReceipts() throws Exception {
        root = Path.of(System.getProperty("packaged.repository")).toRealPath();
        Path output = Files.createDirectories(root.resolve("build/pki-validation/packaged"));
        directory = Files.createTempDirectory(output, "run-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        tls = directory.resolve("tls");
        PackagedIntegrationTls identities = new PackagedIntegrationTls(tls);
        ObjectValue configuration = configuration(identities);
        seed(PkiServerConfigurationCodec.decode(StrictJson.encode(configuration)));
        // Preserve identical realm identities while relocating only fixture paths into the container.
        byte[] encoded = StrictJson.encode(relocate(configuration));
        PkiServerConfigurationCodec.decode(encoded);
        Files.write(directory.resolve("server.json"), encoded);
        String suffix = UUID.randomUUID().toString().substring(0, 12);
        String network = "zeroecho-packaged-test-" + suffix;
        String server = network + "-server";
        String nginx = network + "-nginx";
        boolean networkCreated = false;
        try {
            checked("network-create", List.of("podman", "network", "create", "--internal", network));
            networkCreated = true;
            startServer(network, server);
            startNginx(network, nginx);
            String binding = checked("edge-port", List.of("podman", "port", nginx, "8443/tcp")).output().trim();
            assertTrue(binding.matches("127\\.0\\.0\\.1:[0-9]+"), binding);
            baseUrl = "https://" + binding;
            awaitReady();
            Result anonymous = command("anonymous", List.of("curl", "--silent", "--show-error", "--max-time", "10",
                    "--cacert", tls.resolve("ca.pem").toString(), "--output", directory.resolve("anonymous-body").toString(),
                    "--write-out", "%{http_code}", baseUrl + "/admin/v1/operations"), Map.of(), Duration.ofSeconds(15));
            assertTrue(anonymous.exitCode() != 0 || Integer.parseInt(anonymous.output().trim()) >= 400,
                    "nginx must reject callers without a client certificate");
            remoteCliRoundTrip();
            String cliAccess = checked("nginx-access", List.of("podman", "logs", nginx)).output();
            assertEquals(1, cliAccess.lines().filter(line -> line.contains("POST /admin/v1/operations/ca.create ")).count(),
                    "CLI observation must never repeat the mutation, regardless of response status");
            browser(identities.edgeSpkiPin());
            String access = checked("nginx-access", List.of("podman", "logs", nginx)).output();
            long acceptedPosts = access.lines().filter(line -> line.contains("POST /admin/v1/operations/ca.create ")
                    && line.contains(" 202 ")).count();
            assertEquals(2, acceptedPosts, "Exactly one accepted root submission per CLI/browser scenario");
            assertEquals(3, access.lines().filter(line -> line.contains("POST /admin/v1/operations/ca.create ")).count(),
                    "Only CLI acceptance, browser approval probe, and browser acceptance may submit");
        } finally {
            try {
                try { captureLogs(server); } finally { captureLogs(nginx); }
            } finally {
                // Every name belongs exclusively to this invocation; no global prune or unrelated stop.
                try {
                    checked("remove-nginx", List.of("podman", "rm", "--force", "--ignore", nginx));
                } finally {
                    try {
                        checked("remove-server", List.of("podman", "rm", "--force", "--ignore", server));
                    } finally {
                        if (networkCreated) {
                            checked("remove-network", List.of("podman", "network", "rm", network));
                        }
                    }
                }
            }
        }
    }

    private ObjectValue configuration(PackagedIntegrationTls identities) throws Exception {
        ObjectValue document = object(StrictJson.parse(Files.readAllBytes(
                root.resolve("docs/pki-server-trusted-proxy-rfc9440-example.json")), 1_048_576));
        ObjectValue realm = object(document.fields().get("realm"));
        ObjectValue session = object(realm.fields().get("pkiSession"));
        ObjectValue signing = json("""
                {"provider":{"id":"zeroecho-lib","properties":{}},"signatureAlgorithm":"placeholder",
                 "signingTtlMillis":120000,"topology":{"coordinator":{"pageSize":1,"claimLeaseMillis":30000,
                 "providerCallTimeoutMillis":10000,"idlePollIntervalMillis":20,"closeTimeoutMillis":5000},
                 "exactGroups":[],"catchAll":{"laneCount":1,"prefetchSize":1}}}
                """);
        signing = with(signing, "provider", provider("zeroecho-lib", Map.of(
                "keyringPath", directory.resolve("keyring/signing.zek").toString(), "keyRefPrefix", "fixture:",
                "requireComponentSuffix", "true")));
        signing = with(signing, "signatureAlgorithm", new Text(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()));
        session = with(session, "store", provider("fs", Map.of("root", directory.resolve("store").toString())));
        session = with(session, "audit", provider("file", Map.of("root", directory.resolve("audit").toString())));
        session = with(session, "signing", signing);
        realm = with(realm, "pkiSession", session);
        realm = with(realm, "controlLog", new Text(directory.resolve("control.log").toString()));
        realm = with(realm, "authorityExposure", json(
                "{\"mode\":\"ALL_REALM_AUTHORITIES\",\"authorityIds\":[],\"creationPermitted\":true}"));
        ObjectValue listener = object(document.fields().get("listener"));
        listener = with(listener, "address", new Text("0.0.0.0"));
        listener = with(listener, "tlsProvider", provider("jsse-pkcs12", Map.of(
                "keyStore", tls.resolve("server.p12").toString(), "keyStorePasswordEnvironment", "PACKAGED_TEST_TLS_PASSWORD",
                "trustStore", tls.resolve("trust.p12").toString(), "trustStorePasswordEnvironment", "PACKAGED_TEST_TLS_PASSWORD")));
        ObjectValue auth = object(document.fields().get("authentication"));
        auth = with(auth, "proxyTransportMappings", new PkiOperationValue.ListValue(List.of(
                mapping("proxy-map", "trusted-proxy", identities.fingerprint("proxy")))));
        auth = with(auth, "forwardedClientMappings", new PkiOperationValue.ListValue(List.of(
                mapping("admin-map", "bootstrap-admin", identities.fingerprint("administrator")),
                mapping("approver-map", "bootstrap-approver", identities.fingerprint("approver")),
                mapping("scoped-map", "scoped", identities.fingerprint("scoped")))));
        auth = with(auth, "administrativeClientTrust", provider("jsse-pkcs12-client-trust", Map.of(
                "trustStore", tls.resolve("trust.p12").toString(), "trustStorePasswordEnvironment", "PACKAGED_TEST_TLS_PASSWORD")));
        document = with(document, "realm", realm);
        document = with(document, "listener", listener);
        document = with(document, "authentication", auth);
        document = with(document, "publicListener", json("{\"enabled\":false}"));
        return with(document, "runtime", json("{\"keyUnlockEnvironmentVariable\":\"PACKAGED_TEST_KEY_PASSWORD\"}"));
    }

    private void seed(PkiServerConfiguration configuration) throws Exception {
        Path keyDirectory = Files.createDirectory(directory.resolve("keyring"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try (KeyringPassword password = new KeyringPassword(PASSWORD.toCharArray());
                KeyringStore keys = KeyringStore.create(keyDirectory.resolve("signing.zek"), password)) {
            for (String name : List.of("root", "root-cli", "intermediate")) {
                KeyPair pair = PackagedIntegrationTls.keyPair();
                keys.putPrivate(name + ".prv", "RSA", pair.getPrivate());
                keys.putPublic(name + ".pub", "RSA", pair.getPublic());
            }
        }
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(PASSWORD.toCharArray()));
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(), dependencies,
                Clock.systemUTC(), HttpServerTestSupport.random())) {
            Permission.Scope realm = new Permission.Scope(configuration.realm().realmId(), Optional.empty(),
                    Optional.empty(), Optional.empty());
            context.createPrincipal(new SecurityPrincipal("trusted-proxy", SecurityPrincipal.Type.SERVICE,
                    "Packaged nginx transport", Optional.empty(), Map.of(), true), "system");
            context.grant(ServerTestSupport.grant("proxy-forward", "trusted-proxy", Permission.Effect.ALLOW,
                    Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY, Permission.ResourceType.REALM,
                    realm, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "system");
            for (String principal : List.of("bootstrap-admin", "bootstrap-approver")) {
                context.createPrincipal(ServerTestSupport.principal(principal), "system");
                for (OperationSecurityDescriptors.Descriptor descriptor : new OperationSecurityDescriptors().descriptors().values()) {
                    context.grant(ServerTestSupport.grant(principal + "." + descriptor.operationId(), principal,
                            Permission.Effect.ALLOW, descriptor.action(), descriptor.resourceType(), realm,
                            Permission.Relationship.ANY, descriptor.dataView()), "system");
                }
            }
            context.createPrincipal(ServerTestSupport.principal("scoped"), "system");
            OperationSecurityDescriptors.Descriptor inspection = new OperationSecurityDescriptors().descriptors().get("ca.inspect");
            Permission.Scope otherAuthority = new Permission.Scope(configuration.realm().realmId(),
                    Optional.of(new PkiId("different-authority")), Optional.empty(), Optional.empty());
            context.grant(ServerTestSupport.grant("scoped.inspect", "scoped", Permission.Effect.ALLOW,
                    inspection.action(), inspection.resourceType(), otherAuthority, Permission.Relationship.ANY,
                    inspection.dataView()), "system");
            for (BuiltInCertificateProfileTemplate profile : BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                if (Set.of("root-ca", "intermediate-ca", "server-tls").contains(profile.definition().profileId())) {
                    context.session().profiles().importBuiltIn(profile);
                    context.session().profiles().activateProfile(profile.definition().profileId(), profile.definition().profileVersion());
                }
            }
            KeyPair requestKey = PackagedIntegrationTls.keyPair();
            byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Packaged Browser CSR"), requestKey.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(requestKey.getPrivate())).getEncoded();
            assertInstanceOf(PkiOperationOutcome.Completed.class, context.session().operations().execute(
                    new PkiOperation.ImportRequest(new FormatId("x509"), new EncodedObject(Encoding.DER, csr)), CancellationSignal.NONE));
        }
    }

    private void startServer(String network, String name) throws Exception {
        checked("server-start", List.of("podman", "run", "--detach", "--pull=never", "--name", name,
                "--network", network, "--network-alias", "pki-server", "--userns=keep-id:uid=10001,gid=10001",
                "--volume", directory + ":/fixture:rw,z", "--env", "ZEROECHO_SERVER_CONFIG=/fixture/server.json",
                "--env", "ZEROECHO_PROFILE_RECONCILE=off", "--env", "PACKAGED_TEST_TLS_PASSWORD", "--env", "PACKAGED_TEST_KEY_PASSWORD",
                System.getProperty("packaged.serverImage")));
    }

    private void startNginx(String network, String name) throws Exception {
        List<String> command = new ArrayList<>(List.of("podman", "run", "--detach", "--pull=never", "--name", name,
                "--network", network, "--publish", "127.0.0.1::8443", "--env", "NGINX_SERVER_NAME=localhost",
                "--env", "PKI_UPSTREAM=pki-server:8443", "--env", "PKI_PROXY_SSL_NAME=pki-server"));
        Map<String, String> mounts = Map.of("edge.crt", "edge/edge.crt", "edge.key", "edge/edge.key",
                "proxy.crt", "upstream/proxy-client.crt", "proxy.key", "upstream/proxy-client.key");
        mounts.forEach((source, target) -> command.addAll(List.of("--volume", tls.resolve(source) + ":/etc/nginx/tls/" + target + ":ro,z")));
        command.addAll(List.of("--volume", tls.resolve("ca.pem") + ":/etc/nginx/tls/admin-trust/admin-ca-bundle.pem:ro,z",
                "--volume", tls.resolve("ca.pem") + ":/etc/nginx/tls/upstream/pki-server-ca.pem:ro,z",
                System.getProperty("packaged.nginxImage")));
        checked("nginx-start", command);
    }

    private void awaitReady() throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (System.nanoTime() < deadline) {
            Result result = command("readiness", List.of("curl", "--silent", "--show-error", "--fail", "--max-time", "2",
                    "--cacert", tls.resolve("ca.pem").toString(), "--cert", tls.resolve("administrator.crt").toString(),
                    "--key", tls.resolve("administrator.key").toString(), baseUrl + "/health/ready"), Map.of(), Duration.ofSeconds(5));
            if (result.exitCode() == 0) { return; }
            Thread.sleep(200);
        }
        throw new AssertionError("Packaged deployment did not become ready; retained logs: " + directory);
    }

    private void remoteCliRoundTrip() throws Exception {
        String target = "{\"formatId\":\"x509\",\"subjectRef\":\"CN=Packaged CLI Root\","
                + "\"profileId\":\"root-ca\",\"keyRef\":\"fixture:root-cli.prv\"}";
        cli("cli-approval-request", "administrator", 0, "security.approval.request", "--arg", "approvalId=cli-root",
                "--arg", "targetOperation=ca.create", "--arg-json", "targetArguments=" + target);
        cli("cli-approval", "approver", 0, "security.approval.approve", "--arg", "approvalId=cli-root",
                "--arg", "justification=Independent packaged CLI approval");
        ObjectValue receipt = cli("cli-submit", "administrator", 7, "ca.create", "--format-id", "x509",
                "--subject-ref", "CN=Packaged CLI Root", "--profile-id", "root-ca", "--key-ref", "fixture:root-cli.prv",
                "--approval-id", "cli-root", "--pending-wait", "0");
        String id = text(receipt.fields().get("operationId"));
        assertEquals("PENDING", text(receipt.fields().get("status")));
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        ObjectValue completion = null;
        while (System.nanoTime() < deadline) {
            Result observed = cliResult("cli-inspect", "administrator", "signing.operation.inspect", "--operation-id", id);
            assertTrue(observed.exitCode() == 0 || observed.exitCode() == 7, observed.output());
            ObjectValue observedStep = json(observed.output());
            assertEquals(id, text(observedStep.fields().get("operationId")));
            if (observed.exitCode() == 0) { completion = object(observedStep.fields().get("result")); break; }
            Thread.sleep(100);
        }
        assertTrue(completion != null, "Retained operation did not complete: " + id);
        assertTrue(!text(completion.fields().get("credentialId")).isBlank());
        assertEquals("CA", text(completion.fields().get("kind")));
        assertEquals("DER", text(completion.fields().get("encoding")));
        assertTrue(text(completion.fields().get("resultSha256")).matches("[0-9a-f]{64}"));
        ObjectValue inventory = object(cli("cli-authorities", "administrator", 0, "ca.list",
                "--arg-int", "limit=10").fields().get("result"));
        List<PkiOperationValue> authorities = ((PkiOperationValue.ListValue) inventory.fields().get("authorities")).values();
        assertEquals(1, authorities.size(), "Only the CLI root exists before the browser scenario");
        String caId = text(object(authorities.getFirst()).fields().get("caId"));
        ObjectValue authority = object(cli("cli-authority", "administrator", 0, "ca.inspect",
                "--authority-id", caId, "--ca-id", caId).fields().get("result"));
        assertEquals(caId, text(authority.fields().get("caId")));
        ObjectValue denied = cli("cli-scope-denied", "scoped", 4, "ca.inspect", "--authority-id", caId, "--ca-id", caId);
        assertEquals("DENIED", text(denied.fields().get("failure")));
        assertEquals("AUTHORIZATION_DENIED", text(denied.fields().get("code")));
    }

    private void browser(String edgeSpkiPin) throws Exception {
        Path frontend = root.resolve("pki-frontend");
        Map<String, String> environment = Map.of("E2E_EDGE_SPKI", edgeSpkiPin, "NODE_EXTRA_CA_CERTS", tls.resolve("ca.pem").toString(),
                "E2E_PACKAGED_BASE_URL", baseUrl, "E2E_PACKAGED_TLS", tls.toString(),
                "E2E_PACKAGED_OUTPUT", directory.resolve("playwright").toString(),
                "E2E_BROWSER_EXECUTABLE", System.getProperty("frontend.browser", ""));
        Result result = command("browser", List.of(System.getProperty("frontend.node"),
                frontend.resolve("node_modules/@playwright/test/cli.js").toString(), "test",
                "--config=" + frontend.resolve("playwright.packaged.config.ts")), environment, Duration.ofMinutes(4));
        assertEquals(0, result.exitCode(), "See " + directory + "; " + result.output());
    }

    private ObjectValue cli(String label, String identity, int expected, String... arguments) throws Exception {
        Result result = cliResult(label, identity, arguments);
        assertEquals(expected, result.exitCode(), label + ": " + result.output());
        return json(result.output());
    }

    private Result cliResult(String label, String identity, String... arguments) throws Exception {
        List<String> command = new ArrayList<>(List.of(root.resolve("app/build/install/app/bin/app").toString(), "pki"));
        command.addAll(List.of(arguments));
        command.addAll(List.of("--url", baseUrl, "--client-cert", tls.resolve(identity + ".crt").toString(),
                "--client-key", tls.resolve(identity + ".key").toString(), "--trust", tls.resolve("ca.pem").toString(), "--output", "json"));
        return command(label, command, Map.of(), Duration.ofSeconds(45));
    }

    private void captureLogs(String name) throws Exception {
        command("logs-" + name, List.of("podman", "logs", name), Map.of(), Duration.ofSeconds(10));
    }

    private Result checked(String label, List<String> arguments) throws Exception {
        Result result = command(label, arguments, Map.of("PACKAGED_TEST_TLS_PASSWORD", PASSWORD, "PACKAGED_TEST_KEY_PASSWORD", PASSWORD),
                Duration.ofSeconds(45));
        assertEquals(0, result.exitCode(), label + ": " + result.output());
        return result;
    }

    private Result command(String label, List<String> arguments, Map<String, String> environment, Duration timeout) throws Exception {
        Path stdout = directory.resolve(String.format("%03d-%s.out", ++commandIndex, label));
        Path stderr = directory.resolve(String.format("%03d-%s.err", commandIndex, label));
        ProcessBuilder builder = new ProcessBuilder(arguments).directory(root.toFile());
        builder.environment().putAll(environment);
        builder.redirectOutput(stdout.toFile()).redirectError(stderr.toFile());
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS), "Command timed out: " + label);
            return new Result(process.exitValue(), Files.readString(stdout) +
                    ("nginx-access".equals(label) ? Files.readString(stderr) : ""));
        } finally {
            List<ProcessHandle> owned = new ArrayList<>(process.descendants().toList());
            owned.add(process.toHandle());
            owned.forEach(ProcessHandle::destroy);
            try {
                awaitExit(owned);
            } finally {
                // Force every survivor even if interruption aborts the graceful wait.
                owned.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
                awaitExit(owned);
            }
            assertTrue(owned.stream().noneMatch(ProcessHandle::isAlive), "Owned command processes did not terminate");
        }
    }

    private static void awaitExit(List<ProcessHandle> owned) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (owned.stream().anyMatch(ProcessHandle::isAlive) && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
    }

    private PkiOperationValue relocate(PkiOperationValue value) {
        if (value instanceof Text text) {
            return new Text(text.value().replace(directory.toString(), "/fixture"));
        }
        if (value instanceof ObjectValue object) {
            Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
            object.fields().forEach((name, nested) -> fields.put(name, relocate(nested)));
            return new ObjectValue(fields);
        }
        if (value instanceof PkiOperationValue.ListValue list) {
            return new PkiOperationValue.ListValue(list.values().stream().map(this::relocate).toList());
        }
        return value;
    }

    private static ObjectValue provider(String id, Map<String, String> properties) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>();
        properties.forEach((key, value) -> fields.put(key, new Text(value)));
        return new ObjectValue(Map.of("id", new Text(id), "properties", new ObjectValue(fields)));
    }

    private static ObjectValue mapping(String id, String principal, String fingerprint) {
        return new ObjectValue(Map.of("mappingId", new Text(id), "principalId", new Text(principal),
                "certificateSha256", new Text(fingerprint)));
    }

    private static ObjectValue with(ObjectValue source, String key, PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = new LinkedHashMap<>(source.fields());
        fields.put(key, value);
        return new ObjectValue(fields);
    }

    private static ObjectValue json(String text) {
        return object(StrictJson.parse(text.getBytes(StandardCharsets.UTF_8), 1_048_576));
    }
    private static ObjectValue object(PkiOperationValue value) { return (ObjectValue) value; }
    private static String text(PkiOperationValue value) { return ((Text) value).value(); }
    private record Result(int exitCode, String output) { }
}
