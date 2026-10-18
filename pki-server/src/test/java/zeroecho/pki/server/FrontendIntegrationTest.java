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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.spi.ProviderConfig;

/** Opt-in browser contract gate; all servers, credentials and storage are test-owned. */
@Tag("frontend-integration")
class FrontendIntegrationTest {
    private static final char[] PASSWORD = "frontend-test-only-password".toCharArray();
    @TempDir Path directory;

    @Test
    void builtSpaUsesRealSigningApprovalSelectionsAndRecovery() throws Exception {
        Path frontend = Path.of(System.getProperty("frontend.directory")).toRealPath();
        Path node = Path.of(System.getProperty("frontend.node"));
        assertTrue(Files.isExecutable(node), "Set -PfrontendNode to an installed Node 22 executable");
        assertTrue(Files.isRegularFile(frontend.resolve("dist/index.html")), "Build the frontend first");
        HttpServerTestSupport.Fixture tls = HttpServerTestSupport.tls();
        PkiServerConfiguration configuration = configuration(tls);
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(PASSWORD.clone()));
        seed(configuration, dependencies);
        try (PkiHttpsServer backend = PkiHttpsServer.start(configuration, dependencies);
                FrontendTestBridge bridge = new FrontendTestBridge(frontend.resolve("dist"), backend.address(), tls)) {
            backend.realm().gateway().installEst(new zeroecho.pki.server.est.EstService(backend.realm()));
            backend.realm().gateway().installScep(new zeroecho.pki.server.scep.ScepService(backend.realm()));
            backend.realm().gateway().installCmp(new zeroecho.pki.server.cmp.CmpService(backend.realm()));
            Path spool = directory.resolve("backup-artifacts");
            Files.createDirectory(spool, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")));
            BackupTransferConfiguration transfer = new BackupTransferConfiguration(spool,
                    16 * 1024 * 1024, 64 * 1024 * 1024, 8, 2, 18L * 1024 * 1024 * 1024,
                    Duration.ofHours(1), Duration.ofSeconds(30), bridge.baseUri());
            backend.realm().installBackupTransfer(transfer, Clock.systemUTC(), HttpServerTestSupport.random());
            java.util.concurrent.atomic.AtomicReference<PkiHttpsServer> current = new java.util.concurrent.atomic.AtomicReference<>(backend);
            bridge.restartWith(() -> {
                try {
                    current.get().close();
                    PkiHttpsServer reopened = PkiHttpsServer.start(configuration, dependencies, Optional.of(transfer));
                    current.set(reopened);
                    return reopened.address();
                } catch (Exception failure) { throw new IllegalStateException("Fixture restart failed", failure); }
            });
            ProcessBuilder builder = new ProcessBuilder(node.toString(),
                    frontend.resolve("node_modules/@playwright/test/cli.js").toString(),
                    "test", "--config=playwright.live.config.ts");
            builder.directory(frontend.toFile());
            builder.environment().put("E2E_LIVE_BASE_URL", bridge.baseUri().toString());
            builder.environment().put("E2E_BROWSER_EXECUTABLE", System.getProperty("frontend.browser", ""));
            builder.inheritIO();
            Process browser = builder.start();
            try {
                assertTrue(browser.waitFor(4, TimeUnit.MINUTES), "Live browser contract gate timed out");
                assertEquals(0, browser.exitValue(), "See the Playwright live report");
            } finally {
                List<ProcessHandle> owned = new java.util.ArrayList<>(browser.descendants().toList());
                owned.add(browser.toHandle());
                owned.forEach(ProcessHandle::destroy);
                try {
                    awaitExit(owned);
                } finally {
                    // Force surviving children even when the graceful wait is interrupted.
                    owned.stream().filter(ProcessHandle::isAlive).forEach(ProcessHandle::destroyForcibly);
                    awaitExit(owned);
                }
                assertTrue(owned.stream().noneMatch(ProcessHandle::isAlive), "Browser processes did not terminate");
                current.get().close();
            }
        }
    }

    private static void awaitExit(List<ProcessHandle> owned) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (owned.stream().anyMatch(ProcessHandle::isAlive) && System.nanoTime() < deadline) Thread.sleep(10);
    }

    private PkiServerConfiguration configuration(HttpServerTestSupport.Fixture tls) throws Exception {
        PkiServerConfiguration base = HttpServerTestSupport.configuration(directory, tls.clientCertificate());
        Path keyring = directory.resolve("signing.zek");
        try (KeyringPassword password = new KeyringPassword(PASSWORD.clone());
                KeyringStore keys = KeyringStore.create(keyring, password)) {
            for (String name : List.of("root", "intermediate")) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair pair = generator.generateKeyPair();
                keys.putPrivate(name + ".prv", "RSA", pair.getPrivate());
                keys.putPublic(name + ".pub", "RSA", pair.getPublic());
            }
        }
        PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                new PkiSessionConfiguration.SigningCoordinatorLimits(1, Duration.ofSeconds(10),
                        Duration.ofSeconds(5), Duration.ofMillis(10), Duration.ofSeconds(5)),
                List.of(), new PkiSessionConfiguration.SigningLanePool(1, 1));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString(),
                        "keyRefPrefix", "fixture:", "requireComponentSuffix", "true")),
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Duration.ofMinutes(2),
                Optional.empty(), topology, OptionalLong.empty());
        PkiSessionConfiguration original = base.realm().pkiSessionConfiguration();
        Map<String, String> storeProperties = new java.util.HashMap<>(original.store().properties());
        storeProperties.putAll(Map.of("credentialSearch", "h2", "credentialSearchCacheKiB", "4096",
                "credentialSearchQueryTimeoutMillis", "5000", "credentialSearchMaximumCertificateBytes", "1048576"));
        PkiSessionConfiguration session = new PkiSessionConfiguration(original.version(),
                new ProviderConfig("fs", storeProperties),
                original.audit(), Optional.of(signing), original.publishers(), original.bindingProviders());
        ServerRealmConfiguration realm = base.realm();
        realm = new ServerRealmConfiguration(realm.realmId(), realm.displayName(), realm.confirmationProofPolicy(),
                session, realm.authorityExposure(), realm.authorizationCommitment(), realm.approvalCommitment(),
                realm.extendedApprovalCommitment(), realm.disclosureCommitment(), realm.disclosureDefaults(),
                realm.controlLogPath(), realm.controlStoreId(), realm.approvalPolicies());
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(tls.proxyCertificate().getEncoded()));
        PkiServerConfiguration.ClientCertificateMapping approver = new PkiServerConfiguration.ClientCertificateMapping(
                "approver-map", "approver", Optional.of(digest), Optional.empty(), Optional.empty());
        PkiServerConfiguration.Authentication authentication = new PkiServerConfiguration.Authentication(
                AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(base.authentication().directClientMappings().getFirst(), approver), List.of(), List.of(), Set.of(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        return new PkiServerConfiguration(base.version(), base.serverName(), realm, base.listener(), authentication,
                base.execution(), base.runtime(), base.publicListener());
    }

    private void seed(PkiServerConfiguration configuration, PkiSessionRuntimeDependencies dependencies) throws Exception {
        try (ServerRealmContext context = ServerRealmContext.open(configuration.realm(), dependencies,
                Clock.systemUTC(), HttpServerTestSupport.random())) {
            Permission.Scope scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(),
                    Optional.empty(), Optional.empty());
            for (String principal : List.of("administrator", "approver")) {
                context.createPrincipal(ServerTestSupport.principal(principal), "system");
                for (OperationSecurityDescriptors.Descriptor descriptor : new OperationSecurityDescriptors().descriptors().values()) {
                    if (principal.equals("administrator")
                            && descriptor.action() == Permission.Action.CMP_ENDPOINT_ADMINISTER
                            || principal.equals("approver") && descriptor.action() == Permission.Action.ENROLLMENT_PROFILE_ADMINISTER) {
                        continue;
                    }
                    context.grant(ServerTestSupport.grant(principal + "." + descriptor.operationId(), principal,
                            Permission.Effect.ALLOW, descriptor.action(), descriptor.resourceType(), scope,
                            Permission.Relationship.ANY, descriptor.dataView()), "system");
                }
            }
            for (BuiltInCertificateProfileTemplate profile : BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                if (Set.of("root-ca", "intermediate-ca", "server-tls").contains(profile.definition().profileId())) {
                    context.session().profiles().importBuiltIn(profile);
                    context.session().profiles().activateProfile(profile.definition().profileId(), profile.definition().profileVersion());
                }
            }
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair requestKey = generator.generateKeyPair();
            org.bouncycastle.asn1.x509.ExtensionsGenerator extensions = new org.bouncycastle.asn1.x509.ExtensionsGenerator();
            extensions.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                    new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(2, "browser.example.test")));
            byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Browser CSR"), requestKey.getPublic())
                    .addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(requestKey.getPrivate())).getEncoded();
            assertInstanceOf(PkiOperationOutcome.Completed.class, context.session().operations().execute(
                    new PkiOperation.ImportRequest(new FormatId("x509"), new EncodedObject(Encoding.DER, csr)), CancellationSignal.NONE));
        }
        byte[] payload = new byte[1024 * 1024];
        java.util.Random random = new java.util.Random(7903);
        try (zeroecho.pki.impl.fs.FilesystemPkiStore store = new zeroecho.pki.impl.fs.FilesystemPkiStore(
                Path.of(configuration.realm().pkiSessionConfiguration().store().require("root")),
                zeroecho.pki.impl.fs.FsPkiStoreOptions.defaults())) {
            java.time.Instant now = Clock.systemUTC().instant();
            for (int index = 0; index < 5; index++) {
                random.nextBytes(payload);
                store.putWorkflowState(new zeroecho.pki.api.orch.WorkflowStateRecord(new zeroecho.pki.api.PkiId("large-backup-fixture-" + index),
                    "FIXTURE", new zeroecho.pki.api.audit.Principal("TEST", "fixture"),
                    zeroecho.pki.api.orch.OrchestrationDurabilityPolicy.DURABLE_MIN_STATE, now, now, now.plusSeconds(3600),
                    Encoding.BINARY, Optional.of(new EncodedObject(Encoding.BINARY, payload))));
            }
            try (zeroecho.pki.api.backup.BackupSource archive = store.createBackupSource(
                    new zeroecho.pki.api.backup.BackupRequest("fixture-validation", org.mockito.Mockito.mock(zeroecho.pki.api.attr.AttributeSet.class)));
                    zeroecho.pki.api.backup.BackupPreparation verified = store.prepareBackup(archive)) {
                assertEquals(archive.backupId(), verified.backupId());
            }
        }
    }
}
