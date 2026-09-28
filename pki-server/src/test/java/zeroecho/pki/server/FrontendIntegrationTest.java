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
        PkiSessionConfiguration session = new PkiSessionConfiguration(original.version(), original.store(),
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
            byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=Browser CSR"), requestKey.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(requestKey.getPrivate())).getEncoded();
            assertInstanceOf(PkiOperationOutcome.Completed.class, context.session().operations().execute(
                    new PkiOperation.ImportRequest(new FormatId("x509"), new EncodedObject(Encoding.DER, csr)), CancellationSignal.NONE));
        }
    }
}
