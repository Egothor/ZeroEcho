package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Runs the real external Python scenario and installed crypto helper against localhost HTTPS, never Podman. */
@Tag("certificate-scenario")
class CertificateScenarioHttpTest {
    @ParameterizedTest @ValueSource(strings={"p384", "rsa4096", "mldsa87", "hybrid"})
    void externalClientIssuesAndVerifiesApprovedHierarchy(String variant, @TempDir Path root) throws Exception {
        var original = ManagedKeyGenerationIntegrationTest.configuration(root);
        var bootstrap = ManagedKeyGenerationIntegrationTest.withoutSigning(original);
        PkiAdminBootstrap.bootstrap(bootstrap, "administrator", "approver", "trusted-proxy");
        PkiAdminBootstrap.provisionRootAdmin(bootstrap, "administrator", "approver", "trusted-proxy");
        PkiAdminBootstrap.provisionCertificateAccess(bootstrap, "administrator", "approver", "trusted-proxy");
        var tls = scenarioTls();
        var transport = HttpServerTestSupport.configuration(root.resolve("transport"), tls.clientCertificate());
        int port;
        try (var socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) { port = socket.getLocalPort(); }
        var listener = new PkiServerConfiguration.Listener(transport.listener().address(), port, transport.listener().tlsProvider(),
                true, 65536, 1048576, Optional.of(new PkiServerConfiguration.HybridSdkListener("https://localhost:" + port)));
        var config = new PkiServerConfiguration(original.version(), original.serverName(), original.realm(), listener,
                transport.authentication(), transport.execution(), transport.runtime());
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"));
        writePem(root.resolve("login.pem"), "CERTIFICATE", tls.clientCertificate().getEncoded());
        writePem(root.resolve("login.key"), "PRIVATE KEY", HttpServerTestSupport.keyPair((byte) 3).getPrivate().getEncoded());
        writePem(root.resolve("trust.pem"), "CERTIFICATE", tls.rootCertificate().getEncoded());
        Path repository = Path.of(System.getProperty("scenario.repository"));
        String script = """
import json, sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(sys.argv[1]) / 'deploy'))
from exercise_pki import Api, Exercise, ExerciseFailure
from exercise_algorithms import run
root, variant, origin, realm, classpath = Path(sys.argv[2]), *sys.argv[3:]
options = SimpleNamespace(variant=variant, realm_id=realm, principal_id='administrator',
    crypto_classpath=classpath, sdk_authentication='direct-mtls-v1', sdk_transport_principal=None,
    approved_sdk_target=None, maximum_download_bytes=1048576)
exercise = Exercise(Api(origin, root/'trust.pem', root/'login.pem', root/'login.key'), root/'client-output', timeout=40)
try:
    try:
        run(exercise, options, root/'login.pem')
    except ExerciseFailure as failure:
        if variant != 'hybrid' or not str(failure).startswith('Review sdk-target-proposal.json'):
            raise
        proposal = json.loads((root/'client-output/sdk-target-proposal.json').read_text())
        options.approved_sdk_target = proposal['targetSha512']
        run(exercise, options, root/'login.pem')
    assert json.loads((root/'client-output/algorithm-report.json').read_text())['verified'] is True
    # A completed scenario resumes by observation without new generation/issuance.
    run(exercise, options, root/'login.pem')
finally:
    exercise.close()
""";
        try (var server = PkiHttpsServer.start(config, zeroecho.pki.application.PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> new zeroecho.core.storage.KeyringPassword("integration-test-key".toCharArray())), Clock.systemUTC(),
                HttpServerTestSupport.random(), zeroecho.pki.server.http.TestTlsProvider.class.getClassLoader())) {
            Path log = root.resolve("external-client.log");
            var process = new ProcessBuilder("python3", "-c", script, repository.toString(), root.toString(), variant,
                    "https://localhost:" + server.address().getPort(), config.realm().realmId().value(),
                    System.getProperty("scenario.cryptoClasspath")).redirectErrorStream(true).redirectOutput(log.toFile()).start();
            boolean finished = process.waitFor(180, TimeUnit.SECONDS);
            if (!finished) process.destroyForcibly().waitFor();
            assertTrue(finished, () -> "Client timeout: " + read(log));
            assertEquals(0, process.exitValue(), () -> read(log));
            assertTrue(Files.isRegularFile(root.resolve("client-output/client.der")));
        }
    }
    private static HttpServerTestSupport.Fixture scenarioTls() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        var rootKey = HttpServerTestSupport.keyPair((byte) 1);
        var serverKey = HttpServerTestSupport.keyPair((byte) 2);
        var clientKey = HttpServerTestSupport.keyPair((byte) 3);
        var root = certificate(rootKey, rootKey, "CN=Scenario Transport Root", "CN=Scenario Transport Root", 1, true, false);
        var server = certificate(serverKey, rootKey, "CN=localhost", "CN=Scenario Transport Root", 2, false, true);
        var client = certificate(clientKey, rootKey, "CN=Scenario Administrator", "CN=Scenario Transport Root", 3, false, false);
        var keys = java.security.KeyStore.getInstance("PKCS12"); keys.load(null, null);
        keys.setKeyEntry("server", serverKey.getPrivate(), "test".toCharArray(), new java.security.cert.Certificate[]{server, root});
        var kmf = javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keys, "test".toCharArray());
        var trust = java.security.KeyStore.getInstance("PKCS12"); trust.load(null, null); trust.setCertificateEntry("root", root);
        var tmf = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()); tmf.init(trust);
        var ssl = javax.net.ssl.SSLContext.getInstance("TLS"); ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        zeroecho.pki.server.http.TestTlsProvider.install(ssl);
        return new HttpServerTestSupport.Fixture(client, ssl, ssl, client, ssl, client, root);
    }
    private static java.security.cert.X509Certificate certificate(java.security.KeyPair subjectKey, java.security.KeyPair issuerKey,
            String subject, String issuer, int serial, boolean ca, boolean server) throws Exception {
        var builder = new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(new org.bouncycastle.asn1.x500.X500Name(issuer),
                java.math.BigInteger.valueOf(serial), java.util.Date.from(java.time.Instant.now().minusSeconds(60)),
                java.util.Date.from(java.time.Instant.now().plusSeconds(3600)), new org.bouncycastle.asn1.x500.X500Name(subject), subjectKey.getPublic());
        var ext = new org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils();
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.basicConstraints, true, new org.bouncycastle.asn1.x509.BasicConstraints(ca));
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, true, new org.bouncycastle.asn1.x509.KeyUsage(ca ? 6 : 160));
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subjectKey.getPublic()));
        builder.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKey.getPublic()));
        if (!ca) builder.addExtension(org.bouncycastle.asn1.x509.Extension.extendedKeyUsage, false, new org.bouncycastle.asn1.x509.ExtendedKeyUsage(
                server ? org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth : org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth));
        if (server) builder.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false, new org.bouncycastle.asn1.x509.GeneralNames(
                new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName, "localhost")));
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(
                new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate())));
    }
    private static String read(Path file) { try { return Files.readString(file); } catch (Exception e) { return e.getClass().getSimpleName(); } }
    private static void writePem(Path path, String type, byte[] der) throws Exception {
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + java.util.Base64.getMimeEncoder(64, new byte[]{10}).encodeToString(der) + "\n-----END " + type + "-----\n");
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
}
