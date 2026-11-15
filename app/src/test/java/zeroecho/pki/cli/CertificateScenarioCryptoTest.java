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

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;

final class CertificateScenarioCryptoTest {
    @TempDir Path directory;

    @ParameterizedTest @ValueSource(strings = {"p384", "rsa4096", "mldsa87", "hybrid"})
    void generatedClientProvesExactAlgorithmsAndRealChainAndRejectsWrongVariantAndTampering(String variant) throws Exception {
        Path client = directory.resolve("keys");
        CertificateScenarioCrypto.main(new String[] {"generate", variant, client.toString()});
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(client.resolve("client.key")));
        byte[] csr = Files.readAllBytes(client.resolve("client.csr.der"));
        var request = new PKCS10CertificationRequest(csr);
        String algorithm = variant.equals("rsa4096") ? "RSA" : variant.equals("mldsa87") ? "ML-DSA" : "EC";
        var leaf = new KeyPair(KeyFactory.getInstance(algorithm, "BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(client.resolve("client.spki.der")))),
                KeyFactory.getInstance(algorithm, "BC").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(client.resolve("client.key")))));
        var root = pair(variant); var child = pair(variant);
        KeyPair rootAlt = variant.equals("hybrid") ? pair("mldsa87") : null;
        KeyPair childAlt = variant.equals("hybrid") ? pair("mldsa87") : null;
        byte[] leafAlt = variant.equals("hybrid") ? Files.readAllBytes(client.resolve("alternative.spki.der")) : null;
        privateFile(client.resolve("root.spki.der"), root.getPublic().getEncoded());
        privateFile(client.resolve("intermediate.spki.der"), child.getPublic().getEncoded());
        if (variant.equals("hybrid")) {
            privateFile(client.resolve("root-alternative.spki.der"), rootAlt.getPublic().getEncoded());
            privateFile(client.resolve("intermediate-alternative.spki.der"), childAlt.getPublic().getEncoded());
        }
        String signature = signature(variant);
        Path rootFile = file("root.der", certificate("CN=Root", "CN=Root", root, root, rootAlt == null ? null : rootAlt.getPublic().getEncoded(), rootAlt, 1, signature));
        Path childFile = file("intermediate.der", certificate("CN=Child", "CN=Root", child, root, childAlt == null ? null : childAlt.getPublic().getEncoded(), rootAlt, 0, signature));
        Path leafFile = file("client.der", certificate(request.getSubject().toString(), "CN=Child", leaf, child, leafAlt, childAlt, -1, signature));
        String[] verify = {"verify", variant, client.toString(), rootFile.toString(), childFile.toString(), leafFile.toString()};
        assertDoesNotThrow(() -> CertificateScenarioCrypto.main(verify));
        Path bundle = file("chain.pem", pem(Files.readAllBytes(childFile)) + pem(Files.readAllBytes(rootFile)));
        assertTrue(capture("verify-chain", bundle.toString()).startsWith("VERIFIED issuer-chain certificates=2 "));
        Files.writeString(bundle, pem(Files.readAllBytes(rootFile)));
        assertTrue(capture("verify-chain", bundle.toString()).startsWith("VERIFIED issuer-chain certificates=1 "));
        for (String invalidBundle : new String[] {"", pem(Files.readAllBytes(childFile)),
                pem(Files.readAllBytes(rootFile)) + pem(Files.readAllBytes(childFile)),
                pem(Files.readAllBytes(rootFile)) + pem(Files.readAllBytes(rootFile)),
                pem(Files.readAllBytes(childFile)) + pem(Files.readAllBytes(rootFile)) + "unexpected",
                pem(Files.readAllBytes(leafFile)) + pem(Files.readAllBytes(childFile)) + pem(Files.readAllBytes(rootFile))}) {
            Files.writeString(bundle, invalidBundle);
            assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(new String[] {"verify-chain", bundle.toString()}));
        }
        byte[] restrictedRoot = certificate("CN=Root", "CN=Root", root, root, rootAlt == null ? null : rootAlt.getPublic().getEncoded(), rootAlt, 0, signature);
        Files.writeString(bundle, pem(Files.readAllBytes(childFile)) + pem(restrictedRoot));
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(new String[] {"verify-chain", bundle.toString()}));
        byte[] damagedChild = Files.readAllBytes(childFile); damagedChild[damagedChild.length - 1] ^= 1;
        Files.writeString(bundle, pem(damagedChild) + pem(Files.readAllBytes(rootFile)));
        assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(new String[] {"verify-chain", bundle.toString()}));
        if (variant.equals("hybrid")) {
            var wrongAlt = pair("mldsa87");
            byte[] wrongRoot = certificate("CN=Root", "CN=Root", root, root, wrongAlt.getPublic().getEncoded(), wrongAlt, 1, signature);
            Files.writeString(bundle, pem(Files.readAllBytes(childFile)) + pem(wrongRoot));
            assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(new String[] {"verify-chain", bundle.toString()}));
        }

        privateFile(client.resolve("root.spki.der"), child.getPublic().getEncoded());
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(verify));
        privateFile(client.resolve("root.spki.der"), root.getPublic().getEncoded());
        assertThrows(java.nio.file.FileAlreadyExistsException.class, () -> CertificateScenarioCrypto.main(new String[] {"generate", variant, client.toString()}));
        var wrong = verify.clone(); wrong[1] = variant.equals("p384") ? "rsa4096" : "p384";
        assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(wrong));
        byte[] original = Files.readAllBytes(leafFile); byte[] tampered = original.clone(); tampered[tampered.length - 1] ^= 1; Files.write(leafFile, tampered);
        assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(verify)); Files.write(leafFile, original);
        byte[] saved = Files.readAllBytes(client.resolve("client.key")); Files.write(client.resolve("client.key"), child.getPrivate().getEncoded());
        assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(verify)); Files.write(client.resolve("client.key"), saved);
        if (variant.equals("hybrid")) {
            assertEquals(zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(csr).primary().requestId().value(), Files.readString(client.resolve("request-id.txt")));
            byte[] alternative = Files.readAllBytes(client.resolve("alternative.key")); Files.write(client.resolve("alternative.key"), rootAlt.getPrivate().getEncoded());
            assertThrows(Exception.class, () -> CertificateScenarioCrypto.main(verify)); Files.write(client.resolve("alternative.key"), alternative);
        }
    }

    @Test void signsOnlyMatchingCurrentApprovedFramesAndRetainsVerifiableDualProofs() throws Exception {
        Path client = directory.resolve("keys"); CertificateScenarioCrypto.main(new String[] {"generate", "hybrid", client.toString()});
        long now = Instant.now().getEpochSecond();
        var target = target(); byte[] context = new byte[64]; byte[] nonce = new byte[32]; Arrays.fill(nonce, (byte) 11);
        Map<Integer, byte[]> fields = new TreeMap<>();
        fields.put(1, bytes("zeroecho-hybrid-sdk-v1")); fields.put(2, bytes("realm"));
        fields.put(3, new byte[32]); fields.put(4, new byte[32]); fields.put(5, new byte[32]); fields.put(6, nonce);
        fields.put(7, time(now - 1)); fields.put(8, time(now + 299)); fields.put(9, bytes("https://localhost:8443")); fields.put(10, bytes("admin-http-v1"));
        fields.put(11, HybridSdkFrame.hash(Files.readAllBytes(client.resolve("client.csr.der")))); fields.put(12, context);
        fields.put(13, HybridSdkFrame.hash(Files.readAllBytes(client.resolve("client.spki.der"))));
        fields.put(14, HybridSdkFrame.hash(Files.readAllBytes(client.resolve("alternative.spki.der"))));
        fields.put(15, HybridSdkFrame.primaryAlgorithm()); fields.put(16, HybridSdkFrame.alternativeAlgorithm()); fields.put(17, HybridSdkFrame.hash(target.encode()));
        var first = new HybridSdkFrame(1, fields); var second = new HybridSdkFrame(2, fields);
        Path f1 = file("f1", first.encode()), f2 = file("f2", second.encode()), f7 = file("f7", target.encode());
        String[] command = {"sign", client.toString(), f1.toString(), f2.toString(), f7.toString(), "https://localhost:8443", "realm",
                HexFormat.of().formatHex(nonce), HexFormat.of().formatHex(HybridSdkFrame.hash(target.encode())), HexFormat.of().formatHex(context)};
        String[] wrong = command.clone(); wrong[5] = "https://other.invalid:8443";
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(wrong));
        String[] wrongTarget = command.clone(); wrongTarget[8] = "ab".repeat(64);
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(wrongTarget));
        assertFalse(Files.exists(client.resolve("primary.proof")));
        CertificateScenarioCrypto.main(command);
        var primary = Signature.getInstance("SHA384withECDSA", "BC"); primary.initVerify(KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(client.resolve("client.spki.der")))));
        primary.update(first.encode()); assertTrue(primary.verify(Files.readAllBytes(client.resolve("primary.proof"))));
        var alt = Signature.getInstance("ML-DSA-87", "BC"); alt.initVerify(KeyFactory.getInstance("ML-DSA", "BC").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(client.resolve("alternative.spki.der")))));
        alt.update(second.encode()); assertTrue(alt.verify(Files.readAllBytes(client.resolve("alternative.proof"))));
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(command));
    }

    @Test void authContextMatchesClosedAdministrativeF6AndDescribeUsesCanonicalIdentity() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        var pair = pair("p384");
        Path leaf = file("login.der", certificate("CN=Admin", "CN=Admin", pair, pair, null, null, -1, "SHA384withECDSA"));
        var cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509", "BC").generateCertificate(Files.newInputStream(leaf));
        var hash = java.security.MessageDigest.getInstance("SHA-256"); hash.update(cert.getIssuerX500Principal().getEncoded()); hash.update((byte) 0); hash.update(cert.getSerialNumber().toByteArray());
        var values = Map.of("canonicalKeySha256", HybridSdkValue.text(zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(zeroecho.pkix.Pkix.subjectPublicKeyInfo(cert)).canonicalSha256()),
                "issuerSerialSha256", HybridSdkValue.text(HexFormat.of().formatHex(hash.digest())), "transportPrincipalId", HybridSdkValue.text(""));
        var expected = new HybridSdkFrame(6, Map.of(1, bytes("administrator"), 2, bytes("direct-mtls-v1"),
                3, HybridSdkFrame.hash(bytes("sha256:" + HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())))),
                4, bytes("admin-http-v1"), 5, HybridSdkValue.object(values).encode()));
        assertEquals(HexFormat.of().formatHex(HybridSdkFrame.hash(expected.encode())), capture("auth-context", leaf.toString(), "administrator", "direct-mtls-v1", ""));
        assertEquals(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), capture("describe", "mldsa87"));
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(new String[] {"describe", "p521"}));
        Files.setPosixFilePermissions(leaf, PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(IllegalArgumentException.class, () -> CertificateScenarioCrypto.main(new String[] {"auth-context", leaf.toString(), "administrator", "direct-mtls-v1", ""}));
    }

    private static String capture(String... args) throws Exception {
        PrintStream original = System.out; var output = new ByteArrayOutputStream();
        try (var stream = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            System.setOut(stream); CertificateScenarioCrypto.main(args);
        } finally { System.setOut(original); }
        return output.toString(StandardCharsets.UTF_8).trim();
    }

    private static HybridSdkFrame target() {
        var values = new TreeMap<Integer, byte[]>();
        values.put(1, bytes("credential.issue")); values.put(2, HybridSdkValue.object(Map.of()).encode());
        values.put(3, bytes("administrator")); values.put(4, bytes("ca")); values.put(5, bytes("issuer")); values.put(6, bytes("path"));
        values.put(7, bytes("sha512:" + "00".repeat(64)));
        values.put(8, new HybridSdkFrame(8, Map.of(1, bytes("keyring:primary"), 2, bytes(BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY.canonicalForm()),
                3, bytes(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()), 4, HybridSdkFrame.primaryAlgorithm(), 5, new byte[64])).encode());
        values.put(9, new byte[0]); values.put(10, bytes("leaf")); values.put(11, time(1));
        for (int tag = 12; tag <= 14; tag++) values.put(tag, bytes("sha256:" + "00".repeat(32)));
        for (int tag = 15; tag <= 17; tag++) values.put(tag, HybridSdkValue.object(Map.of()).encode());
        return new HybridSdkFrame(7, values);
    }

    private static void privateFile(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private Path file(String name, String text) throws Exception { return file(name, text.getBytes(StandardCharsets.US_ASCII)); }
    private static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, new byte[] {10}).encodeToString(der) + "\n-----END CERTIFICATE-----\n";
    }
    private Path file(String name, byte[] bytes) throws Exception {
        Path path = directory.resolve(name); Files.write(path, bytes); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")); return path;
    }
    private static KeyPair pair(String variant) throws Exception {
        var generator = KeyPairGenerator.getInstance(variant.equals("rsa4096") ? "RSA" : variant.equals("mldsa87") ? "ML-DSA" : "EC", "BC");
        if (variant.equals("rsa4096")) generator.initialize(4096);
        else if (variant.equals("mldsa87")) generator.initialize(MLDSAParameterSpec.ml_dsa_87);
        else generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }
    private static String signature(String variant) { return variant.equals("rsa4096") ? "SHA384withRSA" : variant.equals("mldsa87") ? "ML-DSA-87" : "SHA384withECDSA"; }
    private static byte[] certificate(String subject, String issuer, KeyPair keys, KeyPair signer, byte[] alternative, KeyPair altSigner, int pathLength, String signature) throws Exception {
        var builder = new X509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(10 + pathLength), Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plusSeconds(3600)), new X500Name(subject), SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        builder.addExtension(Extension.basicConstraints, true, pathLength < 0 ? new BasicConstraints(false) : new BasicConstraints(pathLength));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(pathLength < 0 ? KeyUsage.digitalSignature : KeyUsage.keyCertSign | KeyUsage.cRLSign));
        if (pathLength < 0) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://zeroecho.invalid/scenario/client")));
        }
        if (alternative != null) {
            builder.addExtension(Extension.subjectAltPublicKeyInfo, false, alternative);
            builder.addExtension(Extension.altSignatureAlgorithm, false, AlgorithmIdentifier.getInstance(HybridSdkFrame.alternativeAlgorithm()));
            var preliminary = builder.build(new JcaContentSignerBuilder(signature).setProvider("BC").build(signer.getPrivate()));
            byte[] transcript = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {preliminary.toASN1Structure().getTBSCertificate(), preliminary.getSignatureAlgorithm()}).getEncoded("DER");
            var signing = Signature.getInstance("ML-DSA-87", "BC"); signing.initSign(altSigner.getPrivate()); signing.update(transcript);
            builder.addExtension(Extension.altSignatureValue, false, new DERBitString(signing.sign()));
        }
        return builder.build(new JcaContentSignerBuilder(signature).setProvider("BC").build(signer.getPrivate())).getEncoded();
    }
    private static byte[] time(long value) { return ByteBuffer.allocate(8).putLong(value).array(); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
}
