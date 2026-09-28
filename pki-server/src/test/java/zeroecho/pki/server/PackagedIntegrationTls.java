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

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Ephemeral deployment identities; no test provider or host trust-store changes. */
final class PackagedIntegrationTls {
    static final String PASSWORD = "packaged-integration-only-password";
    private final Map<String, X509Certificate> certificates = new LinkedHashMap<>();

    PackagedIntegrationTls(Path directory) throws Exception {
        Files.createDirectories(directory);
        KeyPair authorityKey = keyPair();
        X509Certificate authority = certificate(authorityKey, authorityKey, "fixture-ca", true, false, 1);
        writePem(directory.resolve("ca.pem"), "CERTIFICATE", authority.getEncoded());
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD.toCharArray());
        trust.setCertificateEntry("fixture-ca", authority);
        store(directory.resolve("trust.p12"), trust);
        int serial = 2;
        for (String identity : List.of("server", "edge", "proxy", "administrator", "approver", "scoped")) {
            KeyPair key = keyPair();
            boolean server = "server".equals(identity) || "edge".equals(identity);
            X509Certificate certificate = certificate(key, authorityKey, identity, false, server, serial++);
            certificate.verify(authorityKey.getPublic());
            certificates.put(identity, certificate);
            writePem(directory.resolve(identity + ".crt"), "CERTIFICATE", certificate.getEncoded());
            writePem(directory.resolve(identity + ".key"), "PRIVATE KEY", key.getPrivate().getEncoded());
            if ("server".equals(identity)) {
                KeyStore keys = KeyStore.getInstance("PKCS12");
                keys.load(null, PASSWORD.toCharArray());
                keys.setKeyEntry(identity, key.getPrivate(), PASSWORD.toCharArray(),
                        new java.security.cert.Certificate[] { certificate, authority });
                store(directory.resolve("server.p12"), keys);
            }
        }
    }

    String fingerprint(String identity) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(certificates.get(identity).getEncoded()));
    }

    String edgeSpkiPin() throws Exception {
        return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(certificates.get("edge").getPublicKey().getEncoded()));
    }

    static KeyPair keyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(KeyPair subject, KeyPair authority, String identity,
            boolean ca, boolean server, int serial) throws Exception {
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name("CN=fixture-ca"),
                BigInteger.valueOf(serial), Date.from(now.minus(5, ChronoUnit.MINUTES)),
                Date.from(now.plus(2, ChronoUnit.DAYS)), new X500Name("CN=" + identity), subject.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca
                ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        if (!ca) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(server ? KeyPurposeId.id_kp_serverAuth : KeyPurposeId.id_kp_clientAuth));
        }
        if (server) {
            builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.dNSName, "pki-server"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1") }));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(authority.getPrivate())));
    }

    private static void store(Path path, KeyStore store) throws Exception {
        try (OutputStream output = Files.newOutputStream(path)) {
            store.store(output, PASSWORD.toCharArray());
        }
    }

    private static void writePem(Path path, String type, byte[] encoded) throws Exception {
        String body = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(encoded);
        Files.writeString(path, "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n",
                StandardCharsets.US_ASCII);
    }
}
