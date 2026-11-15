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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkProofs;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Bounded client-owned cryptography for the approved certificate scenario recipes.
 * This helper has no transport, deployment, server-store or administrative capability.
 * Generated private keys are unencrypted PKCS#8 DER in an owner-only directory.
 * It is a recipe companion and local issuer-chain verifier, outside the general PKI operation catalog.
 */
public final class CertificateScenarioCrypto {
    private static final String EC_OID = "1.2.840.10045.2.1";
    private static final String CURVE_OID = "1.3.132.0.34";
    private static final String RSA_OID = "1.2.840.113549.1.1.1";
    private static final String EC_SIGNATURE = "1.2.840.10045.4.3.3";
    private static final String RSA_SIGNATURE = "1.2.840.113549.1.1.12";
    private static final String ML_OID = "2.16.840.1.101.3.4.3.19";
    private static final String CLIENT_URI = "spiffe://zeroecho.invalid/scenario/client";
    private static final Set<String> VARIANTS = Set.of("p384", "rsa4096", "mldsa87", "hybrid");
    private CertificateScenarioCrypto() { }

    /**
     * Runs generate, sign or verify; writes only new owner-only files and prints public evidence.
     * <p>Usage: {@code generate VARIANT NEW_DIRECTORY}; {@code verify VARIANT DIRECTORY ROOT_DER
     * INTERMEDIATE_DER CLIENT_DER}; {@code sign DIRECTORY F1_FILE F2_FILE F7_FILE ORIGIN REALM_ID
     * CLIENT_NONCE_HEX EXPECTED_TARGET_SHA512_HEX EXPECTED_AUTH_CONTEXT_SHA512_HEX};
     * {@code verify-chain PEM_BUNDLE} (leaf issuer to explicitly selected self-signed anchor;
     * verifies certificate signatures and CA constraints, without asserting external trust);
     * {@code describe VARIANT}; {@code auth-context LOGIN_CERT PRINCIPAL MODE TRANSPORT_PRINCIPAL}.
     * The sign caller must independently approve the F7 semantics and construct trusted F6
     * before passing their hashes; hashes copied blindly from the challenge are insufficient.
     * @param args exact command arguments, without passwords or private material
     * @throws Exception if input, ownership, algorithms, proofs, bounds or cryptographic checks fail
     */
    public static void main(String[] args) throws Exception {
        BouncyCastleActivator.init();
        if (args.length == 2 && args[0].equals("describe")) {
            requireVariant(args[1]);
            System.out.println((switch (args[1]) { case "rsa4096" -> BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384;
                case "mldsa87" -> BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE; default -> BootstrapAlgorithmIdentities.ECDSA_SHA384; }).canonicalForm());
        } else if (args.length == 2 && args[0].equals("verify-chain")) verifyChain(Path.of(args[1]));
        else if (args.length == 5 && args[0].equals("auth-context")) authContext(args);
        else if (args.length == 3 && args[0].equals("generate")) generate(args[1], Path.of(args[2]));
        else if (args.length == 6 && args[0].equals("verify")) verify(args[1], Path.of(args[2]),
                Path.of(args[3]), Path.of(args[4]), Path.of(args[5]));
        else if (args.length == 10 && args[0].equals("sign")) sign(args);
        else throw invalid("Usage: generate VARIANT NEW_DIRECTORY | verify VARIANT DIRECTORY ROOT INTERMEDIATE CLIENT | verify-chain PEM_BUNDLE | sign DIRECTORY F1 F2 F7 ORIGIN REALM NONCE_HEX TARGET_SHA512_HEX CONTEXT_SHA512_HEX");
    }

    private static void verifyChain(Path bundle) throws Exception {
        byte[] encoded = read(bundle, 32 * 1048576);
        String pem = new String(encoded, StandardCharsets.US_ASCII);
        require(Arrays.equals(encoded, pem.getBytes(StandardCharsets.US_ASCII)), "Expected ASCII PEM chain");
        var pattern = java.util.regex.Pattern.compile("-----BEGIN CERTIFICATE-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END CERTIFICATE-----");
        var matcher = pattern.matcher(pem);
        var chain = new java.util.ArrayList<X509Certificate>();
        var identities = new java.util.HashSet<String>();
        int end = 0;
        while (matcher.find()) {
            require(pem.substring(end, matcher.start()).isBlank(), "Unexpected data between PEM certificates");
            require(chain.size() < 32, "Issuer chain exceeds 32 certificates");
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(
                    new java.io.ByteArrayInputStream(matcher.group().getBytes(StandardCharsets.US_ASCII)));
            require(identities.add(hex(digest("SHA-256", certificate.getEncoded()))), "Duplicate issuer certificate");
            chain.add(certificate);
            end = matcher.end();
        }
        require(!chain.isEmpty() && pem.substring(end).isBlank(), "Expected a nonempty PEM certificate chain");
        int subordinateCas = 0;
        for (int i = 0; i < chain.size(); i++) {
            var certificate = chain.get(i);
            var issuer = chain.get(Math.min(i + 1, chain.size() - 1));
            certificate.checkValidity();
            require(certificate.getBasicConstraints() >= subordinateCas, "CA constraints or path length forbid this issuer path");
            boolean[] usage = certificate.getKeyUsage();
            require(usage != null && usage.length > 5 && usage[5], "Issuer certificate lacks keyCertSign usage");
            require(certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()), "Issuer chain order or anchor name differs");
            var holder = new X509CertificateHolder(certificate.getEncoded());
            require(Arrays.equals(holder.getSignatureAlgorithm().getEncoded("DER"),
                    holder.toASN1Structure().getTBSCertificate().getSignature().getEncoded("DER")), "Inner and outer signature algorithms differ");
            certificate.verify(issuer.getPublicKey(), "BC");
            boolean alternative = holder.getExtension(Extension.altSignatureAlgorithm) != null
                    || holder.getExtension(Extension.altSignatureValue) != null || holder.getExtension(Extension.subjectAltPublicKeyInfo) != null;
            if (alternative) {
                require(holder.getExtension(Extension.altSignatureAlgorithm) != null
                        && holder.getExtension(Extension.altSignatureValue) != null
                        && holder.getExtension(Extension.subjectAltPublicKeyInfo) != null, "Incomplete alternative-signature certificate");
                require(Pkix.verifyAlternativeSignatureCor3(certificate, publicKey(alternativeSpki(issuer))), "Alternative issuer signature is invalid");
            }
            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) subordinateCas++;
        }
        System.out.println("VERIFIED issuer-chain certificates=" + chain.size() + " selected-anchor-sha256="
                + hex(digest("SHA-256", chain.get(chain.size() - 1).getEncoded())));
    }

    private static void authContext(String[] args) throws Exception {
        require(Set.of("direct-mtls-v1", "trusted-proxy-mtls-v1").contains(args[3]), "Unsupported authentication mode");
        require(args[3].equals("direct-mtls-v1") ? args[4].isEmpty() : !args[4].isEmpty(), "Wrong transport principal for authentication mode");
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new java.io.ByteArrayInputStream(read(Path.of(args[1]), 1048576)));
        require(certificate.getSerialNumber().signum() > 0, "Certificate serial must be positive");
        var issuerSerial = MessageDigest.getInstance("SHA-256");
        issuerSerial.update(certificate.getIssuerX500Principal().getEncoded()); issuerSerial.update((byte) 0);
        issuerSerial.update(certificate.getSerialNumber().toByteArray());
        var identity = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(Pkix.subjectPublicKeyInfo(certificate));
        var fields = java.util.Map.of("canonicalKeySha256", HybridSdkValue.text(identity.canonicalSha256()),
                "issuerSerialSha256", HybridSdkValue.text(hex(issuerSerial.digest())), "transportPrincipalId", HybridSdkValue.text(args[4]));
        var frame = new HybridSdkFrame(6, java.util.Map.of(1, bytes(args[2]), 2, bytes(args[3]),
                3, HybridSdkFrame.hash(bytes("sha256:" + hex(digest("SHA-256", certificate.getEncoded())))),
                4, bytes("admin-http-v1"), 5, HybridSdkValue.object(fields).encode()));
        System.out.println(hex(HybridSdkFrame.hash(frame.encode())));
    }

    private static void generate(String variant, Path directory) throws Exception {
        requireVariant(variant);
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        var primary = pair(variant.equals("hybrid") ? "p384" : variant);
        var extensions = new ExtensionsGenerator();
        extensions.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CLIENT_URI)));
        if (variant.equals("hybrid")) {
            var alternative = pair("mldsa87");
            write(directory.resolve("alternative.key"), alternative.getPrivate().getEncoded());
            write(directory.resolve("alternative.spki.der"), alternative.getPublic().getEncoded());
            extensions.addExtension(Extension.subjectAltPublicKeyInfo, false, alternative.getPublic().getEncoded());
        }
        byte[] csr = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=ZeroEcho scenario client"), primary.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
                .build(new JcaContentSignerBuilder(signature(variant)).setProvider("BC").build(primary.getPrivate())).getEncoded();
        write(directory.resolve("client.key"), primary.getPrivate().getEncoded());
        write(directory.resolve("client.spki.der"), primary.getPublic().getEncoded());
        write(directory.resolve("client.csr.der"), csr);
        requireCsr(directory, variant);
        if (variant.equals("hybrid")) write(directory.resolve("request-id.txt"), HybridSdkProofs.parse(csr).primary().requestId().value().getBytes(StandardCharsets.US_ASCII));
        System.out.println("GENERATED " + variant + " CSR-SHA256=" + hex(digest("SHA-256", csr)));
    }

    private static KeyPair pair(String variant) throws Exception {
        var generator = KeyPairGenerator.getInstance(switch (variant) {
            case "p384" -> "EC"; case "rsa4096" -> "RSA"; case "mldsa87" -> "ML-DSA";
            default -> throw invalid("Unsupported key variant");
        }, "BC");
        switch (variant) {
            case "p384" -> generator.initialize(new ECGenParameterSpec("secp384r1"));
            case "rsa4096" -> generator.initialize(4096);
            case "mldsa87" -> generator.initialize(MLDSAParameterSpec.ml_dsa_87);
            default -> throw invalid("Unsupported key variant");
        }
        return generator.generateKeyPair();
    }

    private static String signature(String variant) {
        return switch (variant) {
            case "p384", "hybrid" -> "SHA384withECDSA";
            case "rsa4096" -> "SHA384withRSA";
            case "mldsa87" -> "ML-DSA-87";
            default -> throw invalid("Unsupported scenario variant");
        };
    }

    private static void verify(String variant, Path directory, Path rootFile, Path intermediateFile, Path leafFile) throws Exception {
        requireVariant(variant); requireDirectory(directory); requireCsr(directory, variant);
        var root = certificate(rootFile); var intermediate = certificate(intermediateFile); var leaf = certificate(leafFile);
        List<X509Certificate> chain = List.of(root, intermediate, leaf);
        for (int i = 0; i < chain.size(); i++) {
            var certificate = chain.get(i); certificate.checkValidity();
            requireKey(certificate.getPublicKey().getEncoded(), variant.equals("hybrid") ? "p384" : variant);
            var holder = new X509CertificateHolder(certificate.getEncoded());
            var algorithm = holder.getSignatureAlgorithm();
            String expected = switch (variant) { case "rsa4096" -> RSA_SIGNATURE; case "mldsa87" -> ML_OID; default -> EC_SIGNATURE; };
            require(algorithm.getAlgorithm().getId().equals(expected), "Wrong certificate signature OID");
            require(Arrays.equals(algorithm.getEncoded("DER"), holder.toASN1Structure().getTBSCertificate().getSignature().getEncoded("DER")), "Inner and outer signature algorithms differ");
            requireParameters(algorithm, variant.equals("rsa4096"));
            if (i < 2) require(Arrays.equals(read(directory.resolve(i == 0 ? "root.spki.der" : "intermediate.spki.der"), 16384), certificate.getPublicKey().getEncoded()),
                    "CA subject key differs from selected managed key");
            var issuer = chain.get(i == 0 ? 0 : i - 1);
            require(certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()), "Wrong issuer name");
            certificate.verify(issuer.getPublicKey(), "BC");
            boolean ca = i < 2;
            require((certificate.getBasicConstraints() >= 0) == ca, "Wrong CA basic constraints");
            if (i == 0) require(certificate.getBasicConstraints() >= 1, "Root path length forbids intermediate");
            boolean[] usage = certificate.getKeyUsage();
            require(usage != null && usage.length > (ca ? 5 : 0) && usage[ca ? 5 : 0], "Missing required certificate key usage");
            if (!ca) {
                require(usage.length <= 5 || !usage[5], "Leaf may not sign certificates");
                require(certificate.getExtendedKeyUsage() != null && certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"), "Missing client authentication EKU");
            }
            if (variant.equals("hybrid")) {
                byte[] alternative = alternativeSpki(certificate); requireKey(alternative, "mldsa87");
                if (i < 2) require(Arrays.equals(read(directory.resolve(i == 0 ? "root-alternative.spki.der" : "intermediate-alternative.spki.der"), 16384), alternative),
                        "CA alternative subject key differs from selected managed key");
                var extension = holder.getExtension(Extension.altSignatureAlgorithm);
                require(extension != null && !extension.isCritical(), "Missing or critical alternative signature algorithm");
                require(Arrays.equals(extension.getExtnValue().getOctets(), HybridSdkFrame.alternativeAlgorithm()), "Wrong alternative signature algorithm");
                require(holder.getExtension(Extension.subjectAltPublicKeyInfo) != null && !holder.getExtension(Extension.subjectAltPublicKeyInfo).isCritical()
                        && holder.getExtension(Extension.altSignatureValue) != null && !holder.getExtension(Extension.altSignatureValue).isCritical(), "Missing or critical hybrid extensions");
                require(Pkix.verifyAlternativeSignatureCor3(certificate, publicKey(alternativeSpki(issuer))), "Alternative signature is invalid");
            } else require(holder.getExtension(Extension.subjectAltPublicKeyInfo) == null && holder.getExtension(Extension.altSignatureAlgorithm) == null
                    && holder.getExtension(Extension.altSignatureValue) == null, "Unexpected hybrid certificate in ordinary scenario");
            System.out.println("CERTIFICATE " + i + " SPKI-OID=" + SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded()).getAlgorithm().getAlgorithm()
                    + " SIGNATURE-OID=" + certificate.getSigAlgOID() + " SHA256=" + hex(digest("SHA-256", certificate.getEncoded()))
                    + (variant.equals("hybrid") ? " ALTERNATIVE-OID=" + ML_OID + " ALTERNATIVE-VERIFIED=true" : ""));
        }
        byte[] primary = read(directory.resolve("client.spki.der"), 16384);
        require(Arrays.equals(primary, leaf.getPublicKey().getEncoded()), "Issued subject key differs from retained client key");
        requirePossession(directory.resolve("client.key"), primary, signature(variant));
        if (variant.equals("hybrid")) {
            byte[] alternative = read(directory.resolve("alternative.spki.der"), 16384);
            require(Arrays.equals(alternative, alternativeSpki(leaf)), "Issued alternative subject key differs from retained client key");
            requirePossession(directory.resolve("alternative.key"), alternative, "ML-DSA-87");
        }
        var csr = new PKCS10CertificationRequest(read(directory.resolve("client.csr.der"), 262144));
        require(leaf.getSubjectX500Principal().equals(new javax.security.auth.x500.X500Principal(csr.getSubject().getEncoded())), "Issued subject differs from CSR");
        require(leaf.getSubjectAlternativeNames() != null && leaf.getSubjectAlternativeNames().stream()
                .anyMatch(name -> name.size() == 2 && name.get(0).equals(6) && name.get(1).equals(CLIENT_URI)), "Issued URI SAN differs from scenario request");
        System.out.println("VERIFIED " + variant + " chain, signatures, algorithms and retained client key possession");
    }

    private static void sign(String[] args) throws Exception {
        Path directory = Path.of(args[1]); requireDirectory(directory); requireCsr(directory, "hybrid");
        var first = HybridSdkFrame.decode(read(Path.of(args[2]), 1048576));
        var second = HybridSdkFrame.decode(read(Path.of(args[3]), 1048576));
        var target = HybridSdkFrame.decode(read(Path.of(args[4]), 1048576));
        require(first.kind() == 1 && second.kind() == 2 && target.kind() == 7, "Wrong SDK frame kind");
        for (int tag = 1; tag <= 17; tag++) require(Arrays.equals(first.field(tag), second.field(tag)), "F1 and F2 fields differ");
        require(text(first.field(9)).equals(args[5]) && text(first.field(2)).equals(args[6]) && text(first.field(10)).equals("admin-http-v1"), "Challenge origin, realm or mapping differs");
        require(Arrays.equals(first.field(6), unhex(args[7], 32)), "Challenge client nonce differs");
        long now = Instant.now().getEpochSecond();
        require(now >= ByteBuffer.wrap(first.field(7)).getLong() && now < ByteBuffer.wrap(first.field(8)).getLong(), "Challenge is not currently valid");
        require(Arrays.equals(first.field(11), HybridSdkFrame.hash(read(directory.resolve("client.csr.der"), 262144))), "Challenge request differs");
        require(Arrays.equals(first.field(13), HybridSdkFrame.hash(read(directory.resolve("client.spki.der"), 16384))), "Challenge primary subject key differs");
        require(Arrays.equals(first.field(14), HybridSdkFrame.hash(read(directory.resolve("alternative.spki.der"), 16384))), "Challenge alternative subject key differs");
        byte[] expectedTarget = unhex(args[8], 64);
        require(Arrays.equals(HybridSdkFrame.hash(target.encode()), expectedTarget) && Arrays.equals(first.field(17), expectedTarget), "Challenge target differs from approved target");
        require(Arrays.equals(first.field(12), unhex(args[9], 64)), "Challenge authentication context differs");
        require(!Files.exists(directory.resolve("primary.proof"), LinkOption.NOFOLLOW_LINKS)
                && !Files.exists(directory.resolve("alternative.proof"), LinkOption.NOFOLLOW_LINKS), "Proof files already exist");
        byte[] primary = signFile(directory.resolve("client.key"), "SHA384withECDSA", first.encode());
        byte[] alternative = signFile(directory.resolve("alternative.key"), "ML-DSA-87", second.encode());
        HybridSdkProofs.verify(HybridSdkProofs.parse(read(directory.resolve("client.csr.der"), 262144)), first, primary, alternative, Instant.now());
        write(directory.resolve("primary.proof"), primary); write(directory.resolve("alternative.proof"), alternative);
        System.out.println("SIGNED exact approved F1 and F2");
    }

    private static void requireCsr(Path directory, String variant) throws Exception {
        requireDirectory(directory);
        byte[] encoded = read(directory.resolve("client.csr.der"), 262144);
        var csr = new PKCS10CertificationRequest(encoded);
        require(Arrays.equals(encoded, csr.getEncoded()), "Noncanonical CSR");
        byte[] primary = read(directory.resolve("client.spki.der"), 16384);
        requireKey(primary, variant.equals("hybrid") ? "p384" : variant);
        require(Arrays.equals(primary, csr.getSubjectPublicKeyInfo().getEncoded()), "Retained CSR primary key differs");
        require(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider("BC").build(publicKey(primary))), "Invalid native CSR proof");
        requirePossession(directory.resolve("client.key"), primary, signature(variant));
        if (variant.equals("hybrid")) {
            HybridSdkProofs.parse(encoded);
            byte[] alternative = read(directory.resolve("alternative.spki.der"), 16384); requireKey(alternative, "mldsa87");
            var attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            require(attributes.length == 1 && attributes[0].getAttrValues().size() == 1, "Wrong SDK CSR extension request");
            var extensions = org.bouncycastle.asn1.x509.Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
            var extension = extensions.getExtension(Extension.subjectAltPublicKeyInfo);
            require(extension != null && !extension.isCritical() && Arrays.equals(alternative, extension.getExtnValue().getOctets()), "Retained CSR alternative key differs");
            requirePossession(directory.resolve("alternative.key"), alternative, "ML-DSA-87");
        }
    }

    private static void requirePossession(Path keyFile, byte[] spki, String algorithm) throws Exception {
        byte[] challenge = "ZeroEcho C04 local retained-key possession check".getBytes(StandardCharsets.US_ASCII);
        byte[] signed = signFile(keyFile, algorithm, challenge);
        var verifier = Signature.getInstance(algorithm, "BC"); verifier.initVerify(publicKey(spki)); verifier.update(challenge);
        require(verifier.verify(signed), "Private key does not match retained public key");
    }

    private static byte[] signFile(Path keyFile, String algorithm, byte[] message) throws Exception {
        String family = algorithm.equals("ML-DSA-87") ? "ML-DSA" : algorithm.endsWith("ECDSA") ? "EC" : "RSA";
        PrivateKey key = KeyFactory.getInstance(family, "BC").generatePrivate(new PKCS8EncodedKeySpec(read(keyFile, 32768)));
        var signer = Signature.getInstance(algorithm, "BC"); signer.initSign(key); signer.update(message); return signer.sign();
    }

    private static PublicKey publicKey(byte[] encoded) throws Exception {
        String oid = SubjectPublicKeyInfo.getInstance(encoded).getAlgorithm().getAlgorithm().getId();
        String family = oid.equals(EC_OID) ? "EC" : oid.equals(RSA_OID) ? "RSA" : oid.equals(ML_OID) ? "ML-DSA" : "unsupported";
        return KeyFactory.getInstance(family, "BC").generatePublic(new X509EncodedKeySpec(encoded));
    }

    private static void requireKey(byte[] encoded, String variant) throws Exception {
        var spki = SubjectPublicKeyInfo.getInstance(encoded);
        require(Arrays.equals(encoded, spki.getEncoded("DER")) && spki.getPublicKeyData().getPadBits() == 0, "Noncanonical SPKI");
        var algorithm = spki.getAlgorithm(); String oid = algorithm.getAlgorithm().getId();
        switch (variant) {
            case "p384" -> {
                require(oid.equals(EC_OID) && algorithm.getParameters() instanceof ASN1ObjectIdentifier
                        && algorithm.getParameters().equals(new ASN1ObjectIdentifier(CURVE_OID)), "Expected named P-384 key");
                require(spki.getPublicKeyData().getBytes().length == 97 && spki.getPublicKeyData().getBytes()[0] == 4, "Expected uncompressed P-384 point");
            }
            case "rsa4096" -> {
                require(oid.equals(RSA_OID), "Expected RSA key"); requireParameters(algorithm, true);
                require(((RSAPublicKey) publicKey(encoded)).getModulus().bitLength() == 4096, "Expected RSA-4096 modulus");
            }
            case "mldsa87" -> {
                require(oid.equals(ML_OID) && algorithm.getParameters() == null && spki.getPublicKeyData().getBytes().length == 2592, "Expected pure ML-DSA-87 key");
            }
            default -> throw invalid("Unsupported scenario key variant");
        }
        publicKey(encoded);
    }

    private static void requireParameters(AlgorithmIdentifier algorithm, boolean nullRequired) {
        require(nullRequired ? algorithm.getParameters() instanceof org.bouncycastle.asn1.ASN1Null : algorithm.getParameters() == null,
                "Unexpected AlgorithmIdentifier parameters");
    }
    private static byte[] alternativeSpki(X509Certificate certificate) {
        byte[] value = certificate.getExtensionValue(Extension.subjectAltPublicKeyInfo.getId());
        require(value != null, "Missing alternative subject key"); return ASN1OctetString.getInstance(value).getOctets();
    }
    private static X509Certificate certificate(Path path) throws Exception {
        byte[] bytes = read(path, 1048576);
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new java.io.ByteArrayInputStream(bytes));
        require(Arrays.equals(bytes, certificate.getEncoded()), "Certificate is not exact DER"); return certificate;
    }
    private static byte[] read(Path path, int maximum) throws Exception {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path), "Expected regular owned file");
        require(Files.getOwner(path).equals(Files.getOwner(Path.of(System.getProperty("user.home"))))
                && Files.getPosixFilePermissions(path).stream().noneMatch(permission -> permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_")), "Expected owner-only file");
        require(Files.size(path) > 0 && Files.size(path) <= maximum, "File exceeds size bounds"); return Files.readAllBytes(path);
    }
    private static void requireDirectory(Path path) throws Exception {
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)
                && Files.getOwner(path).equals(Files.getOwner(Path.of(System.getProperty("user.home"))))
                && Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rwx------")), "Expected owned private directory");
    }
    private static void write(Path path, byte[] bytes) throws Exception {
        try (var output = Files.newByteChannel(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) { var buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) output.write(buffer); }
    }
    private static void requireVariant(String variant) { require(VARIANTS.contains(variant), "Unsupported scenario variant"); }
    private static byte[] digest(String algorithm, byte[] bytes) throws Exception { return MessageDigest.getInstance(algorithm).digest(bytes); }
    private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    private static byte[] unhex(String text, int length) { require(text.matches("[0-9a-f]{" + length * 2 + "}"), "Expected canonical hex"); return HexFormat.of().parseHex(text); }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }
    private static void require(boolean condition, String message) { if (!condition) throw invalid(message); }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
