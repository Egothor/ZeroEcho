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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkProofs;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CertificationRequestBuilder;
import zeroecho.pkix.csr.CsrAttribute;
import java.security.spec.NamedParameterSpec;
import zeroecho.pkix.PublicKeyIdentity;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * Bounded client-owned cryptography for the approved certificate scenario recipes.
 * This helper has no transport, deployment, server-store or administrative capability.
 * Generated private keys are unencrypted PKCS#8 DER in an owner-only directory.
 * It is a recipe companion and local issuer-chain verifier, outside the general PKI operation catalog.
 */
public final class CertificateScenarioCrypto {
    private static final String P384 = "p384";
    private static final String RSA4096 = "rsa4096";
    private static final String MLDSA87 = "mldsa87";
    private static final String HYBRID = "hybrid";
    private static final String SHA256 = "SHA-256";
    private static final String EC_OID = "1.2.840.10045.2.1";
    private static final String RSA_OID = "1.2.840.113549.1.1.1";
    private static final String EC_SIGNATURE = "1.2.840.10045.4.3.3";
    private static final String RSA_SIGNATURE = "1.2.840.113549.1.1.12";
    private static final String MLDSA_SIGNATURE = "ML-DSA-87";
    private static final String ML_OID = "2.16.840.1.101.3.4.3.19";
    // X.509 extension object identifiers are not IP addresses.
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private static final String ALT_SPKI = "2.5.29.72";
    // X.509 extension object identifiers are not IP addresses.
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private static final String ALT_ALGORITHM = "2.5.29.73";
    // X.509 extension object identifiers are not IP addresses.
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private static final String ALT_SIGNATURE = "2.5.29.74";
    private static final String EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
    private static final String CLIENT_URI = "spiffe://zeroecho.invalid/scenario/client";
    private static final Set<String> VARIANTS = Set.of(P384, RSA4096, MLDSA87, HYBRID);
    private CertificateScenarioCrypto() { }

    /**
     * Executes one client-owned certificate-scenario operation and writes its public result to standard output.
     *
     * <p>The supported command forms are:
     * <ul>
     *   <li>{@code generate VARIANT NEW_DIRECTORY}: create client keys, public-key
     *       encodings and a CSR for {@code p384}, {@code rsa4096}, {@code mldsa87}
     *       or {@code hybrid} in a new directory;</li>
     *   <li>{@code verify VARIANT DIRECTORY ROOT_DER INTERMEDIATE_DER CLIENT_DER}:
     *       check the fixed certificate chain, requested identities, algorithm
     *       profile and possession of the retained client keys;</li>
     *   <li>{@code verify-chain PEM_BUNDLE}: validate the ordered issuer chain to
     *       its supplied self-signed anchor, without establishing external trust
     *       in that anchor;</li>
     *   <li>{@code sign DIRECTORY F1_FILE F2_FILE F7_FILE ORIGIN REALM_ID
     *       CLIENT_NONCE_HEX EXPECTED_TARGET_SHA512_HEX EXPECTED_AUTH_CONTEXT_SHA512_HEX}:
     *       verify the supplied challenge bindings and create the two hybrid proof files;</li>
     *   <li>{@code describe VARIANT}: print the scenario's canonical signing-algorithm identity;</li>
     *   <li>{@code auth-context LOGIN_CERT PRINCIPAL MODE TRANSPORT_PRINCIPAL}:
     *       print the authentication-context commitment for the supplied public inputs.</li>
     * </ul>
     *
     * <p>Generation and signing use client-owned files and request owner-only POSIX
     * permissions for newly created artifacts. The filesystem must support those
     * attributes. Existing output files are not replaced. Failure can leave a
     * partially populated directory or a subset of output files; the operation
     * does not provide transactional rollback. Private keys written by generation
     * are unencrypted PKCS#8 DER and must remain under the client's control.
     *
     * <p>The signing caller must independently approve the F7 target semantics and
     * construct the trusted F6 authentication context before supplying their
     * expected hashes. Copying those hashes from an untrusted challenge does not
     * provide that approval. The helper performs no deployment, server-store
     * access or administrative operation. It initializes the library's
     * cryptographic providers before processing the command.
     *
     * @param args the command and its exact operands; the array and required
     *     operands must not be {@code null}; arguments contain public values and
     *     local paths, not passwords or private-key material
     * @throws IOException if a bounded local input cannot be read or a new output
     *     cannot be created or written
     * @throws GeneralSecurityException if a cryptographic operation cannot be
     *     performed or certificate validation fails
     * @throws IllegalArgumentException if the command, variant, representation or
     *     scenario bindings are invalid
     * @throws NullPointerException if {@code args} or a required referenced operand is null
     * @throws UnsupportedOperationException if the filesystem cannot apply the
     *     requested POSIX creation attributes
     */
    public static void main(String... args) throws IOException, GeneralSecurityException {
        BouncyCastleActivator.init();
        if (args.length == 2 && "describe".equals(args[0])) {
            requireVariant(args[1]);
            System.out.println((switch (args[1]) { case RSA4096 -> BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384;
                case MLDSA87 -> BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE; default -> BootstrapAlgorithmIdentities.ECDSA_SHA384; }).canonicalForm());
        } else if (args.length == 2 && "verify-chain".equals(args[0])) { verifyChain(Path.of(args[1])); }
        else if (args.length == 5 && "auth-context".equals(args[0])) { authContext(args); }
        else if (args.length == 3 && "generate".equals(args[0])) { generate(args[1], Path.of(args[2])); }
        else if (args.length == 6 && "verify".equals(args[0])) { IssuedChainVerifier.verify(args[1], Path.of(args[2]),
                Path.of(args[3]), Path.of(args[4]), Path.of(args[5])); }
        else if (args.length == 10 && "sign".equals(args[0])) { sign(args); }
        else { throw invalid("Usage: generate VARIANT NEW_DIRECTORY | verify VARIANT DIRECTORY ROOT INTERMEDIATE CLIENT | verify-chain PEM_BUNDLE | sign DIRECTORY F1 F2 F7 ORIGIN REALM NONCE_HEX TARGET_SHA512_HEX CONTEXT_SHA512_HEX"); }
    }

    private static void verifyChain(Path bundle) throws IOException, GeneralSecurityException {
        byte[] encoded = read(bundle, 32 * 1_048_576);
        String pem = new String(encoded, StandardCharsets.US_ASCII);
        require(Arrays.equals(encoded, pem.getBytes(StandardCharsets.US_ASCII)), "Expected ASCII PEM chain");
        Pattern pattern = Pattern.compile("-----BEGIN CERTIFICATE-----\\r?\\n[A-Za-z0-9+/=\\r\\n]+-----END CERTIFICATE-----");
        Matcher matcher = pattern.matcher(pem);
        List<X509Certificate> chain = new ArrayList<>();
        Set<String> identities = new HashSet<>();
        int end = 0;
        while (matcher.find()) {
            require(pem.substring(end, matcher.start()).isBlank(), "Unexpected data between PEM certificates");
            require(chain.size() < 32, "Issuer chain exceeds 32 certificates");
            X509Certificate certificate = decodeCertificate(matcher.group().getBytes(StandardCharsets.US_ASCII));
            require(identities.add(hex(digest(SHA256, certificate.getEncoded()))), "Duplicate issuer certificate");
            chain.add(certificate);
            end = matcher.end();
        }
        require(!chain.isEmpty() && pem.substring(end).isBlank(), "Expected a nonempty PEM certificate chain");
        int subordinateCas = 0;
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate certificate = chain.get(i);
            X509Certificate issuer = chain.get(Math.min(i + 1, chain.size() - 1));
            certificate.checkValidity();
            require(certificate.getBasicConstraints() >= subordinateCas, "CA constraints or path length forbid this issuer path");
            boolean[] usage = certificate.getKeyUsage();
            require(usage != null && usage.length > 5 && usage[5], "Issuer certificate lacks keyCertSign usage");
            require(certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()), "Issuer chain order or anchor name differs");
            requireCertificateEncoding(certificate);
            certificate.verify(issuer.getPublicKey(), "BC");
            verifyIssuerAlternative(certificate, issuer);
            if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) { subordinateCas++; }
        }
        System.out.println("VERIFIED issuer-chain certificates=" + chain.size() + " selected-anchor-sha256="
                + hex(digest(SHA256, chain.get(chain.size() - 1).getEncoded())));
    }

    private static void verifyIssuerAlternative(X509Certificate certificate, X509Certificate issuer)
            throws IOException, GeneralSecurityException {
        Map<String, CertificateExtension> extensions = extensions(certificate);
        boolean alternative = extensions.containsKey(ALT_ALGORITHM) || extensions.containsKey(ALT_SIGNATURE)
                || extensions.containsKey(ALT_SPKI);
        if (alternative) {
            require(extensions.containsKey(ALT_ALGORITHM) && extensions.containsKey(ALT_SIGNATURE)
                    && extensions.containsKey(ALT_SPKI), "Incomplete alternative-signature certificate");
            require(Pkix.verifyAlternativeSignatureCor3(certificate, publicKey(alternativeSpki(issuer))), "Alternative issuer signature is invalid");
        }
    }

    private static void authContext(String... args) throws IOException, GeneralSecurityException {
        require(Set.of("direct-mtls-v1", "trusted-proxy-mtls-v1").contains(args[3]), "Unsupported authentication mode");
        require("direct-mtls-v1".equals(args[3]) ? args[4].isEmpty() : !args[4].isEmpty(), "Wrong transport principal for authentication mode");
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC")
                .generateCertificate(new ByteArrayInputStream(read(Path.of(args[1]), 1_048_576)));
        require(certificate.getSerialNumber().signum() > 0, "Certificate serial must be positive");
        MessageDigest issuerSerial = MessageDigest.getInstance(SHA256);
        issuerSerial.update(certificate.getIssuerX500Principal().getEncoded()); issuerSerial.update((byte) 0);
        issuerSerial.update(certificate.getSerialNumber().toByteArray());
        PublicKeyIdentity identity = PublicKeyIdentity.fromSubjectPublicKeyInfo(Pkix.subjectPublicKeyInfo(certificate));
        Map<String, HybridSdkValue> fields = Map.of("canonicalKeySha256", HybridSdkValue.text(identity.canonicalSha256()),
                "issuerSerialSha256", HybridSdkValue.text(hex(issuerSerial.digest())), "transportPrincipalId", HybridSdkValue.text(args[4]));
        HybridSdkFrame frame = new HybridSdkFrame(6, Map.of(1, bytes(args[2]), 2, bytes(args[3]),
                3, HybridSdkFrame.hash(bytes("sha256:" + hex(digest(SHA256, certificate.getEncoded())))),
                4, bytes("admin-http-v1"), 5, HybridSdkValue.object(fields).encode()));
        System.out.println(hex(HybridSdkFrame.hash(frame.encode())));
    }

    private static void generate(String variant, Path directory) throws IOException, GeneralSecurityException {
        requireVariant(variant);
        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        KeyPair primary = pair(HYBRID.equals(variant) ? P384 : variant);
        CertificationRequestBuilder builder = Pkix.certificationRequestBuilder()
                .subject(new javax.security.auth.x500.X500Principal("CN=ZeroEcho scenario client"))
                .publicKey(primary.getPublic())
                .subjectAlternativeNames(List.of(new GeneralName.UniformResourceIdentifier(CLIENT_URI)), false);
        if (HYBRID.equals(variant)) {
            KeyPair alternative = pair(MLDSA87);
            write(directory.resolve("alternative.key"), alternative.getPrivate().getEncoded());
            write(directory.resolve("alternative.spki.der"), alternative.getPublic().getEncoded());
            builder.requestExtension(new CertificateExtension(ALT_SPKI, false, alternative.getPublic().getEncoded()));
        }
        AlgorithmIdentifier algorithm = switch (variant) {
            case RSA4096 -> AlgorithmIdentifier.derNull(RSA_SIGNATURE);
            case MLDSA87 -> AlgorithmIdentifier.absent(ML_OID);
            default -> AlgorithmIdentifier.absent(EC_SIGNATURE);
        };
        byte[] csr = builder.build(Pkix.signer(primary.getPrivate(), algorithm)).encoded();
        write(directory.resolve("client.key"), primary.getPrivate().getEncoded());
        write(directory.resolve("client.spki.der"), primary.getPublic().getEncoded());
        write(directory.resolve("client.csr.der"), csr);
        requireCsr(directory, variant);
        if (HYBRID.equals(variant)) { write(directory.resolve("request-id.txt"), HybridSdkProofs.parse(csr).primary().requestId().value().getBytes(StandardCharsets.US_ASCII)); }
        System.out.println("GENERATED " + variant + " CSR-SHA256=" + hex(digest(SHA256, csr)));
    }

    private static KeyPair pair(String variant) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(switch (variant) {
            case P384 -> "EC"; case RSA4096 -> "RSA"; case MLDSA87 -> "ML-DSA";
            default -> throw invalid("Unsupported key variant");
        }, "BC");
        switch (variant) {
            case P384 -> generator.initialize(new ECGenParameterSpec("secp384r1"));
            case RSA4096 -> generator.initialize(4096);
            case MLDSA87 -> generator.initialize(new NamedParameterSpec(MLDSA_SIGNATURE));
            default -> throw invalid("Unsupported key variant");
        }
        return generator.generateKeyPair();
    }

    private static String signature(String variant) {
        return switch (variant) {
            case P384, HYBRID -> "SHA384withECDSA";
            case RSA4096 -> "SHA384withRSA";
            case MLDSA87 -> MLDSA_SIGNATURE;
            default -> throw invalid("Unsupported scenario variant");
        };
    }

    /**
     * Checks the fixed scenario chain against retained key material and requested certificate identities.
     *
     * <p>The selected root is an explicit test input, not a newly discovered trust
     * anchor. Successful scenario verification does not grant it external trust.
     */
    private static final class IssuedChainVerifier {
        private static final int CA_COUNT = 2;
        private static void verify(String variant, Path directory, Path rootFile, Path intermediateFile, Path leafFile) throws IOException, GeneralSecurityException {
            requireVariant(variant); requireDirectory(directory); requireCsr(directory, variant);
            X509Certificate root = certificate(rootFile); X509Certificate intermediate = certificate(intermediateFile); X509Certificate leaf = certificate(leafFile);
            List<X509Certificate> chain = List.of(root, intermediate, leaf);
            for (int i = 0; i < chain.size(); i++) {
                X509Certificate certificate = chain.get(i);
                X509Certificate issuer = chain.get(i == 0 ? 0 : i - 1);
                verifyCertificate(variant, directory, certificate, issuer, i);
            }
            byte[] primary = read(directory.resolve("client.spki.der"), 16_384);
            require(Arrays.equals(primary, leaf.getPublicKey().getEncoded()), "Issued subject key differs from retained client key");
            requirePossession(directory.resolve("client.key"), primary, signature(variant));
            if (HYBRID.equals(variant)) {
                byte[] alternative = read(directory.resolve("alternative.spki.der"), 16_384);
                require(Arrays.equals(alternative, alternativeSpki(leaf)), "Issued alternative subject key differs from retained client key");
                requirePossession(directory.resolve("alternative.key"), alternative, MLDSA_SIGNATURE);
            }
            CertificationRequest csr = Pkix.parseCertificationRequest(read(directory.resolve("client.csr.der"), 262_144));
            require(leaf.getSubjectX500Principal().equals(csr.subject()), "Issued subject differs from CSR");
            require(leaf.getSubjectAlternativeNames() != null && leaf.getSubjectAlternativeNames().stream()
                    .anyMatch(name -> name.size() == 2 && name.get(0).equals(6) && CLIENT_URI.equals(name.get(1))), "Issued URI SAN differs from scenario request");
            System.out.println("VERIFIED " + variant + " chain, signatures, algorithms and retained client key possession");
        }


        private static void verifyCertificate(String variant, Path directory, X509Certificate certificate,
                X509Certificate issuer, int i) throws IOException, GeneralSecurityException {
            verifyPrimary(variant, directory, certificate, issuer, i);
            verifyHybrid(variant, directory, certificate, issuer, i);
            System.out.println("CERTIFICATE " + i + " SPKI-OID=" + Pkix.subjectPublicKeyAlgorithm(certificate.getPublicKey().getEncoded()).oid()
                    + " SIGNATURE-OID=" + certificate.getSigAlgOID() + " SHA256=" + hex(digest(SHA256, certificate.getEncoded()))
                    + (HYBRID.equals(variant) ? " ALTERNATIVE-OID=" + ML_OID + " ALTERNATIVE-VERIFIED=true" : ""));
        }

        private static void verifyPrimary(String variant, Path directory, X509Certificate certificate,
                X509Certificate issuer, int i) throws IOException, GeneralSecurityException {
            certificate.checkValidity();
            KeyEncoding.requireKey(certificate.getPublicKey().getEncoded(), HYBRID.equals(variant) ? P384 : variant);
            AlgorithmIdentifier algorithm = signatureAlgorithm(certificate);
            String expected = switch (variant) { case RSA4096 -> RSA_SIGNATURE; case MLDSA87 -> ML_OID; default -> EC_SIGNATURE; };
            require(expected.equals(algorithm.oid()), "Wrong certificate signature OID");
            requireCertificateEncoding(certificate);
            KeyEncoding.requireParameters(algorithm, RSA4096.equals(variant));
            if (i < CA_COUNT) { require(Arrays.equals(read(directory.resolve(i == 0 ? "root.spki.der" : "intermediate.spki.der"), 16_384), certificate.getPublicKey().getEncoded()),
                    "CA subject key differs from selected managed key"); }
            require(certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()), "Wrong issuer name");
            certificate.verify(issuer.getPublicKey(), "BC");
            verifyUsage(certificate, i);

        }

        private static void verifyUsage(X509Certificate certificate, int i) throws GeneralSecurityException {
            boolean ca = i < CA_COUNT;
            require((certificate.getBasicConstraints() >= 0) == ca, "Wrong CA basic constraints");
            if (i == 0) { require(certificate.getBasicConstraints() >= 1, "Root path length forbids intermediate"); }
            boolean[] usage = certificate.getKeyUsage();
            require(usage != null && usage.length > (ca ? 5 : 0) && usage[ca ? 5 : 0], "Missing required certificate key usage");
            if (!ca) {
                require(usage.length <= 5 || !usage[5], "Leaf may not sign certificates");
                require(certificate.getExtendedKeyUsage() != null && certificate.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"), "Missing client authentication EKU");
            }
        }

        private static void verifyHybrid(String variant, Path directory, X509Certificate certificate,
                X509Certificate issuer, int i) throws IOException, GeneralSecurityException {
            if (HYBRID.equals(variant)) {
                byte[] alternative = alternativeSpki(certificate); KeyEncoding.requireKey(alternative, MLDSA87);
                if (i < CA_COUNT) { require(Arrays.equals(read(directory.resolve(i == 0 ? "root-alternative.spki.der" : "intermediate-alternative.spki.der"), 16_384), alternative),
                        "CA alternative subject key differs from selected managed key"); }
                Map<String, CertificateExtension> extensions = extensions(certificate);
                CertificateExtension extension = extensions.get(ALT_ALGORITHM);
                require(extension != null && !extension.critical(), "Missing or critical alternative signature algorithm");
                require(Arrays.equals(extension.derValue(), HybridSdkFrame.alternativeAlgorithm()), "Wrong alternative signature algorithm");
                require(extensions.containsKey(ALT_SPKI) && !extensions.get(ALT_SPKI).critical()
                        && extensions.containsKey(ALT_SIGNATURE) && !extensions.get(ALT_SIGNATURE).critical(), "Missing or critical hybrid extensions");
                require(Pkix.verifyAlternativeSignatureCor3(certificate, publicKey(alternativeSpki(issuer))), "Alternative signature is invalid");
            } else {
                Map<String, CertificateExtension> extensions = extensions(certificate);
                require(!extensions.containsKey(ALT_SPKI) && !extensions.containsKey(ALT_ALGORITHM)
                        && !extensions.containsKey(ALT_SIGNATURE), "Unexpected hybrid certificate in ordinary scenario");
            }
        }
    }

    private static void sign(String... args) throws IOException, GeneralSecurityException {
        Path directory = Path.of(args[1]); requireDirectory(directory); requireCsr(directory, HYBRID);
        HybridSdkFrame first = HybridSdkFrame.decode(read(Path.of(args[2]), 1_048_576));
        HybridSdkFrame second = HybridSdkFrame.decode(read(Path.of(args[3]), 1_048_576));
        HybridSdkFrame target = HybridSdkFrame.decode(read(Path.of(args[4]), 1_048_576));
        require(first.kind() == 1 && second.kind() == 2 && target.kind() == 7, "Wrong SDK frame kind");
        for (int tag = 1; tag <= 17; tag++) { require(Arrays.equals(first.field(tag), second.field(tag)), "F1 and F2 fields differ"); }
        require(text(first.field(9)).equals(args[5]) && text(first.field(2)).equals(args[6]) && "admin-http-v1".equals(text(first.field(10))), "Challenge origin, realm or mapping differs");
        require(Arrays.equals(first.field(6), unhex(args[7], 32)), "Challenge client nonce differs");
        long now = Instant.now().getEpochSecond();
        require(now >= ByteBuffer.wrap(first.field(7)).getLong() && now < ByteBuffer.wrap(first.field(8)).getLong(), "Challenge is not currently valid");
        require(Arrays.equals(first.field(11), HybridSdkFrame.hash(read(directory.resolve("client.csr.der"), 262_144))), "Challenge request differs");
        require(Arrays.equals(first.field(13), HybridSdkFrame.hash(read(directory.resolve("client.spki.der"), 16_384))), "Challenge primary subject key differs");
        require(Arrays.equals(first.field(14), HybridSdkFrame.hash(read(directory.resolve("alternative.spki.der"), 16_384))), "Challenge alternative subject key differs");
        byte[] expectedTarget = unhex(args[8], 64);
        require(Arrays.equals(HybridSdkFrame.hash(target.encode()), expectedTarget) && Arrays.equals(first.field(17), expectedTarget), "Challenge target differs from approved target");
        require(Arrays.equals(first.field(12), unhex(args[9], 64)), "Challenge authentication context differs");
        require(!Files.exists(directory.resolve("primary.proof"), LinkOption.NOFOLLOW_LINKS)
                && !Files.exists(directory.resolve("alternative.proof"), LinkOption.NOFOLLOW_LINKS), "Proof files already exist");
        byte[] primary = signFile(directory.resolve("client.key"), "SHA384withECDSA", first.encode());
        byte[] alternative = signFile(directory.resolve("alternative.key"), MLDSA_SIGNATURE, second.encode());
        HybridSdkProofs.verify(HybridSdkProofs.parse(read(directory.resolve("client.csr.der"), 262_144)), first, primary, alternative, Instant.now());
        write(directory.resolve("primary.proof"), primary); write(directory.resolve("alternative.proof"), alternative);
        System.out.println("SIGNED exact approved F1 and F2");
    }

    private static void requireCsr(Path directory, String variant) throws IOException, GeneralSecurityException {
        requireDirectory(directory);
        byte[] encoded = read(directory.resolve("client.csr.der"), 262_144);
        CertificationRequest csr = Pkix.parseCertificationRequest(encoded);
        require(Arrays.equals(encoded, csr.encoded()), "Noncanonical CSR");
        byte[] primary = read(directory.resolve("client.spki.der"), 16_384);
        KeyEncoding.requireKey(primary, HYBRID.equals(variant) ? P384 : variant);
        require(Arrays.equals(primary, csr.subjectPublicKeyInfo()), "Retained CSR primary key differs");
        require(csr.verifySelfSignature(), "Invalid native CSR proof");
        requirePossession(directory.resolve("client.key"), primary, signature(variant));
        if (HYBRID.equals(variant)) {
            HybridSdkProofs.parse(encoded);
            byte[] alternative = read(directory.resolve("alternative.spki.der"), 16_384); KeyEncoding.requireKey(alternative, MLDSA87);
            List<CsrAttribute> attributes = csr.rawAttributes().stream()
                    .filter(attribute -> EXTENSION_REQUEST.equals(attribute.oid())).toList();
            require(attributes.size() == 1 && attributes.getFirst().derValues().size() == 1, "Wrong SDK CSR extension request");
            List<CertificateExtension> extensions = Pkix.parseExtensions(attributes.getFirst().derValues().getFirst());
            CertificateExtension extension = extensions.stream().filter(value -> ALT_SPKI.equals(value.oid())).findFirst().orElse(null);
            require(extension != null && !extension.critical() && Arrays.equals(alternative, extension.derValue()), "Retained CSR alternative key differs");
            requirePossession(directory.resolve("alternative.key"), alternative, MLDSA_SIGNATURE);
        }
    }

    private static void requirePossession(Path keyFile, byte[] spki, String algorithm) throws IOException, GeneralSecurityException {
        byte[] challenge = "ZeroEcho C04 local retained-key possession check".getBytes(StandardCharsets.US_ASCII);
        byte[] signed = signFile(keyFile, algorithm, challenge);
        Signature verifier = Signature.getInstance(algorithm, "BC"); verifier.initVerify(publicKey(spki)); verifier.update(challenge);
        require(verifier.verify(signed), "Private key does not match retained public key");
    }

    private static byte[] signFile(Path keyFile, String algorithm, byte[] message) throws IOException, GeneralSecurityException {
        String family = MLDSA_SIGNATURE.equals(algorithm) ? "ML-DSA" : algorithm.endsWith("ECDSA") ? "EC" : "RSA";
        PrivateKey key = KeyFactory.getInstance(family, "BC").generatePrivate(new PKCS8EncodedKeySpec(read(keyFile, 32_768)));
        Signature signer = Signature.getInstance(algorithm, "BC"); signer.initSign(key); signer.update(message); return signer.sign();
    }

    private static PublicKey publicKey(byte[] encoded) {
        return Pkix.publicKeyFromSubjectPublicKeyInfo(encoded);
    }

    /**
     * Enforces the exact canonical public-key encodings selected by each scenario suite.
     *
     * <p>These checks bind algorithm identifiers, parameter forms and key sizes
     * before retained keys are used for proof or certificate verification.
     */
    private static final class KeyEncoding {
        private static void requireKey(byte[] encoded, String variant) throws IOException, GeneralSecurityException {
            AlgorithmIdentifier algorithm = Pkix.subjectPublicKeyAlgorithm(encoded);
            byte[] bits = Pkix.subjectPublicKeyBytes(encoded);
            require(Arrays.equals(encoded, Pkix.buildSubjectPublicKeyInfo(algorithm, bits)), "Noncanonical SPKI");
            String oid = algorithm.oid();
            switch (variant) {
                case P384 -> {
                    require(EC_OID.equals(oid) && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.EXACT_DER
                            && Arrays.equals(algorithm.parameters(), HexFormat.of().parseHex("06052b81040022")), "Expected named P-384 key");
                    require(bits.length == 97 && bits[0] == 4, "Expected uncompressed P-384 point");
                }
                case RSA4096 -> {
                    require(RSA_OID.equals(oid), "Expected RSA key"); requireParameters(algorithm, true);
                    require(((RSAPublicKey) publicKey(encoded)).getModulus().bitLength() == 4096, "Expected RSA-4096 modulus");
                }
                case MLDSA87 -> require(ML_OID.equals(oid) && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.ABSENT
                        && bits.length == 2592, "Expected pure ML-DSA-87 key");
                default -> throw invalid("Unsupported scenario key variant");
            }
            publicKey(encoded);
        }

        private static void requireParameters(AlgorithmIdentifier algorithm, boolean nullRequired) {
            require(algorithm.parameterForm() == (nullRequired ? AlgorithmIdentifier.ParameterForm.DER_NULL
                    : AlgorithmIdentifier.ParameterForm.ABSENT), "Unexpected AlgorithmIdentifier parameters");
        }
    }

    private static Map<String, CertificateExtension> extensions(X509Certificate certificate) {
        Map<String, CertificateExtension> extensions = new java.util.HashMap<>();
        for (CertificateExtension extension : Pkix.certificateExtensions(certificate)) {
            require(extensions.put(extension.oid(), extension) == null, "Duplicate certificate extension");
        }
        return extensions;
    }

    private static byte[] alternativeSpki(X509Certificate certificate) {
        CertificateExtension extension = extensions(certificate).get(ALT_SPKI);
        require(extension != null, "Missing alternative subject key");
        return extension.derValue();
    }

    private static AlgorithmIdentifier signatureAlgorithm(X509Certificate certificate) {
        byte[] parameters = certificate.getSigAlgParams();
        if (parameters == null) { return AlgorithmIdentifier.absent(certificate.getSigAlgOID()); }
        return Arrays.equals(parameters, new byte[] {5, 0}) ? AlgorithmIdentifier.derNull(certificate.getSigAlgOID())
                : AlgorithmIdentifier.exact(certificate.getSigAlgOID(), parameters);
    }

    private static void requireCertificateEncoding(X509Certificate certificate) throws GeneralSecurityException {
        require(Arrays.equals(certificate.getEncoded(), Pkix.assembleCertificateOrCrl(certificate.getTBSCertificate(),
                certificate.getSignature(), false)), "Inner and outer signature algorithms differ");
    }
    private static X509Certificate decodeCertificate(byte[] encoded) throws GeneralSecurityException {
        return (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(encoded));
    }
    private static X509Certificate certificate(Path path) throws IOException, GeneralSecurityException {
        byte[] bytes = read(path, 1_048_576);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(bytes));
        require(Arrays.equals(bytes, certificate.getEncoded()), "Certificate is not exact DER"); return certificate;
    }
    private static byte[] read(Path path, int maximum) throws IOException {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path), "Expected regular owned file");
        require(Files.getOwner(path).equals(Files.getOwner(Path.of(System.getProperty("user.home"))))
                && Files.getPosixFilePermissions(path).stream().noneMatch(permission -> permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_")), "Expected owner-only file");
        require(Files.size(path) > 0 && Files.size(path) <= maximum, "File exceeds size bounds"); return Files.readAllBytes(path);
    }
    private static void requireDirectory(Path path) throws IOException {
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)
                && Files.getOwner(path).equals(Files.getOwner(Path.of(System.getProperty("user.home"))))
                && Files.getPosixFilePermissions(path).equals(PosixFilePermissions.fromString("rwx------")), "Expected owned private directory");
    }
    private static void write(Path path, byte[] bytes) throws IOException {
        try (SeekableByteChannel output = Files.newByteChannel(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) { ByteBuffer buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) { output.write(buffer); } }
    }
    private static void requireVariant(String variant) { require(VARIANTS.contains(variant), "Unsupported scenario variant"); }
    private static byte[] digest(String algorithm, byte[] bytes) throws NoSuchAlgorithmException { return MessageDigest.getInstance(algorithm).digest(bytes); }
    private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    private static byte[] unhex(String text, int length) { require(text.matches("[0-9a-f]{" + length * 2 + "}"), "Expected canonical hex"); return HexFormat.of().parseHex(text); }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String text(byte[] bytes) { return new String(bytes, StandardCharsets.UTF_8); }
    private static void require(boolean condition, String message) { if (!condition) { throw invalid(message); } }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}
