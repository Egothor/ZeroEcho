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

package zeroecho.pki.server.enrollment;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.PublicKeyIdentity;

/** Bounded credential graph validation and strict immutable public commitments. */
final class EnrollmentCredentialValidation { // NOPMD CyclomaticComplexity - One credential validation boundary binds chains, keys and persisted identity; individual methods remain checked.
    private static final int SINGLE_CERTIFICATE_COUNT = 1;
    private static final int CERTIFICATE_BYTES = 262_144;

    /* default */ record Loaded(EnrollmentRuntimeConfiguration.CredentialSet configuration,
            List<X509Certificate> signerChain, List<X509Certificate> trustAnchors,
            Instant notBefore, Instant notAfter, String fingerprint) { }

    private EnrollmentCredentialValidation() { }

    /* default */ static Loaded load(EnrollmentRuntimeConfiguration.CredentialSet set, String realm,
            PkiRepository repository, Map<String, KeyringStore> rings) {
        try {
            List<X509Certificate> authorityChain = authorityChain(set, repository);
            List<X509Certificate> signer = new ArrayList<>();
            for (Path path : set.signer().map(EnrollmentRuntimeConfiguration.Signer::certificateChain).orElse(List.of())) {
                signer.add(certificate(path));
            }
            List<X509Certificate> trust = new ArrayList<>();
            for (Path path : set.requestTrustAnchors()) {
                X509Certificate anchor = certificate(path);
                requireCa(anchor);
                PublicKeyIdentity.fromSubjectPublicKeyInfo(Pkix.subjectPublicKeyInfo(anchor));
                trust.add(anchor);
            }
            List<X509Certificate> all = new ArrayList<>(authorityChain);
            all.addAll(signer);
            all.addAll(trust);
            Instant before = all.stream().map(value -> value.getNotBefore().toInstant()).max(Instant::compareTo).orElseThrow();
            Instant after = all.stream().map(value -> value.getNotAfter().toInstant()).min(Instant::compareTo).orElseThrow();
            if (!before.isBefore(after)) {
                throw invalid();
            }
            validatePath(authorityChain, before);
            if (set.signer().isPresent()) {
                validateSigner(set, signer, authorityChain, before, rings, realm);
            }
            byte[] fingerprint = encode(set, realm, authorityChain, signer, trust, rings);
            return new Loaded(set, List.copyOf(signer), List.copyOf(trust), before, after, digest(fingerprint));
        } catch (IOException | GeneralSecurityException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw invalid(); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private static void validateSigner(EnrollmentRuntimeConfiguration.CredentialSet set, List<X509Certificate> signer,
            List<X509Certificate> authorityChain, Instant before, Map<String, KeyringStore> rings, String realm)
            throws IOException, GeneralSecurityException {
        if (signer.size() != authorityChain.size() + 1) {
            throw invalid();
        }
        for (int index = 0; index < authorityChain.size(); index++) {
            if (!Arrays.equals(signer.get(index + 1).getEncoded(), authorityChain.get(index).getEncoded())) {
                throw invalid();
            }
        }
        X509Certificate leaf = signer.getFirst();
        if (leaf.getBasicConstraints() >= 0 || !usage(leaf, 0)) {
            throw invalid();
        }
        if (set.protocol() == EnrollmentRuntimeConfiguration.Protocol.SCEP
                && (!usage(leaf, 2) || !"RSA".equals(leaf.getPublicKey().getAlgorithm()))) {
            throw invalid();
        }
        PublicKeyIdentity.fromSubjectPublicKeyInfo(Pkix.subjectPublicKeyInfo(leaf));
        validatePath(signer, before);
        EnrollmentRuntimeConfiguration.KeyReference ref = set.signer().orElseThrow().key();
        PrivateKey key = rings.get(ref.keyringId()).getPrivate(ref.alias());
        verifyPair(key, leaf, realm, set.credentialId());
    }

    /* default */ static void requireCurrent(Loaded loaded, PkiRepository repository) {
        EnrollmentRuntimeConfiguration.CredentialSet set = loaded.configuration();
        CaRecord authority = repository.authority(new PkiId(set.authorityId())).orElseThrow(EnrollmentCredentialValidation::invalid);
        IssuerGeneration issuer = repository.issuer(new PkiId(set.issuerId())).orElseThrow(EnrollmentCredentialValidation::invalid);
        if (!authority.currentIssuanceIssuerId().value().equals(set.issuerId())
                || !authority.issuanceChainPathId().value().equals(set.chainPathId())
                || authority.state() != zeroecho.pki.api.ca.CaState.ACTIVE
                || issuer.state() != zeroecho.pki.api.ca.IssuerGenerationState.ACTIVE) {
            throw invalid();
        }
    }

    /* default */ static void pin(ServerControlStore control, Map<String, Loaded> loaded) {
        synchronized (control) { // NOPMD AvoidSynchronizedStatement - Shares the authoritative control-store monitor across admission and durable state transitions.
            int offset = 0;
            ServerControlStore.Page<ServerControlStore.ProtocolRecord> page;
            do {
                page = control.protocolRecords(ServerControlStore.ENROLLMENT_CREDENTIAL, offset, 128);
                for (ServerControlStore.ProtocolRecord record : page.values()) {
                    Loaded current = loaded.get(record.recordId());
                    if (current == null || !Arrays.equals(payload(current), record.payload())
                            || !digest(record.payload()).equals(record.commitment())) {
                        throw invalid();
                    }
                }
                offset = page.nextOffset();
            } while (page.hasMore());
            List<ServerControlStore.ProtocolMutation> mutations = new ArrayList<>();
            for (Loaded value : loaded.values()) {
                if (control.protocolRecord(ServerControlStore.ENROLLMENT_CREDENTIAL, value.configuration().credentialId()).isEmpty()) {
                    byte[] payload = payload(value);
                    mutations.add(new ServerControlStore.ProtocolMutation(new ServerControlStore.ProtocolRecord(
                            ServerControlStore.ENROLLMENT_CREDENTIAL, value.configuration().credentialId(), digest(payload), payload), Optional.empty()));
                }
            }
            if (!mutations.isEmpty()) {
                control.mutateProtocol(mutations);
            }
        }
    }

    private static byte[] payload(Loaded loaded) {
        return ("1\n" + loaded.fingerprint()).getBytes(StandardCharsets.US_ASCII);
    }

    private static List<X509Certificate> authorityChain(EnrollmentRuntimeConfiguration.CredentialSet set, PkiRepository repository)
            throws IOException, GeneralSecurityException {
        PkiId authorityId = new PkiId(set.authorityId());
        CaRecord authority = repository.authority(authorityId).orElseThrow(EnrollmentCredentialValidation::invalid);
        IssuerGeneration issuer = repository.issuer(new PkiId(set.issuerId())).orElseThrow(EnrollmentCredentialValidation::invalid);
        IssuerChainPath path = repository.chainPath(new PkiId(set.chainPathId())).orElseThrow(EnrollmentCredentialValidation::invalid);
        if (!authority.issuerIds().contains(issuer.issuerId()) || !issuer.authorityId().equals(authorityId)
                || !path.authorityId().equals(authorityId) || !path.issuerId().equals(issuer.issuerId())
                || !path.orderedCredentialIds().getFirst().equals(issuer.credentialId())) {
            throw invalid();
        }
        List<X509Certificate> certificates = new ArrayList<>();
        for (PkiId id : path.orderedCredentialIds()) {
            try (PkiRepositoryContent content = repository.openCredential(id); InputStream input = content.openStream()) {
                X509Certificate certificate = certificate(input.readNBytes(CERTIFICATE_BYTES + 1));
                requireCa(certificate);
                certificates.add(certificate);
            }
        }
        return List.copyOf(certificates);
    }

    private static X509Certificate certificate(Path path) throws IOException, GeneralSecurityException {
        try (InputStream input = Files.newInputStream(path)) {
            return certificate(input.readNBytes(CERTIFICATE_BYTES + 1));
        }
    }

    private static X509Certificate certificate(byte[] bytes) throws GeneralSecurityException {
        if (bytes.length == 0 || bytes.length > CERTIFICATE_BYTES || bytes[0] != 0x30) {
            throw invalid();
        }
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        if (input.available() != 0 || !Arrays.equals(bytes, certificate.getEncoded())) {
            throw invalid();
        }
        return certificate;
    }

    private static void requireCa(X509Certificate certificate) {
        if (certificate.getBasicConstraints() < 0 || !usage(certificate, 5)) {
            throw invalid();
        }
    }

    private static boolean usage(X509Certificate certificate, int bit) {
        boolean[] usage = certificate.getKeyUsage();
        return usage != null && usage.length > bit && usage[bit];
    }

    private static void validatePath(List<X509Certificate> chain, Instant instant) throws GeneralSecurityException {
        for (X509Certificate certificate : chain) {
            certificate.checkValidity(Date.from(instant));
        }
        for (int index = 0; index + 1 < chain.size(); index++) {
            X509Certificate child = chain.get(index);
            X509Certificate issuer = chain.get(index + 1);
            if (!child.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                throw invalid();
            }
            child.verify(issuer.getPublicKey());
        }
        if (chain.size() > SINGLE_CERTIFICATE_COUNT) {
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(chain.getLast(), null)));
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(instant));
            CertPathValidator.getInstance("PKIX").validate(CertificateFactory.getInstance("X.509")
                    .generateCertPath(chain.subList(0, chain.size() - 1)), parameters);
        }
    }

    private static void verifyPair(PrivateKey key, X509Certificate certificate, String realm, String credential)
            throws GeneralSecurityException {
        String algorithm = switch (certificate.getPublicKey().getAlgorithm()) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw invalid();
        };
        byte[] probe = ("zeroecho-enrollment-key-match-v1\n" + realm + "\n" + credential).getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(probe);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(certificate);
        verifier.update(probe);
        if (!verifier.verify(signature)) {
            throw invalid();
        }
    }

    private static byte[] encode(EnrollmentRuntimeConfiguration.CredentialSet set, String realm,
            List<X509Certificate> authority, List<X509Certificate> signer, List<X509Certificate> trust,
            Map<String, KeyringStore> rings) throws IOException, GeneralSecurityException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            text(output, "zeroecho-enrollment-credentials-v1");
            text(output, realm); text(output, set.credentialId()); text(output, set.protocol().name());
            text(output, set.authorityId()); text(output, set.issuerId()); text(output, set.chainPathId());
            certificates(output, authority);
            certificates(output, signer);
            List<String> anchors = new ArrayList<>();
            for (X509Certificate anchor : trust) {
                anchors.add(digest(anchor.getEncoded()));
            }
            strings(output, anchors.stream().sorted().toList());
            strings(output, set.authorizedRaKeys());
            output.writeBoolean(set.signer().isPresent());
            if (set.signer().isPresent()) {
                reference(output, set.signer().orElseThrow().key());
            }
            output.writeBoolean(set.pbm().isPresent());
            if (set.pbm().isPresent()) {
                EnrollmentRuntimeConfiguration.Pbm policy = set.pbm().orElseThrow();
                output.writeInt(policy.minimumIterations()); output.writeInt(policy.maximumIterations());
                output.writeInt(policy.minimumSaltBytes()); output.writeInt(policy.maximumSaltBytes());
                strings(output, policy.digests().stream().map(Enum::name).sorted().toList());
                strings(output, policy.macs().stream().map(Enum::name).sorted().toList());
                List<EnrollmentRuntimeConfiguration.PbmIdentity> identities = policy.identities().stream()
                        .sorted(java.util.Comparator.comparing(EnrollmentRuntimeConfiguration.PbmIdentity::senderKid)).toList();
                output.writeInt(identities.size());
                for (EnrollmentRuntimeConfiguration.PbmIdentity identity : identities) {
                    field(output, HexFormat.of().parseHex(identity.senderKid()));
                    text(output, identity.identityId()); reference(output, identity.secret());
                    strings(output, identity.ownerAliases());
                    SecretKey secret = rings.get(identity.secret().keyringId()).getSecret(identity.secret().alias());
                    byte[] material = secret.getEncoded();
                    if (material == null) {
                        throw invalid();
                    }
                    try {
                        if (material.length < 32 || material.length > 128) {
                            throw invalid();
                        }
                        field(output, secretFingerprint(material, realm, set, identity));
                    } finally { Arrays.fill(material, (byte) 0); }
                }
            }
        }
        return bytes.toByteArray();
    }

    private static void certificates(DataOutputStream output, List<X509Certificate> values) throws IOException, GeneralSecurityException {
        output.writeInt(values.size());
        for (X509Certificate value : values) {
            field(output, value.getEncoded());
        }
    }
    private static void reference(DataOutputStream output, EnrollmentRuntimeConfiguration.KeyReference reference) throws IOException {
        text(output, reference.keyringId()); text(output, reference.alias());
    }
    private static void strings(DataOutputStream output, List<String> values) throws IOException {
        output.writeInt(values.size());
        for (String value : values) {
            text(output, value);
        }
    }
    private static void text(DataOutputStream output, String text) throws IOException { field(output, text.getBytes(StandardCharsets.UTF_8)); }
    private static void field(DataOutputStream output, byte[] value) throws IOException { output.writeInt(value.length); output.write(value); }
    private static byte[] secretFingerprint(byte[] material, String realm, EnrollmentRuntimeConfiguration.CredentialSet set,
            EnrollmentRuntimeConfiguration.PbmIdentity identity) throws IOException, GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(material, "HmacSHA256"));
        ByteArrayOutputStream contextBytes = new ByteArrayOutputStream();
        try (DataOutputStream context = new DataOutputStream(contextBytes)) {
            text(context, "zeroecho-enrollment-pbm-secret-v1");
            text(context, realm); text(context, set.credentialId());
            text(context, set.authorityId()); field(context, HexFormat.of().parseHex(identity.senderKid()));
        }
        return mac.doFinal(contextBytes.toByteArray());
    }

    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA-256 unavailable", failure); }
    }
    private static IllegalStateException invalid() { return new IllegalStateException("Enrollment credential validation failed"); }
}
