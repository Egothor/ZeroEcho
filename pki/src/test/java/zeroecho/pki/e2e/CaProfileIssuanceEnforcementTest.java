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
package zeroecho.pki.e2e;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaImportCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.impl.core.ValidatedCaCertificateRequest;
import zeroecho.pki.impl.core.ValidatedCertificateRequest;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.testkit.PkiTestRuntime;

/**
 * Focused real-certificate acceptance tests for active CA profile enforcement.
 */
final class CaProfileIssuanceEnforcementTest {

    @Test
    void fixedSubjectIntermediateIsValidatedOnceAndPersistsCanonicalSubject(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:fixed-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:fixed-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            byte[] fixedProfile = builtIn("intermediate-ca")
                    .replace("\"profileId\":\"intermediate-ca\"", "\"profileId\":\"fixed-intermediate-ca\"")
                    .replace("\"maximumUtf8Bytes\":253}]}",
                            "\"maximumUtf8Bytes\":253},{\"oid\":\"2.5.4.10\",\"source\":\"PROFILE_FIXED\","
                                    + "\"minimumOccurrences\":1,\"maximumOccurrences\":1,"
                                    + "\"maximumUtf8Bytes\":256,\"fixedValue\":\"Fixed Organization\"}]}")
                    .getBytes(StandardCharsets.UTF_8);
            CertificateProfileRef reference = runtime.profileService().importProfile(fixedProfile);
            runtime.profileService().activateProfile(reference.profileId(), reference.profileVersion());

            PkiId rootId = runtime.caService().createRoot(
                    new CaCreateCommand(runtime.framework().formatId(), new SubjectRef("CN=Fixed Subject Root"),
                            "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            PkiId intermediateId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                            new SubjectRef("CN=Fixed Subject Intermediate"), "fixed-intermediate-ca",
                            Optional.of(intermediateRef), new SimpleAttributeSet()));
            Credential additional = runtime.caService().issueIntermediateCertificate(
                    new IntermediateCertIssueCommand(runtime.framework().formatId(), rootId, intermediateId,
                            "fixed-intermediate-ca", Optional.empty(), new SimpleAttributeSet()));

            CaRecord intermediate = runtime.caService().getCa(intermediateId);
            Credential credential = intermediate.caCredentials().get(0);
            X509CertificateHolder holder = new X509CertificateHolder(credential.encoded().bytes());
            X509CertificateHolder additionalHolder = new X509CertificateHolder(additional.encoded().bytes());
            assertEquals("Fixed Organization",
                    holder.getSubject().getRDNs(BCStyle.O)[0].getFirst().getValue().toString());
            assertEquals("Fixed Organization",
                    additionalHolder.getSubject().getRDNs(BCStyle.O)[0].getFirst().getValue().toString());
            assertEquals(holder.getSubject().toString(), intermediate.subjectRef().value());
            assertEquals(intermediate.subjectRef(), credential.subjectRef());
            assertEquals(intermediate.subjectRef(), additional.subjectRef());
            assertEquals(2, intermediate.caCredentials().size());
        }
    }

    @Test
    void rootIntermediateAdditionalAndRestartRetainExactReferences(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:intermediate");
        Path store = directory.resolve("store");
        Path bus = directory.resolve("bus.log");
        PkiId rootId;
        PkiId intermediateId;
        CertificateProfileRef rootProfile;
        CertificateProfileRef intermediateProfile;
        try (PkiTestRuntime runtime = PkiTestRuntime.create(store, bus,
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Profile Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            intermediateId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                            new SubjectRef("CN=Profile Intermediate"), "intermediate-ca", Optional.of(intermediateRef),
                            new SimpleAttributeSet()));
            Credential additional = runtime.caService()
                    .issueIntermediateCertificate(new IntermediateCertIssueCommand(runtime.framework().formatId(),
                            rootId, intermediateId, "intermediate-ca", Optional.empty(), new SimpleAttributeSet()));
            rootProfile = ((CaProfileBinding) runtime.caService().getCa(rootId).caCredentials().get(0).profileBinding())
                    .reference();
            intermediateProfile = ((CaProfileBinding) additional.profileBinding()).reference();
            assertCaCertificate(runtime.caService().getCa(rootId).caCredentials().get(0), 1);
            assertCaCertificate(additional, 0);
        }
        try (PkiTestRuntime reopened = PkiTestRuntime.create(store, directory.resolve("reopened-bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            assertEquals(rootProfile,
                    ((CaProfileBinding) reopened.caService().getCa(rootId).caCredentials().get(0).profileBinding())
                            .reference());
            assertEquals(intermediateProfile, ((CaProfileBinding) reopened.caService().getCa(intermediateId)
                    .caCredentials().get(1).profileBinding()).reference());
        }
    }

    @Test
    void missingAndWrongKindActiveProfilesFailBeforeProof(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:missing");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey))) {
            assertThrows(PkiException.class,
                    () -> runtime.caService().createRoot(
                            new CaCreateCommand(runtime.framework().formatId(), new SubjectRef("CN=Missing"),
                                    "missing-ca-profile", Optional.of(rootRef), new SimpleAttributeSet())));
            assertThrows(PkiException.class,
                    () -> runtime.caService().createRoot(
                            new CaCreateCommand(runtime.framework().formatId(), new SubjectRef("CN=Wrong Kind"),
                                    "default", Optional.of(rootRef), new SimpleAttributeSet())));
            assertEquals(0, runtime.submittedSignCount());
            assertTrue(runtime.store().listCas().isEmpty());
        }
    }

    @Test
    void historicalIssuerVersionRemainsValidAfterActiveSwitch(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:history-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:history-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Historical Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            byte[] versionTwo = builtIn("root-ca").replace("\"profileVersion\":1", "\"profileVersion\":2")
                    .getBytes(StandardCharsets.UTF_8);
            CertificateProfileRef imported = runtime.profileService().importProfile(versionTwo);
            runtime.profileService().activateProfile(imported.profileId(), imported.profileVersion());

            PkiId intermediateId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                            new SubjectRef("CN=Historical Intermediate"), "intermediate-ca",
                            Optional.of(intermediateRef), new SimpleAttributeSet()));
            CaProfileBinding issuerBinding = (CaProfileBinding) runtime.caService().getCa(rootId).caCredentials().get(0)
                    .profileBinding();
            assertEquals(1, issuerBinding.reference().profileVersion());
            assertEquals(1, runtime.caService().getCa(intermediateId).caCredentials().size());
        }
    }

    @Test
    void rootCaProfileVersionSwitchA_B_C(@TempDir Path directory) throws Exception {
        System.out.println("rootCaProfileVersionSwitchA_B_C");
        String profileId = "ca-version-switch-root";
        byte[] versionOneDocument = caProfileDocument("root-ca", profileId, 1, 1, 1);
        byte[] versionTwoDocument = caProfileDocument("root-ca", profileId, 2, 1, 2);
        KeyPair keyA = rsa();
        KeyPair keyB = rsa();
        KeyPair keyC = rsa();
        KeyRef keyRefA = new KeyRef("kref:v1:keyring:ca-version-switch:root-a");
        KeyRef keyRefB = new KeyRef("kref:v1:keyring:ca-version-switch:root-b");
        KeyRef keyRefC = new KeyRef("kref:v1:keyring:ca-version-switch:root-c");
        Map<KeyRef, KeyPair> keys = Map.of(keyRefA, keyA, keyRefB, keyB, keyRefC, keyC);
        Path store = directory.resolve("store");
        CertificateProfileRef versionOne;
        CertificateProfileRef versionTwo;
        byte[] persistedVersionOne;
        byte[] persistedVersionOneHash;
        PkiId caA;
        PkiId caB;
        PkiId caC;
        PkiId credentialA;
        PkiId credentialB;
        PkiId credentialC;

        try (PkiTestRuntime runtime = PkiTestRuntime.create(store, directory.resolve("bus.log"), keys)) {
            versionOne = runtime.profileService().importProfile(versionOneDocument);
            assertEquals(profileId, versionOne.profileId());
            assertEquals(1, versionOne.profileVersion());
            runtime.profileService().activateProfile(profileId, 1);

            caA = createRoot(runtime, keyRefA, "CN=Version Switch Root A", profileId);
            Credential issuedA = onlyCredential(runtime.caService(), caA);
            assertCaProfileCredential("A", issuedA, versionOne, 1);
            credentialA = issuedA.credentialId();

            ImportedCertificateProfileVersion storedOne = runtime.profileService().getImportedVersion(profileId, 1)
                    .orElseThrow();
            persistedVersionOne = storedOne.canonicalJson();
            persistedVersionOneHash = storedOne.reference().canonicalSha256();

            versionTwo = runtime.profileService().importProfile(versionTwoDocument);
            assertEquals(profileId, versionTwo.profileId());
            assertEquals(2, versionTwo.profileVersion());
            assertTrue(!MessageDigest.isEqual(versionOne.canonicalSha256(), versionTwo.canonicalSha256()));
            assertEquals(versionOne, runtime.profileService().getActiveReference(profileId).orElseThrow());

            caB = createRoot(runtime, keyRefB, "CN=Version Switch Root B", profileId);
            Credential issuedB = onlyCredential(runtime.caService(), caB);
            assertCaProfileCredential("B", issuedB, versionOne, 1);
            credentialB = issuedB.credentialId();

            assertEquals(versionTwo, runtime.profileService().activateProfile(profileId, 2));
            caC = createRoot(runtime, keyRefC, "CN=Version Switch Root C", profileId);
            Credential issuedC = onlyCredential(runtime.caService(), caC);
            assertCaProfileCredential("C", issuedC, versionTwo, 2);
            credentialC = issuedC.credentialId();

            assertCaProfileCredential("A-reread", runtime.store().getCredential(credentialA).orElseThrow(), versionOne,
                    1);
            assertCaProfileCredential("B-reread", runtime.store().getCredential(credentialB).orElseThrow(), versionOne,
                    1);
            ImportedCertificateProfileVersion unchanged = runtime.profileService().getImportedVersion(profileId, 1)
                    .orElseThrow();
            assertArrayEquals(persistedVersionOne, unchanged.canonicalJson());
            assertArrayEquals(persistedVersionOneHash, unchanged.reference().canonicalSha256());
        }

        try (PkiTestRuntime reopened = PkiTestRuntime.create(store, directory.resolve("reopened-bus.log"), keys)) {
            assertEquals(versionTwo, reopened.profileService().getActiveReference(profileId).orElseThrow());
            assertCaProfileCredential("A-restart", reopened.store().getCredential(credentialA).orElseThrow(),
                    versionOne, 1);
            assertCaProfileCredential("B-restart", reopened.store().getCredential(credentialB).orElseThrow(),
                    versionOne, 1);
            assertCaProfileCredential("C-restart", reopened.store().getCredential(credentialC).orElseThrow(),
                    versionTwo, 2);
            ImportedCertificateProfileVersion unchanged = reopened.profileService().getImportedVersion(profileId, 1)
                    .orElseThrow();
            assertArrayEquals(persistedVersionOne, unchanged.canonicalJson());
            assertArrayEquals(persistedVersionOneHash, unchanged.reference().canonicalSha256());
        }
        System.out.println("...ok");
    }

    @Test
    void intermediateCaProfileVersionSwitchA_B_C(@TempDir Path directory) throws Exception {
        System.out.println("intermediateCaProfileVersionSwitchA_B_C");
        String rootProfileId = "ca-version-switch-issuer-root";
        String intermediateProfileId = "ca-version-switch-intermediate";
        byte[] rootProfileDocument = caProfileDocument("root-ca", rootProfileId, 1, 1, 2);
        byte[] versionOneDocument = caProfileDocument("intermediate-ca", intermediateProfileId, 1, 0, 0);
        byte[] versionTwoDocument = caProfileDocument("intermediate-ca", intermediateProfileId, 2, 0, 1);
        KeyPair rootKey = rsa();
        KeyPair keyA = rsa();
        KeyPair keyB = rsa();
        KeyPair keyC = rsa();
        KeyRef rootKeyRef = new KeyRef("kref:v1:keyring:ca-version-switch:issuer-root");
        KeyRef keyRefA = new KeyRef("kref:v1:keyring:ca-version-switch:intermediate-a");
        KeyRef keyRefB = new KeyRef("kref:v1:keyring:ca-version-switch:intermediate-b");
        KeyRef keyRefC = new KeyRef("kref:v1:keyring:ca-version-switch:intermediate-c");
        Map<KeyRef, KeyPair> keys = Map.of(rootKeyRef, rootKey, keyRefA, keyA, keyRefB, keyB, keyRefC, keyC);
        Path store = directory.resolve("store");
        CertificateProfileRef rootProfile;
        CertificateProfileRef versionOne;
        CertificateProfileRef versionTwo;
        byte[] persistedVersionOne;
        byte[] persistedVersionOneHash;
        PkiId rootId;
        PkiId caA;
        PkiId caB;
        PkiId caC;
        PkiId credentialA;
        PkiId credentialB;
        PkiId credentialC;

        try (PkiTestRuntime runtime = PkiTestRuntime.create(store, directory.resolve("bus.log"), keys)) {
            rootProfile = runtime.profileService().importProfile(rootProfileDocument);
            runtime.profileService().activateProfile(rootProfileId, 1);
            rootId = createRoot(runtime, rootKeyRef, "CN=Version Switch Issuer Root", rootProfileId);
            Credential rootCredential = onlyCredential(runtime.caService(), rootId);
            assertCaProfileCredential("issuer", rootCredential, rootProfile, 2);

            versionOne = runtime.profileService().importProfile(versionOneDocument);
            assertEquals(intermediateProfileId, versionOne.profileId());
            assertEquals(1, versionOne.profileVersion());
            runtime.profileService().activateProfile(intermediateProfileId, 1);

            caA = createIntermediate(runtime, rootId, keyRefA, "CN=Version Switch Intermediate A",
                    intermediateProfileId);
            Credential issuedA = onlyCredential(runtime.caService(), caA);
            assertCaProfileCredential("A", issuedA, versionOne, 0);
            credentialA = issuedA.credentialId();
            assertCaProfileCredential("issuer-after-A", onlyCredential(runtime.caService(), rootId), rootProfile, 2);

            ImportedCertificateProfileVersion storedOne = runtime.profileService()
                    .getImportedVersion(intermediateProfileId, 1).orElseThrow();
            persistedVersionOne = storedOne.canonicalJson();
            persistedVersionOneHash = storedOne.reference().canonicalSha256();

            versionTwo = runtime.profileService().importProfile(versionTwoDocument);
            assertEquals(intermediateProfileId, versionTwo.profileId());
            assertEquals(2, versionTwo.profileVersion());
            assertTrue(!MessageDigest.isEqual(versionOne.canonicalSha256(), versionTwo.canonicalSha256()));
            assertEquals(versionOne, runtime.profileService().getActiveReference(intermediateProfileId).orElseThrow());

            caB = createIntermediate(runtime, rootId, keyRefB, "CN=Version Switch Intermediate B",
                    intermediateProfileId);
            Credential issuedB = onlyCredential(runtime.caService(), caB);
            assertCaProfileCredential("B", issuedB, versionOne, 0);
            credentialB = issuedB.credentialId();

            assertEquals(versionTwo, runtime.profileService().activateProfile(intermediateProfileId, 2));
            caC = createIntermediate(runtime, rootId, keyRefC, "CN=Version Switch Intermediate C",
                    intermediateProfileId);
            Credential issuedC = onlyCredential(runtime.caService(), caC);
            assertCaProfileCredential("C", issuedC, versionTwo, 1);
            credentialC = issuedC.credentialId();

            assertCaProfileCredential("A-reread", runtime.store().getCredential(credentialA).orElseThrow(), versionOne,
                    0);
            assertCaProfileCredential("B-reread", runtime.store().getCredential(credentialB).orElseThrow(), versionOne,
                    0);
            assertCaProfileCredential("issuer-reread", onlyCredential(runtime.caService(), rootId), rootProfile, 2);
            ImportedCertificateProfileVersion unchanged = runtime.profileService()
                    .getImportedVersion(intermediateProfileId, 1).orElseThrow();
            assertArrayEquals(persistedVersionOne, unchanged.canonicalJson());
            assertArrayEquals(persistedVersionOneHash, unchanged.reference().canonicalSha256());
        }

        try (PkiTestRuntime reopened = PkiTestRuntime.create(store, directory.resolve("reopened-bus.log"), keys)) {
            assertEquals(versionTwo, reopened.profileService().getActiveReference(intermediateProfileId).orElseThrow());
            assertCaProfileCredential("A-restart", reopened.store().getCredential(credentialA).orElseThrow(),
                    versionOne, 0);
            assertCaProfileCredential("B-restart", reopened.store().getCredential(credentialB).orElseThrow(),
                    versionOne, 0);
            assertCaProfileCredential("C-restart", reopened.store().getCredential(credentialC).orElseThrow(),
                    versionTwo, 1);
            assertCaProfileCredential("issuer-restart", onlyCredential(reopened.caService(), rootId), rootProfile, 2);
            ImportedCertificateProfileVersion unchanged = reopened.profileService()
                    .getImportedVersion(intermediateProfileId, 1).orElseThrow();
            assertArrayEquals(persistedVersionOne, unchanged.canonicalJson());
            assertArrayEquals(persistedVersionOneHash, unchanged.reference().canonicalSha256());
        }
        System.out.println("...ok");
    }

    @Test
    void historicalIssuerFormatMismatchFailsBeforeProof(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:format-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:format-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Format Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            CertificateProfileRef wrongFormat = runtime.profileService().importProfile(builtIn("root-ca")
                    .replace("\"profileId\":\"root-ca\"", "\"profileId\":\"other-format-root\"")
                    .replace("\"formatId\":\"x509\"", "\"formatId\":\"other\"").getBytes(StandardCharsets.UTF_8));
            CaRecord root = runtime.caService().getCa(rootId);
            Credential original = root.caCredentials().get(0);
            Credential mutated = new Credential(original.credentialId(), original.formatId(), original.issuerRef(),
                    original.subjectRef(), original.validity(), original.serialOrUniqueId(), original.publicKeyId(),
                    new CaProfileBinding(wrongFormat), original.status(), original.encoded(), original.attributes());
            runtime.store().putCa(new CaRecord(root.caId(), root.kind(), root.state(), root.issuerKeyRef(),
                    root.subjectRef(), List.of(mutated)));

            int signCount = runtime.submittedSignCount();
            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                                    new SubjectRef("CN=Format Intermediate"), "intermediate-ca",
                                    Optional.of(intermediateRef), new SimpleAttributeSet())));
            assertEquals(signCount, runtime.submittedSignCount());
            assertEquals(1, runtime.store().listCas().size());
        }
    }

    @Test
    void invalidCaSubjectAndKeyAlgorithmFailBeforeProof(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair dsaKey = keyPair("DSA");
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:invalid-root");
        KeyRef dsaRef = new KeyRef("kref:v1:keyring:ca-profile:invalid-dsa");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, dsaRef, dsaKey))) {
            assertThrows(PkiException.class,
                    () -> runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                            new SubjectRef("O=Forbidden"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet())));
            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .createRoot(new CaCreateCommand(runtime.framework().formatId(),
                                    new SubjectRef("CN=Unsupported Algorithm"), "root-ca", Optional.of(dsaRef),
                                    new SimpleAttributeSet())));
            assertEquals(0, runtime.submittedSignCount());
            assertTrue(runtime.store().listCas().isEmpty());
        }
    }

    @Test
    void eachCaOperationResolvesItsActiveProfileExactlyOnce(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:lookup-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:lookup-intermediate");
        byte[] rootCertificate;
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory.resolve("main"),
                directory.resolve("main-bus.log"), Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            runtime.caService();
            CountingProfileService profiles = new CountingProfileService(runtime.profileService());
            CaService service = runtime.caService(profiles);

            PkiId rootId = service.createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Lookup Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            profiles.assertAndReset("root-ca");
            PkiId intermediateId = service.createIntermediate(new IntermediateCreateCommand(
                    runtime.framework().formatId(), rootId, new SubjectRef("CN=Lookup Intermediate"), "intermediate-ca",
                    Optional.of(intermediateRef), new SimpleAttributeSet()));
            profiles.assertAndReset("intermediate-ca");
            service.issueIntermediateCertificate(new IntermediateCertIssueCommand(runtime.framework().formatId(),
                    rootId, intermediateId, "intermediate-ca", Optional.empty(), new SimpleAttributeSet()));
            profiles.assertAndReset("intermediate-ca");
            rootCertificate = service.getCa(rootId).caCredentials().get(0).encoded().bytes();
        }
        try (PkiTestRuntime target = PkiTestRuntime.create(directory.resolve("import"),
                directory.resolve("import-bus.log"), Map.of(rootRef, rootKey))) {
            target.caService();
            CountingProfileService profiles = new CountingProfileService(target.profileService());
            CaService service = target.caService(profiles);
            service.importRoot(new CaImportCommand(target.framework().formatId(), new SubjectRef("CN=Lookup Root"),
                    "root-ca", rootRef, new EncodedObject(Encoding.DER, rootCertificate), new SimpleAttributeSet()));
            profiles.assertAndReset("root-ca");
        }
    }

    @Test
    void rootCannotBeUsedAsAdditionalIntermediateSubject(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:root-subject");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Root Subject"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            int signCount = runtime.submittedSignCount();
            assertThrows(PkiException.class,
                    () -> runtime.caService().issueIntermediateCertificate(
                            new IntermediateCertIssueCommand(runtime.framework().formatId(), rootId, rootId,
                                    "intermediate-ca", Optional.empty(), new SimpleAttributeSet())));
            assertEquals(signCount, runtime.submittedSignCount());
            assertEquals(1, runtime.caService().getCa(rootId).caCredentials().size());
        }
    }

    @Test
    void invalidRequestedIntermediateValidityFailsBeforeProof(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:validity-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:validity-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Validity Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            PkiId intermediateId = runtime.caService()
                    .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                            new SubjectRef("CN=Validity Intermediate"), "intermediate-ca", Optional.of(intermediateRef),
                            new SimpleAttributeSet()));
            int signCount = runtime.submittedSignCount();
            Validity invalid = new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(3_153_600_000L));

            assertThrows(PkiException.class,
                    () -> runtime.caService()
                            .issueIntermediateCertificate(new IntermediateCertIssueCommand(
                                    runtime.framework().formatId(), rootId, intermediateId, "intermediate-ca",
                                    Optional.of(invalid), new SimpleAttributeSet())));
            assertEquals(signCount, runtime.submittedSignCount());
            assertEquals(1, runtime.caService().getCa(intermediateId).caCredentials().size());
        }
    }

    @Test
    void generatedRootCanBeImportedAgainstTheSameActivatedProfile(@TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:import");
        byte[] encoded;
        try (PkiTestRuntime source = PkiTestRuntime.create(directory.resolve("source"),
                directory.resolve("source-bus.log"), Map.of(rootRef, rootKey))) {
            PkiId rootId = source.caService().createRoot(new CaCreateCommand(source.framework().formatId(),
                    new SubjectRef("CN=Imported Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            encoded = source.caService().getCa(rootId).caCredentials().get(0).encoded().bytes();
        }
        try (PkiTestRuntime target = PkiTestRuntime.create(directory.resolve("target"),
                directory.resolve("target-bus.log"), Map.of(rootRef, rootKey))) {
            PkiId imported = target.caService()
                    .importRoot(new CaImportCommand(target.framework().formatId(), new SubjectRef("CN=Imported Root"),
                            "root-ca", rootRef, new EncodedObject(Encoding.DER, encoded), new SimpleAttributeSet()));
            Credential credential = target.caService().getCa(imported).caCredentials().get(0);
            assertEquals(target.profileService().getActiveReference("root-ca").orElseThrow(),
                    ((CaProfileBinding) credential.profileBinding()).reference());
        }
    }

    @ParameterizedTest
    @EnumSource(ImportMutation.class)
    void importedRootMutationFailsBeforePersistence(ImportMutation mutation, @TempDir Path directory) throws Exception {
        KeyPair rootKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:import-mutation");
        byte[] encoded;
        try (PkiTestRuntime source = PkiTestRuntime.create(directory.resolve("source"),
                directory.resolve("source-bus.log"), Map.of(rootRef, rootKey))) {
            PkiId rootId = source.caService()
                    .createRoot(new CaCreateCommand(source.framework().formatId(),
                            new SubjectRef("CN=Import Mutation Root"), "root-ca", Optional.of(rootRef),
                            new SimpleAttributeSet()));
            Credential sourceCredential = source.caService().getCa(rootId).caCredentials().get(0);
            encoded = mutation.mutate(sourceCredential, rootKey);
        }
        try (PkiTestRuntime target = PkiTestRuntime.create(directory.resolve("target"),
                directory.resolve("target-bus.log"), Map.of(rootRef, rootKey))) {
            CaImportCommand command = mutation.command(target, rootRef, encoded);
            assertThrows(PkiException.class, () -> target.caService().importRoot(command));
            assertTrue(target.store().listCas().isEmpty());
            assertEquals(0, target.submittedSignCount());
        }
    }

    @ParameterizedTest
    @EnumSource(MetadataMutation.class)
    void intermediateBackendMetadataMutationFailsBeforePersistence(MetadataMutation mutation, @TempDir Path directory)
            throws Exception {
        KeyPair rootKey = rsa();
        KeyPair intermediateKey = rsa();
        KeyRef rootRef = new KeyRef("kref:v1:keyring:ca-profile:mutation-root");
        KeyRef intermediateRef = new KeyRef("kref:v1:keyring:ca-profile:mutation-intermediate");
        try (PkiTestRuntime runtime = PkiTestRuntime.create(directory, directory.resolve("bus.log"),
                Map.of(rootRef, rootKey, intermediateRef, intermediateKey))) {
            PkiId rootId = runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                    new SubjectRef("CN=Mutation Root"), "root-ca", Optional.of(rootRef), new SimpleAttributeSet()));
            CredentialIssuerBackend delegate = runtime.issuerBackend();
            CredentialIssuerBackend backend = new CredentialIssuerBackend() {
                @Override
                public CredentialBundle issueEndEntity(ValidatedCertificateRequest request,
                        EncodedObject issuerCertificate, KeyRef issuerKeyRef, java.math.BigInteger serial) {
                    return delegate.issueEndEntity(request, issuerCertificate, issuerKeyRef, serial);
                }

                @Override
                public Credential issueIntermediateCertificate(ValidatedCaCertificateRequest request,
                        EncodedObject issuerCertificate, KeyRef issuerKeyRef) {
                    return mutation.apply(
                            delegate.issueIntermediateCertificate(request, issuerCertificate, issuerKeyRef), rootKey);
                }
            };
            assertThrows(PkiException.class,
                    () -> runtime.caService(backend)
                            .createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(), rootId,
                                    new SubjectRef("CN=Mutation Intermediate"), "intermediate-ca",
                                    Optional.of(intermediateRef), new SimpleAttributeSet())));
            assertEquals(1, runtime.store().listCas().size());
        }
    }

    private static void assertCaCertificate(Credential credential, int pathLength) throws Exception {
        X509CertificateHolder holder = new X509CertificateHolder(credential.encoded().bytes());
        BasicConstraints constraints = BasicConstraints
                .getInstance(holder.getExtension(Extension.basicConstraints).getParsedValue());
        KeyUsage usage = KeyUsage.getInstance(holder.getExtension(Extension.keyUsage).getParsedValue());
        assertTrue(holder.getExtension(Extension.basicConstraints).isCritical());
        assertTrue(holder.getExtension(Extension.keyUsage).isCritical());
        assertEquals(pathLength, constraints.getPathLenConstraint().intValueExact());
        assertTrue(usage.hasUsages(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        assertEquals(2, holder.getExtensions().getExtensionOIDs().length);
    }

    private static void assertCaProfileCredential(String label, Credential credential,
            CertificateProfileRef expectedProfile, int pathLength) throws Exception {
        assertTrue(credential.profileBinding() instanceof CaProfileBinding);
        assertEquals(expectedProfile, ((CaProfileBinding) credential.profileBinding()).reference());
        assertCaCertificate(credential, pathLength);
        System.out.println("..." + label + " profileVersion=" + expectedProfile.profileVersion() + " hash="
                + abbreviatedHash(expectedProfile) + " credentialId=" + credential.credentialId().value()
                + " pathLength=" + pathLength);
    }

    private static PkiId createRoot(PkiTestRuntime runtime, KeyRef keyRef, String subject, String profileId) {
        return runtime.caService().createRoot(new CaCreateCommand(runtime.framework().formatId(),
                new SubjectRef(subject), profileId, Optional.of(keyRef), new SimpleAttributeSet()));
    }

    private static PkiId createIntermediate(PkiTestRuntime runtime, PkiId issuerId, KeyRef keyRef, String subject,
            String profileId) {
        return runtime.caService().createIntermediate(new IntermediateCreateCommand(runtime.framework().formatId(),
                issuerId, new SubjectRef(subject), profileId, Optional.of(keyRef), new SimpleAttributeSet()));
    }

    private static Credential onlyCredential(CaService service, PkiId caId) {
        CaRecord ca = service.getCa(caId);
        assertEquals(1, ca.caCredentials().size());
        return ca.caCredentials().get(0);
    }

    private static byte[] caProfileDocument(String builtInProfileId, String profileId, long profileVersion,
            int originalPathLength, int pathLength) {
        return builtIn(builtInProfileId)
                .replace("\"profileId\":\"" + builtInProfileId + "\"", "\"profileId\":\"" + profileId + "\"")
                .replace("\"profileVersion\":1", "\"profileVersion\":" + profileVersion)
                .replace("\"pathLengthConstraint\":" + originalPathLength, "\"pathLengthConstraint\":" + pathLength)
                .getBytes(StandardCharsets.UTF_8);
    }

    private static String abbreviatedHash(CertificateProfileRef reference) {
        byte[] hash = reference.canonicalSha256();
        return HexFormat.of().formatHex(hash, 0, 6) + "...";
    }

    private static String builtIn(String profileId) {
        return BuiltInCertificateProfileCatalog.load(CaProfileIssuanceEnforcementTest.class.getClassLoader()).stream()
                .filter(template -> template.definition().profileId().equals(profileId))
                .map(template -> new String(template.canonicalJson(), StandardCharsets.UTF_8)).findFirst()
                .orElseThrow();
    }

    private static KeyPair rsa() throws Exception {
        return keyPair("RSA");
    }

    private static KeyPair keyPair(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static final class CountingProfileService implements ProfileService {
        private final ProfileService delegate;
        private final AtomicInteger activeLookups = new AtomicInteger();
        private String lastProfileId;

        private CountingProfileService(ProfileService delegate) {
            this.delegate = delegate;
        }

        @Override
        public CertificateProfileRef importProfile(byte[] jsonDocument) {
            return delegate.importProfile(jsonDocument);
        }

        @Override
        public CertificateProfileRef importProfile(java.io.InputStream jsonDocument) {
            return delegate.importProfile(jsonDocument);
        }

        @Override
        public CertificateProfileRef importBuiltIn(BuiltInCertificateProfileTemplate template) {
            return delegate.importBuiltIn(template);
        }

        @Override
        public CertificateProfileRef activateProfile(String profileId, long profileVersion) {
            return delegate.activateProfile(profileId, profileVersion);
        }

        @Override
        public ActiveCertificateProfile requireActiveProfile(String profileId) {
            lastProfileId = profileId;
            activeLookups.incrementAndGet();
            return delegate.requireActiveProfile(profileId);
        }

        @Override
        public Optional<ImportedCertificateProfileVersion> getImportedVersion(String profileId, long profileVersion) {
            return delegate.getImportedVersion(profileId, profileVersion);
        }

        @Override
        public List<ImportedCertificateProfileVersion> listImportedVersions(String profileId) {
            return delegate.listImportedVersions(profileId);
        }

        @Override
        public Optional<CertificateProfileRef> getActiveReference(String profileId) {
            return delegate.getActiveReference(profileId);
        }

        private void assertAndReset(String profileId) {
            assertEquals(1, activeLookups.getAndSet(0));
            assertEquals(profileId, lastProfileId);
            lastProfileId = null;
        }
    }

    private enum MetadataMutation {
        PROFILE {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                return copy(value, value.serialOrUniqueId(), value.validity(),
                        new CaProfileBinding(new CertificateProfileRef("other", 1, new byte[32])));
            }
        },
        SERIAL {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                return copy(value, value.serialOrUniqueId() + "1", value.validity(), value.profileBinding());
            }
        },
        VALIDITY {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                return copy(value, value.serialOrUniqueId(), new zeroecho.pki.api.Validity(value.validity().notBefore(),
                        value.validity().notAfter().minusSeconds(1)), value.profileBinding());
            }
        },
        SUBJECT {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                return new Credential(value.credentialId(), value.formatId(), value.issuerRef(),
                        new SubjectRef("CN=Substituted"), value.validity(), value.serialOrUniqueId(),
                        value.publicKeyId(), value.profileBinding(), value.status(), value.encoded(),
                        value.attributes());
            }
        },
        ATTRIBUTES {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                zeroecho.pki.api.attr.AttributeSet attributes = SimpleAttributeSet.builder()
                        .put(new zeroecho.pki.api.attr.AttributeId("test.unexpected"),
                                new zeroecho.pki.api.attr.AttributeValue.StringValue("unexpected"))
                        .build();
                return new Credential(value.credentialId(), value.formatId(), value.issuerRef(), value.subjectRef(),
                        value.validity(), value.serialOrUniqueId(), value.publicKeyId(), value.profileBinding(),
                        value.status(), value.encoded(), attributes);
            }
        },
        EXTRA_EXTENSION {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                return rebuild(value, issuerKey, null, true);
            }
        },
        SUBJECT_DER {
            @Override
            Credential apply(Credential value, KeyPair issuerKey) {
                X500Name alternate = new X500Name(
                        new RDN[] { new RDN(BCStyle.CN, new DERPrintableString("Mutation Intermediate")) });
                return rebuild(value, issuerKey, alternate, false);
            }
        };

        abstract Credential apply(Credential value, KeyPair issuerKey);

        private static Credential copy(Credential value, String serial, zeroecho.pki.api.Validity validity,
                zeroecho.pki.api.credential.CredentialProfileBinding binding) {
            return new Credential(value.credentialId(), value.formatId(), value.issuerRef(), value.subjectRef(),
                    validity, serial, value.publicKeyId(), binding, value.status(), value.encoded(),
                    value.attributes());
        }

        private static Credential rebuild(Credential value, KeyPair issuerKey, X500Name alternateSubject,
                boolean extraExtension) {
            return rebuild(value, issuerKey, alternateSubject, extraExtension, null, null, null);
        }

        private static Credential rebuild(Credential value, KeyPair issuerKey, X500Name alternateSubject,
                boolean extraExtension, BasicConstraints alternateConstraints, KeyUsage alternateKeyUsage,
                Date alternateNotAfter) {
            try {
                X509CertificateHolder original = new X509CertificateHolder(value.encoded().bytes());
                X500Name subject = alternateSubject == null ? original.getSubject() : alternateSubject;
                X509v3CertificateBuilder builder = new X509v3CertificateBuilder(original.getIssuer(),
                        original.getSerialNumber(), Date.from(original.getNotBefore().toInstant()),
                        alternateNotAfter == null ? Date.from(original.getNotAfter().toInstant()) : alternateNotAfter,
                        subject, original.getSubjectPublicKeyInfo());
                if (alternateConstraints == null) {
                    builder.addExtension(original.getExtension(Extension.basicConstraints));
                } else {
                    builder.addExtension(Extension.basicConstraints, true, alternateConstraints);
                }
                if (alternateKeyUsage == null) {
                    builder.addExtension(original.getExtension(Extension.keyUsage));
                } else {
                    builder.addExtension(Extension.keyUsage, true, alternateKeyUsage);
                }
                if (extraExtension) {
                    builder.addExtension(Extension.subjectKeyIdentifier, false, new DEROctetString(new byte[] { 1 }));
                }
                byte[] encoded = builder
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate())).getEncoded();
                return new Credential(new PkiId("x509:" + sha256(encoded)), value.formatId(), value.issuerRef(),
                        value.subjectRef(), value.validity(), value.serialOrUniqueId(), value.publicKeyId(),
                        value.profileBinding(), value.status(), new EncodedObject(Encoding.DER, encoded),
                        value.attributes());
            } catch (Exception exception) {
                throw new IllegalStateException("test certificate mutation failed", exception);
            }
        }

        private static String sha256(byte[] value) throws Exception {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        }
    }

    private enum ImportMutation {
        SUBJECT {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Substituted"), "root-ca");
            }
        },
        KIND {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Import Mutation Root"),
                        "intermediate-ca");
            }
        },
        MALFORMED_DER {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, new byte[] { 0x30, 0x01, 0x00 },
                        new SubjectRef("CN=Import Mutation Root"), "root-ca");
            }
        },
        EXTRA_EXTENSION {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Import Mutation Root"), "root-ca");
            }

            @Override
            byte[] mutate(Credential credential, KeyPair issuerKey) {
                return MetadataMutation.rebuild(credential, issuerKey, null, true).encoded().bytes();
            }
        },
        BASIC_CONSTRAINTS {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Import Mutation Root"), "root-ca");
            }

            @Override
            byte[] mutate(Credential credential, KeyPair issuerKey) {
                return MetadataMutation
                        .rebuild(credential, issuerKey, null, false, new BasicConstraints(false), null, null).encoded()
                        .bytes();
            }
        },
        KEY_USAGE {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Import Mutation Root"), "root-ca");
            }

            @Override
            byte[] mutate(Credential credential, KeyPair issuerKey) {
                return MetadataMutation.rebuild(credential, issuerKey, null, false, null,
                        new KeyUsage(KeyUsage.digitalSignature), null).encoded().bytes();
            }
        },
        VALIDITY {
            @Override
            CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded) {
                return importCommand(runtime, keyRef, encoded, new SubjectRef("CN=Import Mutation Root"), "root-ca");
            }

            @Override
            byte[] mutate(Credential credential, KeyPair issuerKey) {
                Date extended = Date.from(credential.validity().notAfter().plusSeconds(1));
                return MetadataMutation.rebuild(credential, issuerKey, null, false, null, null, extended).encoded()
                        .bytes();
            }
        };

        abstract CaImportCommand command(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded);

        byte[] mutate(Credential credential, KeyPair issuerKey) {
            return credential.encoded().bytes();
        }

        private static CaImportCommand importCommand(PkiTestRuntime runtime, KeyRef keyRef, byte[] encoded,
                SubjectRef subject, String profileId) {
            return new CaImportCommand(runtime.framework().formatId(), subject, profileId, keyRef,
                    new EncodedObject(Encoding.DER, encoded), new SimpleAttributeSet());
        }
    }
}
