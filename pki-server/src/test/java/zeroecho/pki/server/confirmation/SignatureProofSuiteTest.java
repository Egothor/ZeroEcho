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
package zeroecho.pki.server.confirmation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;

/** Deterministic transcript, cryptographic profile, mutation, and bounds vectors. */
class SignatureProofSuiteTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Instant EXPIRY = Instant.parse("2030-01-01T00:00:00Z");
    private static final String CREDENTIAL_ID = "x509:000102030405060708090a0b0c0d0e0f"
            + "101112131415161718191a1b1c1d1e1f";
    private static final byte[] ED25519_PKCS8 = HEX.parseHex("302e020100300506032b657004220420"
            + "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    private static final byte[] ED25519_SPKI = HEX.parseHex("302a300506032b6570032100"
            + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    private static final String EXPECTED_COMMITMENT =
            "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11";
    private static final String EXPECTED_TRANSCRIPT = "5a4550500009010000000400000001"
            + "020000002663726564656e7469616c2d6b65792d706f7373657373696f6e2d636f6e6669726d6174696f6e"
            + "030000000770726f642d6575"
            + "0400000010706b692e6578616d706c652e74657374"
            + "0500000045783530393a303030313032303330343035303630373038303930613062306330643065306631"
            + "30313131323133313431353136313731383139316131623163316431653166"
            + "06000000197a65726f6563686f2e7369676e61747572652d706f702e7631"
            + "07000000205ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11"
            + "0800000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
            + "090000000c0000000070dbd88000000000";
    private static final String EXPECTED_ED25519_SIGNATURE = "ac022c376cfe85c5a44c1a493ed9842a"
            + "9ff148333bbb52d518f5038b5bb5e5aa173f9617ae56180e20cabfe2b5e3c0c72fc0688ebf838e3c8de7cd456bb9f400";

    @Test
    void deterministicTranscriptAndEd25519ProofMatchFrozenVectors() throws Exception {
        SignatureProofSuite suite = new SignatureProofSuite();
        CanonicalProofTranscript transcript = transcript(suite.descriptor(), challenge());
        assertEquals(EXPECTED_COMMITMENT,
                HEX.formatHex(suite.descriptor().configurationCommitment().bytes()));
        assertEquals(EXPECTED_TRANSCRIPT, HEX.formatHex(transcript.encoded()));

        KeyFactory keys = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = keys.generatePrivate(new PKCS8EncodedKeySpec(ED25519_PKCS8));
        PublicKey publicKey = keys.generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        suite.validatePublicKey(publicKey);
        ProofChallengeEnvelope issued = suite.createChallenge(transcript);
        byte[] signature = sign("Ed25519", null, privateKey, issued.signatureInput());
        assertEquals(EXPECTED_ED25519_SIGNATURE, HEX.formatHex(signature));
        assertEquals(VerificationResult.VERIFIED,
                suite.verify(issued, publicKey,
                        new ProofResponseEnvelope(signature, suite.descriptor().maximumResponseBytes())));
    }

    @Test
    void publicProviderDescriptorsAreExactDeterministicAndConfigurationBound() {
        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        KeyPossessionProofDescriptor rsa2048 = provider.descriptor(2_048);
        KeyPossessionProofDescriptor rsa8192 = provider.descriptor(8_192);
        KeyPossessionProofDescriptor rsa16384 = provider.descriptor(16_384);

        assertEquals(SignatureKeyPossessionProofProvider.SUITE_ID, provider.suiteId());
        assertEquals(rsa8192, provider.descriptor(8_192));
        assertEquals(32, rsa8192.challengeBytes());
        assertEquals(256, rsa2048.maximumResponseBytes());
        assertEquals(1_024, rsa8192.maximumResponseBytes());
        assertEquals(2_048, rsa16384.maximumResponseBytes());
        assertNotEquals(rsa2048.proofSuiteBinding().proofSuiteRef().configurationCommitment(),
                rsa8192.proofSuiteBinding().proofSuiteRef().configurationCommitment());
        assertNotEquals(rsa8192.proofSuiteBinding().proofSuiteRef().configurationCommitment(),
                rsa16384.proofSuiteBinding().proofSuiteRef().configurationCommitment());
        assertEquals(EXPECTED_COMMITMENT,
                rsa8192.proofSuiteBinding().proofSuiteRef().configurationCommitment());
        assertThrows(IllegalArgumentException.class, () -> provider.descriptor(2_047));
        assertThrows(IllegalArgumentException.class, () -> provider.descriptor(16_385));
    }

    @Test
    void publicProviderPreservesFrozenPresentationAndRejectsBindingMismatch() throws Exception {
        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        ConfirmationProofSuiteBinding binding = provider.descriptor(8_192).proofSuiteBinding();
        KeyPossessionProofChallengeContext context = context(binding, challenge());
        KeyPossessionProofPresentation presentation = provider.createChallenge(context);
        assertEquals(EXPECTED_TRANSCRIPT, HEX.formatHex(presentation.canonicalBytes()));

        PublicKey key = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        byte[] changedCommitment = HEX.parseHex(
                binding.proofSuiteRef().configurationCommitment());
        changedCommitment[0] ^= 1;
        ConfirmationProofSuiteBinding changedBinding = new ConfirmationProofSuiteBinding(
                new ConfirmationProofSuiteRef(binding.proofSuiteRef().suiteId(),
                        HEX.formatHex(changedCommitment)), 8_192);
        assertThrows(IllegalArgumentException.class, () -> provider.validateCredential(
                new KeyPossessionProofCredential(changedBinding, new PkiId(CREDENTIAL_ID), key)));
        assertThrows(IllegalArgumentException.class,
                () -> provider.createChallenge(context(changedBinding, challenge())));
        ConfirmationProofSuiteBinding changedMaximum = new ConfirmationProofSuiteBinding(
                binding.proofSuiteRef(), 2_048);
        assertThrows(IllegalArgumentException.class,
                () -> provider.createChallenge(context(changedMaximum, challenge())));
    }

    @Test
    void publicProviderRejectsWrongProofCoordinatesAndSuiteSpecificOversize() throws Exception {
        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        ConfirmationProofSuiteBinding binding = provider.descriptor(8_192).proofSuiteBinding();
        KeyFactory keys = KeyFactory.getInstance("Ed25519");
        PublicKey publicKey = keys.generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        PrivateKey privateKey = keys.generatePrivate(new PKCS8EncodedKeySpec(ED25519_PKCS8));
        KeyPossessionProofChallengeContext context = context(binding, challenge());
        KeyPossessionProofCredential credential = credential(binding, publicKey);
        byte[] presentation = provider.createChallenge(context).canonicalBytes();
        byte[] signature = sign("Ed25519", null, privateKey, presentation);

        assertEquals(KeyPossessionProofVerification.VERIFIED, provider.verify(context, credential,
                new KeyPossessionProofResponse(signature)));
        signature[0] ^= 1;
        assertEquals(KeyPossessionProofVerification.REJECTED, provider.verify(context, credential,
                new KeyPossessionProofResponse(signature)));
        KeyPair wrongKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertEquals(KeyPossessionProofVerification.REJECTED, provider.verify(context,
                credential(binding, wrongKey.getPublic()), new KeyPossessionProofResponse(
                        sign("Ed25519", null, privateKey, presentation))));
        assertThrows(IllegalArgumentException.class, () -> provider.verify(context,
                new KeyPossessionProofCredential(binding, new PkiId("x509:" + "11".repeat(32)), publicKey),
                new KeyPossessionProofResponse(new byte[64])));
        assertThrows(IllegalArgumentException.class, () -> provider.verify(context, credential,
                new KeyPossessionProofResponse(new byte[1_025])));

        KeyPossessionProofChallengeContext changedAudience = new KeyPossessionProofChallengeContext(
                context.realm(), "other.example.test", context.credentialId(), binding,
                context.rawChallenge(), context.expiresAt());
        assertEquals(KeyPossessionProofVerification.REJECTED, provider.verify(changedAudience, credential,
                new KeyPossessionProofResponse(sign("Ed25519", null, privateKey, presentation))));
    }

    @Test
    void publicProviderConcurrentPresentationsAreDeterministic() throws Exception {
        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        KeyPossessionProofChallengeContext context = context(
                provider.descriptor(8_192).proofSuiteBinding(), challenge());
        List<Callable<KeyPossessionProofPresentation>> calls = new ArrayList<>();
        for (int index = 0; index < 8; index++) {
            calls.add(() -> provider.createChallenge(context));
        }
        try (java.util.concurrent.ExecutorService executor = Executors.newFixedThreadPool(4)) {
            List<java.util.concurrent.Future<KeyPossessionProofPresentation>> results =
                    executor.invokeAll(calls);
            KeyPossessionProofPresentation expected = results.getFirst().get();
            for (java.util.concurrent.Future<KeyPossessionProofPresentation> result : results) {
                assertEquals(expected, result.get());
            }
        }
    }

    @Test
    void everyConfirmationEnabledBuiltInUsesInstalledDefaultDescriptor() {
        SignatureProofSuite suite = new SignatureProofSuite();
        ConfirmationProofSuiteRef expected = new ConfirmationProofSuiteRef(
                suite.descriptor().suiteId().value(),
                HEX.formatHex(suite.descriptor().configurationCommitment().bytes()));
        int confirmationEnabled = 0;

        for (BuiltInCertificateProfileTemplate template : BuiltInCertificateProfileCatalog
                .load(getClass().getClassLoader())) {
            if (template.definition().confirmationPolicy().isPresent()) {
                CredentialConfirmationPolicy policy = template.definition().confirmationPolicy().orElseThrow();
                assertEquals(expected, policy.proofSuite());
                confirmationEnabled++;
            }
        }

        assertEquals(4, confirmationEnabled);
    }

    @Test
    void everyBoundFieldMutationRejectsTheOriginalChallenge() throws Exception {
        SignatureProofSuite suite = new SignatureProofSuite();
        KeyFactory keys = KeyFactory.getInstance("Ed25519");
        PrivateKey privateKey = keys.generatePrivate(new PKCS8EncodedKeySpec(ED25519_PKCS8));
        PublicKey publicKey = keys.generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        CanonicalProofTranscript original = transcript(suite.descriptor(), challenge());
        List<byte[]> mutations = new ArrayList<>();
        byte[] version = original.encoded();
        version[12] ^= 1;
        mutations.add(version);
        byte[] purpose = original.encoded();
        purpose[20] ^= 1;
        mutations.add(purpose);
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-us"), "pki.example.test",
                new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), EXPIRY).encoded());
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"), "other.example.test",
                new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), EXPIRY).encoded());
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"), "pki.example.test",
                new PkiId("x509:" + "11".repeat(32)), suite.descriptor(), challenge(), EXPIRY).encoded());
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"), "pki.example.test",
                new PkiId(CREDENTIAL_ID), descriptor("zeroecho.signature-pop.v2",
                        suite.descriptor().configurationCommitment().bytes()), challenge(), EXPIRY).encoded());
        byte[] otherCommitment = suite.descriptor().configurationCommitment().bytes();
        otherCommitment[0] ^= 1;
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"), "pki.example.test",
                new PkiId(CREDENTIAL_ID), descriptor(SignatureProofSuite.SUITE_ID.value(), otherCommitment),
                challenge(), EXPIRY).encoded());
        byte[] otherChallenge = challenge();
        otherChallenge[0] ^= 1;
        mutations.add(transcript(suite.descriptor(), otherChallenge).encoded());
        mutations.add(new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"), "pki.example.test",
                new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), EXPIRY.plusSeconds(1)).encoded());

        for (byte[] mutation : mutations) {
            ProofChallengeEnvelope issued = suite.createChallenge(original);
            byte[] signature = sign("Ed25519", null, privateKey, mutation);
            assertEquals(VerificationResult.REJECTED, suite.verify(issued, publicKey,
                    new ProofResponseEnvelope(signature, suite.descriptor().maximumResponseBytes())));
        }
    }

    @Test
    void standardSignatureProfilesVerifyAndUnsupportedKeysFailClosed() throws Exception {
        verifyGenerated("RSA", 2_048, null, "RSASSA-PSS",
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        verifyGenerated("EC", 0, "secp256r1", "SHA256withECDSA", null);
        verifyGenerated("EC", 0, "secp384r1", "SHA384withECDSA", null);
        verifyGenerated("EC", 0, "secp521r1", "SHA512withECDSA", null);
        verifyGenerated("Ed25519", 0, null, "Ed25519", null);
        verifyGenerated("Ed448", 0, null, "Ed448", null);

        KeyPairGenerator rsa1024 = KeyPairGenerator.getInstance("RSA");
        rsa1024.initialize(1_024);
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(2_048);
        SignatureProofSuite suite = new SignatureProofSuite();
        assertThrows(IllegalArgumentException.class,
                () -> suite.validatePublicKey(rsa1024.generateKeyPair().getPublic()));
        assertThrows(IllegalArgumentException.class,
                () -> suite.validatePublicKey(dsa.generateKeyPair().getPublic()));
        assertThrows(IllegalArgumentException.class, () -> suite.createChallenge(
                transcript(descriptor("zeroecho.signature-pop.v2",
                        suite.descriptor().configurationCommitment().bytes()), challenge())));
    }

    @Test
    void rsaConfigurationBindsCommitmentBoundsAndPublicExponent() {
        SignatureProofSuite rsa2048 = new SignatureProofSuite(2_048);
        SignatureProofSuite rsa8192 = new SignatureProofSuite();
        SignatureProofSuite rsa16384 = new SignatureProofSuite(16_384);

        assertEquals(256, rsa2048.descriptor().maximumResponseBytes());
        assertEquals(1_024, rsa8192.descriptor().maximumResponseBytes());
        assertEquals(2_048, rsa16384.descriptor().maximumResponseBytes());
        assertNotEquals(rsa2048.descriptor().configurationCommitment(),
                rsa8192.descriptor().configurationCommitment());
        assertNotEquals(rsa8192.descriptor().configurationCommitment(),
                rsa16384.descriptor().configurationCommitment());
        assertNotEquals(rsa2048.descriptor().configurationCommitment(),
                rsa16384.descriptor().configurationCommitment());
        assertThrows(IllegalArgumentException.class, () -> new SignatureProofSuite(2_047));
        assertThrows(IllegalArgumentException.class, () -> new SignatureProofSuite(16_385));

        CanonicalProofTranscript transcript = transcript(rsa8192.descriptor(), challenge());
        rsa8192.validatePublicKey(rsaKey(8_192, BigInteger.valueOf(65_537L)));
        assertThrows(IllegalArgumentException.class,
                () -> rsa8192.validatePublicKey(rsaKey(8_192, BigInteger.valueOf(3L))));
        assertThrows(IllegalArgumentException.class,
                () -> rsa8192.validatePublicKey(rsaKey(8_193, BigInteger.valueOf(65_537L))));
    }

    @Test
    void fullDescriptorIdentityRejectsAlteredNumericBounds() throws Exception {
        SignatureProofSuite suite = new SignatureProofSuite();
        PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        ProofSuiteDescriptor alteredChallenge = new ProofSuiteDescriptor(SignatureProofSuite.SUITE_ID,
                suite.descriptor().configurationCommitment(), SignatureProofSuite.CHALLENGE_BYTES + 1,
                suite.descriptor().maximumResponseBytes());
        ProofSuiteDescriptor alteredResponse = new ProofSuiteDescriptor(SignatureProofSuite.SUITE_ID,
                suite.descriptor().configurationCommitment(), SignatureProofSuite.CHALLENGE_BYTES,
                suite.descriptor().maximumResponseBytes() - 1);

        assertThrows(IllegalArgumentException.class, () -> suite.createChallenge(
                transcript(alteredChallenge, new byte[SignatureProofSuite.CHALLENGE_BYTES + 1])));
        assertThrows(IllegalArgumentException.class,
                () -> suite.createChallenge(transcript(alteredResponse, challenge())));

        ProofChallengeEnvelope issued = suite.createChallenge(transcript(suite.descriptor(), challenge()));
        ProofResponseEnvelope response = new ProofResponseEnvelope(new byte[64],
                suite.descriptor().maximumResponseBytes());
        assertThrows(IllegalArgumentException.class, () -> suite.verify(
                new ProofChallengeEnvelope(alteredChallenge, issued.signatureInput(), issued.expiresAt()),
                publicKey, response));
        assertThrows(IllegalArgumentException.class, () -> suite.verify(
                new ProofChallengeEnvelope(alteredResponse, issued.signatureInput(), issued.expiresAt()),
                publicKey, response));
    }

    @Test
    void envelopesAreBoundedImmutableAndVerificationRetainsNoRequestState() throws Exception {
        SignatureProofSuite suite = new SignatureProofSuite();
        byte[] sourceChallenge = challenge();
        CanonicalProofTranscript transcript = transcript(suite.descriptor(), sourceChallenge);
        byte[] before = transcript.encoded();
        Arrays.fill(sourceChallenge, (byte) 0);
        assertArrayEquals(before, transcript.encoded());
        byte[] challengeCopy = transcript.encoded();
        challengeCopy[0] ^= 1;
        assertFalse(Arrays.equals(challengeCopy, transcript.encoded()));

        byte[] sourceResponse = { 1, 2, 3 };
        ProofResponseEnvelope response = new ProofResponseEnvelope(sourceResponse, 3);
        sourceResponse[0] = 9;
        assertArrayEquals(new byte[] { 1, 2, 3 }, response.response());
        byte[] responseCopy = response.response();
        responseCopy[0] = 9;
        assertArrayEquals(new byte[] { 1, 2, 3 }, response.response());

        PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        PrivateKey privateKey = KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(ED25519_PKCS8));
        ProofChallengeEnvelope issued = suite.createChallenge(transcript);
        byte[] challengePayload = issued.signatureInput();
        challengePayload[0] ^= 1;
        assertArrayEquals(transcript.encoded(), issued.signatureInput());
        byte[] signature = sign("Ed25519", null, privateKey, issued.signatureInput());
        ProofResponseEnvelope validResponse = new ProofResponseEnvelope(signature,
                suite.descriptor().maximumResponseBytes());
        assertEquals(VerificationResult.VERIFIED, suite.verify(issued, publicKey, validResponse));
        assertEquals(VerificationResult.VERIFIED, suite.verify(issued, publicKey, validResponse));
    }

    @Test
    void malformedAndOversizedFoundationInputsAreRejected() {
        SignatureProofSuite suite = new SignatureProofSuite();
        assertEquals(EXPECTED_COMMITMENT,
                HEX.formatHex(suite.descriptor().configurationCommitment().bytes()));
        assertThrows(IllegalArgumentException.class, () -> new ProofSuiteId("signature-pop"));
        assertThrows(IllegalArgumentException.class, () -> new ProofSuiteCommitment(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> new ProofSuiteDescriptor(SignatureProofSuite.SUITE_ID,
                        suite.descriptor().configurationCommitment(), 31, 1));
        assertThrows(IllegalArgumentException.class, () -> new ProofResponseEnvelope(new byte[0], 1));
        assertThrows(IllegalArgumentException.class, () -> new ProofResponseEnvelope(new byte[2], 1));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalProofTranscript(
                new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId("x509:not-a-digest"), suite.descriptor(), challenge(), EXPIRY));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalProofTranscript(
                new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId(CREDENTIAL_ID), suite.descriptor(), new byte[31], EXPIRY));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalProofTranscript(
                new ConfirmationRealmBinding("prod-eu"),
                "x".repeat(513), new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), EXPIRY));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalProofTranscript(
                new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), EXPIRY.plusNanos(1)));
        assertThrows(IllegalArgumentException.class, () -> new CanonicalProofTranscript(
                new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId(CREDENTIAL_ID), suite.descriptor(), challenge(), Instant.EPOCH.minusSeconds(1)));
    }

    @Test
    void decoderRejectsEveryNoncanonicalOrOutOfBoundTranscriptShape() throws Exception {
        SignatureProofSuite suite = new SignatureProofSuite();
        byte[] canonical = transcript(suite.descriptor(), challenge()).encoded();
        assertArrayEquals(canonical, CanonicalProofTranscript.decode(canonical, suite.descriptor()).encoded());

        List<byte[]> malformed = new ArrayList<>();
        malformed.add(Arrays.copyOf(canonical, canonical.length - 1));
        malformed.add(Arrays.copyOf(canonical, CanonicalProofTranscript.MAXIMUM_ENCODED_BYTES + 1));
        malformed.add(changedByte(canonical, 0, (byte) 'X'));
        malformed.add(changedByte(canonical, 5, (byte) 8));
        malformed.add(changedByte(canonical, fieldHeader(canonical, 1), (byte) 2));
        malformed.add(changedLength(canonical, 1, -1));
        malformed.add(changedLength(canonical, 3, 129));
        malformed.add(changedLength(canonical, 4, 513));
        malformed.add(changedLength(canonical, 6, ProofSuiteId.MAXIMUM_LENGTH + 1));
        malformed.add(changedLength(canonical, 7, ProofSuiteCommitment.LENGTH - 1));
        malformed.add(changedLength(canonical, 8, SignatureProofSuite.CHALLENGE_BYTES - 1));
        malformed.add(changedLength(canonical, 9, Long.BYTES + Integer.BYTES - 1));
        malformed.add(changedByte(canonical, fieldValue(canonical, 1) + Integer.BYTES - 1, (byte) 2));
        malformed.add(changedByte(canonical, fieldValue(canonical, 2), (byte) 'X'));
        malformed.add(changedByte(canonical, fieldValue(canonical, 3), (byte) 'P'));
        byte[] malformedUtf8 = changedByte(canonical, fieldValue(canonical, 4), (byte) 0xc3);
        malformedUtf8[fieldValue(canonical, 4) + 1] = 0x28;
        malformed.add(malformedUtf8);
        malformed.add(changedByte(canonical, fieldValue(canonical, 5), (byte) 'X'));
        malformed.add(changedByte(canonical, fieldValue(canonical, 6), (byte) 'Z'));
        malformed.add(changedByte(canonical, fieldValue(canonical, 7), (byte) 1));
        malformed.add(changedByte(canonical, fieldValue(canonical, 9) + Long.BYTES + Integer.BYTES - 1,
                (byte) 1));
        malformed.add(Arrays.copyOf(canonical, canonical.length + 1));

        for (byte[] candidate : malformed) {
            assertThrows(IllegalArgumentException.class,
                    () -> CanonicalProofTranscript.decode(candidate, suite.descriptor()));
        }

        PublicKey publicKey = KeyFactory.getInstance("Ed25519")
                .generatePublic(new X509EncodedKeySpec(ED25519_SPKI));
        ProofChallengeEnvelope invalid = new ProofChallengeEnvelope(suite.descriptor(),
                changedByte(canonical, 0, (byte) 'X'), EXPIRY);
        assertThrows(IllegalArgumentException.class, () -> suite.verify(invalid, publicKey,
                new ProofResponseEnvelope(new byte[64], suite.descriptor().maximumResponseBytes())));
    }

    private static void verifyGenerated(String keyAlgorithm, int keySize, String parameter,
            String signatureAlgorithm, PSSParameterSpec signatureParameters) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        if (keySize != 0) {
            generator.initialize(keySize);
        } else if (parameter != null) {
            generator.initialize(new ECGenParameterSpec(parameter));
        }
        KeyPair keyPair = generator.generateKeyPair();
        SignatureProofSuite suite = new SignatureProofSuite();
        suite.validatePublicKey(keyPair.getPublic());
        ProofChallengeEnvelope issued = suite.createChallenge(transcript(suite.descriptor(), challenge()));
        byte[] signature = sign(signatureAlgorithm, signatureParameters, keyPair.getPrivate(),
                issued.signatureInput());
        assertEquals(VerificationResult.VERIFIED,
                suite.verify(issued, keyPair.getPublic(),
                        new ProofResponseEnvelope(signature, suite.descriptor().maximumResponseBytes())));

        SignatureKeyPossessionProofProvider provider = new SignatureKeyPossessionProofProvider();
        ConfirmationProofSuiteBinding binding = provider.descriptor(8_192).proofSuiteBinding();
        KeyPossessionProofChallengeContext context = context(binding, challenge());
        KeyPossessionProofCredential credential = credential(binding, keyPair.getPublic());
        provider.validateCredential(credential);
        byte[] providerPresentation = provider.createChallenge(context).canonicalBytes();
        byte[] providerSignature = sign(signatureAlgorithm, signatureParameters,
                keyPair.getPrivate(), providerPresentation);
        assertEquals(KeyPossessionProofVerification.VERIFIED, provider.verify(context, credential,
                new KeyPossessionProofResponse(providerSignature)));
    }

    private static byte[] sign(String algorithm, PSSParameterSpec parameters, PrivateKey key, byte[] input)
            throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        if (parameters != null) {
            signer.setParameter(parameters);
        }
        signer.initSign(key);
        signer.update(input);
        return signer.sign();
    }

    private static CanonicalProofTranscript transcript(ProofSuiteDescriptor descriptor, byte[] challenge) {
        return new CanonicalProofTranscript(new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId(CREDENTIAL_ID),
                descriptor, challenge, EXPIRY);
    }

    private static KeyPossessionProofChallengeContext context(
            ConfirmationProofSuiteBinding binding, byte[] challenge) {
        return new KeyPossessionProofChallengeContext(new ConfirmationRealmBinding("prod-eu"),
                "pki.example.test", new PkiId(CREDENTIAL_ID), binding, challenge, EXPIRY);
    }

    private static KeyPossessionProofCredential credential(
            ConfirmationProofSuiteBinding binding, PublicKey key) {
        return new KeyPossessionProofCredential(binding, new PkiId(CREDENTIAL_ID), key);
    }

    private static ProofSuiteDescriptor descriptor(String id, byte[] commitment) {
        return new ProofSuiteDescriptor(new ProofSuiteId(id), new ProofSuiteCommitment(commitment),
                SignatureProofSuite.CHALLENGE_BYTES,
                new SignatureProofSuite().descriptor().maximumResponseBytes());
    }

    private static byte[] challenge() {
        byte[] challenge = new byte[SignatureProofSuite.CHALLENGE_BYTES];
        for (int index = 0; index < challenge.length; index++) {
            challenge[index] = (byte) (0xa0 + index);
        }
        return challenge;
    }

    private static byte[] changedByte(byte[] source, int offset, byte value) {
        byte[] changed = source.clone();
        changed[offset] = value;
        return changed;
    }

    private static byte[] changedLength(byte[] source, int tag, int length) {
        byte[] changed = source.clone();
        ByteBuffer.wrap(changed).putInt(fieldHeader(changed, tag) + Byte.BYTES, length);
        return changed;
    }

    private static int fieldValue(byte[] encoded, int targetTag) {
        return fieldHeader(encoded, targetTag) + Byte.BYTES + Integer.BYTES;
    }

    private static int fieldHeader(byte[] encoded, int targetTag) {
        ByteBuffer input = ByteBuffer.wrap(encoded);
        input.position(4 + Short.BYTES);
        for (int tag = 1; tag <= CanonicalProofTranscript.VERSION + 8; tag++) {
            int offset = input.position();
            int actualTag = Byte.toUnsignedInt(input.get());
            int length = input.getInt();
            if (actualTag != tag) {
                throw new AssertionError("Fixture transcript is malformed");
            }
            if (tag == targetTag) {
                return offset;
            }
            input.position(input.position() + length);
        }
        throw new AssertionError("Fixture transcript does not contain tag " + targetTag);
    }

    private static RSAPublicKey rsaKey(int modulusBits, BigInteger exponent) {
        return new TestRsaPublicKey(BigInteger.ONE.shiftLeft(modulusBits - 1).setBit(0), exponent);
    }

    private static final class TestRsaPublicKey implements RSAPublicKey {
        private static final long serialVersionUID = 1L;

        private final BigInteger modulus;
        private final BigInteger publicExponent;

        private TestRsaPublicKey(BigInteger modulus, BigInteger publicExponent) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
        }

        @Override public BigInteger getModulus() { return modulus; }
        @Override public BigInteger getPublicExponent() { return publicExponent; }
        @Override public String getAlgorithm() { return "RSA"; }
        @Override public String getFormat() { return "X.509"; }
        @Override public byte[] getEncoded() { return new byte[0]; }
    }
}
