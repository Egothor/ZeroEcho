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
package zeroecho.pki.server.acme;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.profile.CertificateProfileRef;

/** Strict replay, JOSE and bounded-admission coverage. */
class AcmeSecurityPrimitivesTest {
    private static final Instant NOW = Instant.parse("2026-08-05T08:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String DIRECTORY = "directory:internal:r1";
    private static final String NONCE_SCOPE = "internal";
    private static final URI URL = URI.create("https://acme.example.test/acme/internal/new-account");

    @Test
    void nonceIsDirectoryBoundOneTimeAndBounded() {
        System.out.println("nonceIsDirectoryBoundOneTimeAndBounded");
        AcmeNonceService service = new AcmeNonceService("listener", Duration.ofMinutes(5), 16,
                CLOCK, deterministicRandom());
        String first = service.issue(NONCE_SCOPE);
        assertFalse(service.consume(first, "other"));
        assertTrue(service.consume(first, NONCE_SCOPE));
        assertFalse(service.consume(first, NONCE_SCOPE));
        for (int index = 0; index < 16; index++) service.issue(NONCE_SCOPE);
        assertThrows(IllegalStateException.class, () -> service.issue(NONCE_SCOPE));
        System.out.println("...nonce-length=" + first.length());
        System.out.println("...ok");
    }

    @Test
    void completionWireBoundIsExactListenerMinimum() throws Exception {
        URI external = URI.create("https://acme.example.test");
        int minimum = AcmeWireBounds.minimumCompletionDocumentBytes(external);
        String identifier = "a".repeat(128);
        String alias = "a".repeat(63);
        String kid = external.resolve("/acme/" + alias + "/account/" + identifier).toASCIIString();
        String url = external.resolve("/acme/" + alias
                + "/credential-confirmation/v1/complete/" + identifier).toASCIIString();
        String protectedJson = "{\"alg\":\"ES256\",\"kid\":\"" + kid
                + "\",\"nonce\":\"" + "a".repeat(43) + "\",\"url\":\"" + url + "\"}";
        String payloadJson = "{\"expectedLifecycleRevision\":9223372036854775807,"
                + "\"expectedLifecycleRecordCommitment\":\"" + "a".repeat(64) + "\","
                + "\"expectedChallengeRecordCommitment\":\"" + "a".repeat(64) + "\","
                + "\"response\":\"" + "a".repeat(AcmeWireBounds.MAX_PROOF_B64URL_CHARS) + "\"}";
        String document = "{\"protected\":\""
                + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        protectedJson.getBytes(StandardCharsets.US_ASCII))
                + "\",\"payload\":\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(
                        payloadJson.getBytes(StandardCharsets.US_ASCII))
                + "\",\"signature\":\"" + "a".repeat(86) + "\"}";
        assertEquals(document.getBytes(StandardCharsets.US_ASCII).length, minimum);
        assertTrue(minimum > 1_024);
        assertThrows(IllegalArgumentException.class, () -> listener(external, minimum - 1));
        assertEquals(minimum, listener(external, minimum).maximumBodyBytes());
    }

    @Test
    void es256JwsRequiresCanonicalUrlNonceAndJwkMode() throws Exception {
        System.out.println("es256JwsRequiresCanonicalUrlNonceAndJwkMode");
        KeyPair key = accountKey();
        AcmeNonceService nonces = new AcmeNonceService("listener", Duration.ofMinutes(5), 16,
                CLOCK, deterministicRandom());
        String nonce = nonces.issue(NONCE_SCOPE);
        byte[] document = jws(key, nonce, URL, "{}".getBytes(StandardCharsets.UTF_8));
        AcmeJwsVerifier.Verified verified = new AcmeJwsVerifier().verify(document, 65_536, URL, NONCE_SCOPE,
                AcmeJwsVerifier.KeyMode.JWK, nonces, ignored -> { throw new AssertionError(); });
        assertEquals(64, verified.keyThumbprint().length());
        assertThrows(AcmeJwsVerifier.AcmeProblem.class, () -> new AcmeJwsVerifier().verify(document,
                65_536, URL, NONCE_SCOPE, AcmeJwsVerifier.KeyMode.JWK, nonces,
                ignored -> { throw new AssertionError(); }));
        String second = nonces.issue(NONCE_SCOPE);
        byte[] wrongUrl = jws(key, second, URI.create("https://wrong.example/acme/internal/new-account"),
                "{}".getBytes(StandardCharsets.UTF_8));
        assertThrows(AcmeJwsVerifier.AcmeProblem.class, () -> new AcmeJwsVerifier().verify(wrongUrl,
                65_536, URL, NONCE_SCOPE, AcmeJwsVerifier.KeyMode.JWK, nonces,
                ignored -> { throw new AssertionError(); }));
        System.out.println("...algorithm=ES256");
        System.out.println("...ok");
    }

    @Test
    void accountCodecAndAdmissionRemainFiniteAndDeterministic() throws Exception {
        System.out.println("accountCodecAndAdmissionRemainFiniteAndDeterministic");
        KeyPair key = accountKey();
        AcmeState.Account source = new AcmeState.Account("account:test", DIRECTORY, 1, "1".repeat(64),
                "2".repeat(64), key.getPublic().getEncoded(), AcmeState.AccountStatus.VALID,
                List.of("mailto:operator@example.test"), true, Optional.empty(), NOW, NOW, "0".repeat(64));
        AcmeStateCodec codec = new AcmeStateCodec();
        AcmeState.Account sealed = (AcmeState.Account) codec.seal(source);
        AcmeState.Account decoded = (AcmeState.Account) codec.decode(codec.encode(sealed));
        assertEquals(sealed.accountId(), decoded.accountId());
        assertEquals(sealed.commitment(), decoded.commitment());
        assertArrayEquals(sealed.publicKeySpki(), decoded.publicKeySpki());
        PkiServerConfiguration.AcmeListener configuration = listener();
        AcmeRateAdmission admission = new AcmeRateAdmission(configuration, CLOCK);
        assertTrue(admission.admitOrder("account:test"));
        assertFalse(admission.admitOrder("account:test"));
        assertTrue(admission.tryAcquireFinalization());
        assertFalse(admission.tryAcquireFinalization());
        admission.releaseFinalization();
        System.out.println("...record-commitment=" + sealed.commitment().substring(0, 12));
        System.out.println("...ok");
    }

    @Test
    void accountHistoryRejectsMissingCurrentKeyDuplicateKeysAndOldFormats() throws Exception {
        byte[] spki = accountKey().getPublic().getEncoded();
        AcmeState.AccountKeyIdentity identity = AcmeState.AccountKeyIdentity.fromKey(spki, Set.of());
        AcmeState.AccountKeyIdentity other = new AcmeState.AccountKeyIdentity("f".repeat(64), Set.of("e".repeat(64)), Set.of());
        for (List<AcmeState.AccountKeyIdentity> history : List.of(List.<AcmeState.AccountKeyIdentity>of(),
                List.of(other), List.of(identity, identity), java.util.Collections.nCopies(257, identity))) {
            assertThrows(IllegalArgumentException.class, () -> new AcmeState.Account("account:test", DIRECTORY, 1,
                    "1".repeat(64), "2".repeat(64), spki, AcmeState.AccountStatus.VALID, List.of(), true,
                    Optional.empty(), NOW, NOW, "0".repeat(64), history));
        }
        AcmeState.Account account = new AcmeState.Account("account:test", DIRECTORY, 1, "1".repeat(64),
                "2".repeat(64), spki, AcmeState.AccountStatus.VALID, List.of(), true, Optional.empty(), NOW, NOW,
                "0".repeat(64));
        AcmeStateCodec codec = new AcmeStateCodec();
        byte[] previous = codec.encode(codec.seal(account));
        java.nio.ByteBuffer.wrap(previous).putInt(4, 7);
        assertThrows(IllegalArgumentException.class, () -> codec.decode(previous));
    }

    @Test
    void processingOrderCodecRetainsExactSigningOperation() {
        PkiId operationId = new PkiId("signing:acme-restart");
        AcmeState.Order source = new AcmeState.Order("order:restart", "account:test", DIRECTORY, 1,
                "1".repeat(64), new PkiId("ca:test"),
                new CertificateProfileRef("leaf", 1, new byte[32]), new PkiId("issuer:test"),
                new PkiId("path:test"), "2".repeat(64),
                List.of(new AcmeState.Identifier(AcmeState.IdentifierType.DNS, "example.test", false)),
                Optional.empty(), Optional.empty(), AcmeState.OrderStatus.PROCESSING,
                List.of("authorization:test"), Optional.empty(), Optional.of("3".repeat(64)), Optional.of(operationId),
                NOW, NOW.plus(Duration.ofHours(1)), "0".repeat(64));
        AcmeStateCodec codec = new AcmeStateCodec();

        AcmeState.Order sealed = (AcmeState.Order) codec.seal(source);
        AcmeState.Order decoded = (AcmeState.Order) codec.decode(codec.encode(sealed));

        assertEquals(AcmeState.OrderStatus.PROCESSING, decoded.status());
        assertEquals(Optional.of("3".repeat(64)), decoded.issuanceCommitment());
        assertEquals(Optional.of(operationId), decoded.signingOperationId());
        assertEquals(sealed.commitment(), decoded.commitment());
    }

    @Test
    void directoryCodecFreezesExactConfirmationPolicyInCommitment() {
        CredentialConfirmationPolicy policy = confirmationPolicy(ConfirmationDisclosurePolicy.OWNER_ONLY);
        AcmeState.Directory source = directory(policy, policy.configurationCommitment());
        AcmeStateCodec codec = new AcmeStateCodec();

        AcmeState.Directory sealed = (AcmeState.Directory) codec.seal(source);
        AcmeState.Directory decoded = (AcmeState.Directory) codec.decode(codec.encode(sealed));
        AcmeState.Directory inactive = (AcmeState.Directory) codec.seal(new AcmeState.Directory(
                sealed.directoryId(), sealed.alias(), sealed.revision(), sealed.realmId(), sealed.authorityId(),
                sealed.profile(), sealed.enrollmentProfileId(), sealed.issuerId(), sealed.issuancePathId(), sealed.issuancePathCommitment(),
                sealed.identifierTypes(), sealed.dnsNamespaces(), sealed.maximumValidity(),
                sealed.publicKeyAlgorithms(), sealed.x509BindingPolicies(), sealed.challengeTypes(),
                sealed.challengeProviderIds(), sealed.eabProviderId(), sealed.eabRequired(),
                sealed.confirmationPolicy(), sealed.confirmationPolicyCommitment(),
                AcmeState.DirectoryStatus.INACTIVE, sealed.policyCommitment(), sealed.createdAt(),
                "0".repeat(64)));
        AcmeState.Directory publicDirectory = (AcmeState.Directory) codec.seal(directory(
                confirmationPolicy(ConfirmationDisclosurePolicy.PUBLIC),
                confirmationPolicy(ConfirmationDisclosurePolicy.PUBLIC).configurationCommitment()));

        assertEquals(policy, decoded.confirmationPolicy());
        assertEquals(policy.configurationCommitment(), decoded.confirmationPolicyCommitment());
        assertEquals(sealed.commitment(), decoded.commitment());
        assertEquals(sealed.policyCommitment(), inactive.policyCommitment());
        assertNotEquals(sealed.commitment(), inactive.commitment());
        assertNotEquals(sealed.commitment(), publicDirectory.commitment());
        assertThrows(IllegalArgumentException.class, () -> directory(policy, "8".repeat(64)));
    }

    private static AcmeState.Directory directory(CredentialConfirmationPolicy policy, String policyCommitment) {
        return new AcmeState.Directory(DIRECTORY, "internal", 1, new RealmId("realm"), new PkiId("ca:test"),
                new CertificateProfileRef("leaf", 1, new byte[32]), "acme-enrollment", new PkiId("issuer:test"),
                new PkiId("path:test"), "1".repeat(64), Set.of(AcmeState.IdentifierType.DNS),
                Set.of("example.test"), Duration.ofDays(30), Set.of("RSA"), Set.of("STANDARD_ONLY"),
                Set.of(AcmeState.ChallengeType.HTTP_01), Set.of("http"), Optional.empty(), false,
                policy, policyCommitment, AcmeState.DirectoryStatus.ACTIVE, "2".repeat(64), NOW,
                "0".repeat(64));
    }

    private static CredentialConfirmationPolicy confirmationPolicy(ConfirmationDisclosurePolicy disclosure) {
        return new CredentialConfirmationPolicy(disclosure, Duration.ofHours(24),
                new ConfirmationProofSuiteRef("zeroecho.signature-pop.v1", "7".repeat(64)));
    }

    private static PkiServerConfiguration.AcmeListener listener() throws Exception {
        return listener(URI.create("https://acme.example.test"), 1_048_576);
    }

    private static PkiServerConfiguration.AcmeListener listener(URI externalBaseUri,
            int maximumBodyBytes) throws Exception {
        PkiServerConfiguration.Execution execution = new PkiServerConfiguration.Execution(1, 1, 1, 1, 1,
                Duration.ofSeconds(5), Duration.ofSeconds(5), Duration.ofSeconds(1), Duration.ofSeconds(1));
        return new PkiServerConfiguration.AcmeListener("listener", InetAddress.getLoopbackAddress(), 0,
                new ProviderConfig("tls-test", Map.of()), PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS,
                List.of(), Set.of(), externalBaseUri, 4096, maximumBodyBytes,
                execution, execution, Duration.ofMinutes(5), 16, 16, 16, Duration.ofMinutes(1),
                2, 1, 2, 2, 1, List.of(), List.of());
    }

    private static byte[] jws(KeyPair key, String nonce, URI url, byte[] payload) throws Exception {
        ECPublicKey publicKey = (ECPublicKey) key.getPublic();
        String x = coordinate(publicKey.getW().getAffineX());
        String y = coordinate(publicKey.getW().getAffineY());
        String protectedJson = "{\"alg\":\"ES256\",\"nonce\":\"" + nonce + "\",\"url\":\""
                + url + "\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x
                + "\",\"y\":\"" + y + "\"}}";
        String protectedValue = encode(protectedJson.getBytes(StandardCharsets.UTF_8));
        String payloadValue = encode(payload);
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(key.getPrivate(), deterministicRandom());
        signer.update((protectedValue + "." + payloadValue).getBytes(StandardCharsets.US_ASCII));
        return ("{\"protected\":\"" + protectedValue + "\",\"payload\":\"" + payloadValue
                + "\",\"signature\":\"" + encode(signer.sign()) + "\"}").getBytes(StandardCharsets.UTF_8);
    }

    private static KeyPair accountKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), deterministicRandom());
        return generator.generateKeyPair();
    }

    private static String coordinate(BigInteger value) {
        byte[] source = value.toByteArray(); byte[] exact = new byte[32];
        int length = Math.min(source.length, exact.length);
        System.arraycopy(source, source.length - length, exact, exact.length - length, length);
        return encode(exact);
    }
    private static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static SecureRandom deterministicRandom() {
        try {
            SecureRandom value = SecureRandom.getInstance("SHA1PRNG");
            value.setSeed(new byte[] {1, 3, 3, 7}); return value;
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
