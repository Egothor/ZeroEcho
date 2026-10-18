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

package zeroecho.pki.impl.crypto.zeroecholib;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.CallControl;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.crypto.SigningProvider.OperationObservation;
import zeroecho.pki.spi.crypto.SigningProvider.SignRequest;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;

final class ZeroEchoLibSigningProviderTest {
    private static final String NAMESPACE = "0123456789abcdef0123456789abcdef.zeroecho-lib";
    private static final AccessContext ACCESS = new AccessContext(new Principal("TEST", "owner"),
            new Purpose("TEST"), Optional.empty(), Optional.empty());

    @Test
    void enumeratesOnlyKnownPrivateAliasesWithoutKeyMaterial(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path path = createKeyring(root, pair);
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire(); KeyringStore keyring = KeyringStore.open(path, password)) {
            keyring.putPublic("public-only.pub", "RSA", pair.getPublic());
        }
        try (SigningProvider opened = provider(path)) {
            java.util.List<KeyRef> keys = new java.util.ArrayList<>();
            ((ZeroEchoLibSigningProvider) opened).visitKnownKeyReferences(keys::add);
            assertEquals(java.util.Set.of(new KeyRef("zeroecho-lib:test.prv")), java.util.Set.copyOf(keys));
        }
    }

    @Test
    void signsInlineWithoutRetainedOperationStateAndNeverReplaysOnReconcile(@TempDir Path root)
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] payload = new byte[] { 1, 2, 3, 4 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            SignRequest request = request(provider, new PkiId("operation-1"), payload,
                    repeatable(payload, new AtomicInteger()));
            OperationObservation observation = provider.dispatch(request, control());
            assertEquals(ObservationState.SUCCEEDED, observation.state());
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(pair.getPublic());
            verifier.update(payload);
            assertTrue(verifier.verify(observation.signature().orElseThrow().bytes()));

            OperationObservation recovered = provider.reconcile(request.operationId(), control());
            assertEquals(ObservationState.UNRECOVERABLE, recovered.state());
            assertEquals(DetailCode.LOCAL_RESTART_UNRECOVERABLE, recovered.detailCode());
        }
        assertFalse(Arrays.stream(ZeroEchoLibSigningProvider.class.getDeclaredFields())
                .anyMatch(field -> Map.class.isAssignableFrom(field.getType())),
                "local provider must retain no per-operation maps");
    }

    @Test
    void rejectsNamespaceAndConfigurationMismatchBeforeContentOrCrypto(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        AtomicInteger opens = new AtomicInteger();
        byte[] payload = new byte[] { 5, 6, 7 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            SignRequest foreignNamespace = request(provider, new PkiId("operation-2"), payload,
                    repeatable(payload, opens), "foreign.zeroecho-lib", provider.configurationCommitment());
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> provider.dispatch(foreignNamespace, control()));

            SignRequest foreignConfiguration = request(provider, new PkiId("operation-3"), payload,
                    repeatable(payload, opens), NAMESPACE,
                    new SigningProvider.ConfigurationCommitment(new byte[32]));
            org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                    () -> provider.dispatch(foreignConfiguration, control()));
            assertEquals(0, opens.get());
        }
    }

    @Test
    void mapsInvalidKeyReferenceToFiniteSafeDetail(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] payload = new byte[] { 8 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            SignRequest request = request(provider, new PkiId("operation-4"), payload,
                    repeatable(payload, new AtomicInteger()), NAMESPACE,
                    provider.configurationCommitment(), new KeyRef("foreign:secret.prv"));
            OperationObservation observation = provider.dispatch(request, control());
            assertEquals(ObservationState.FAILED, observation.state());
            assertEquals(DetailCode.INVALID_KEY_REFERENCE, observation.detailCode());
        }
    }

    @Test
    void binaryDerAndPemEncodingsProduceCryptographicallyEquivalentSignatures(@TempDir Path root)
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] payload = new byte[] { 9, 10, 11, 12 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            for (Encoding encoding : List.of(Encoding.BINARY, Encoding.DER, Encoding.PEM)) {
                SignRequest request = request(provider, new PkiId("operation-encoding-" + encoding), payload,
                        repeatable(payload, new AtomicInteger()), NAMESPACE,
                        provider.configurationCommitment(), new KeyRef("zeroecho-lib:test.prv"),
                        "SHA256withRSA", encoding, ContentCommitment.sha256(payload), CancellationSignal.NONE);
                OperationObservation observation = provider.dispatch(request, control());
                assertEquals(ObservationState.SUCCEEDED, observation.state());
                assertEquals(encoding, observation.signature().orElseThrow().encoding());
                Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(pair.getPublic());
                verifier.update(payload);
                assertTrue(verifier.verify(rawSignature(observation.signature().orElseThrow().bytes(), encoding)));
            }
        }
    }

    @Test
    void contentMismatchConsumesOnePassAndReturnsFiniteIntegrityFailure(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] actual = new byte[] { 13, 14, 15 };
        AtomicInteger opens = new AtomicInteger();
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            SignRequest request = request(provider, new PkiId("operation-integrity"), actual,
                    repeatable(actual, opens), NAMESPACE, provider.configurationCommitment(),
                    new KeyRef("zeroecho-lib:test.prv"), "SHA256withRSA", Encoding.BINARY,
                    ContentCommitment.sha256(new byte[] { 13, 14, 16 }), CancellationSignal.NONE);
            OperationObservation observation = provider.dispatch(request, control());
            assertEquals(ObservationState.FAILED, observation.state());
            assertEquals(DetailCode.CONTENT_INTEGRITY_FAILURE, observation.detailCode());
            assertTrue(observation.signature().isEmpty());
            assertEquals(1, opens.get());
        }
    }

    @Test
    void invalidAlgorithmMissingKeyAndKeyMismatchUseFiniteSafeDetails(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] payload = new byte[] { 17, 18 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            assertFailure(provider, payload, "SHA1withRSA", new KeyRef("zeroecho-lib:test.prv"),
                    DetailCode.INVALID_ALGORITHM);
            assertFailure(provider, payload, "SHA256withRSA", new KeyRef("zeroecho-lib:missing.prv"),
                    DetailCode.KEY_NOT_FOUND);
            assertFailure(provider, payload, "SHA256withECDSA", new KeyRef("zeroecho-lib:test.prv"),
                    DetailCode.ALGORITHM_MISMATCH);
        }
    }

    @Test
    void requestCancellationProducesOnlyFiniteCancelledObservation(@TempDir Path root) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Path keyring = createKeyring(root, pair);
        byte[] payload = new byte[] { 19, 20 };
        try (SigningProvider provider = provider(keyring)) {
            provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            SignRequest request = request(provider, new PkiId("operation-cancelled"), payload,
                    repeatable(payload, new AtomicInteger()), NAMESPACE, provider.configurationCommitment(),
                    new KeyRef("zeroecho-lib:test.prv"), "SHA256withRSA", Encoding.BINARY,
                    ContentCommitment.sha256(payload), () -> true);
            OperationObservation observation = provider.dispatch(request, control());
            assertEquals(ObservationState.CANCELLED, observation.state());
            assertEquals(DetailCode.CANCELLED, observation.detailCode());
            assertTrue(observation.signature().isEmpty());
        }
    }

    private static Path createKeyring(Path root, KeyPair pair) throws Exception {
        Path keyring = root.resolve("keyring.bin");
        try (KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("test.prv", "RSA", pair.getPrivate());
            store.putPublic("test.pub", "RSA", pair.getPublic());
        }
        return keyring;
    }

    private static SigningProvider provider(Path keyring) {
        ProviderConfig config = new ProviderConfig("zeroecho-lib", Map.of(
                "keyringPath", keyring.toString(), "operationHorizon", "P90D",
                "keyRefPrefix", "zeroecho-lib:", "requireComponentSuffix", "true"));
        return new ZeroEchoLibSigningProviderFactory().allocate(config,
                SigningProviderRuntimeDependencies.withKeyringUnlockProvider(TestKeyringUnlocks.provider()));
    }

    private static SignRequest request(SigningProvider provider, PkiId id, byte[] payload,
            RepeatableContent content) {
        return request(provider, id, payload, content, NAMESPACE, provider.configurationCommitment());
    }

    private static SignRequest request(SigningProvider provider, PkiId id, byte[] payload,
            RepeatableContent content, String namespace, SigningProvider.ConfigurationCommitment commitment) {
        return request(provider, id, payload, content, namespace, commitment,
                new KeyRef("zeroecho-lib:test.prv"));
    }

    private static SignRequest request(SigningProvider provider, PkiId id, byte[] payload,
            RepeatableContent content, String namespace, SigningProvider.ConfigurationCommitment commitment,
            KeyRef keyRef) {
        return request(provider, id, payload, content, namespace, commitment, keyRef,
                "SHA256withRSA", Encoding.BINARY, ContentCommitment.sha256(payload), CancellationSignal.NONE);
    }

    private static SignRequest request(SigningProvider provider, PkiId id, byte[] payload,
            RepeatableContent content, String namespace, SigningProvider.ConfigurationCommitment commitment,
            KeyRef keyRef, String algorithm, Encoding encoding, ContentCommitment contentCommitment,
            CancellationSignal cancellation) {
        Optional<Instant> deadline = Optional.empty();
        String fingerprint = SignRequest.fingerprint(commitment, namespace, ACCESS, keyRef,
                algorithm, contentCommitment, Optional.of(encoding), deadline);
        return new SignRequest(id, namespace, fingerprint, commitment, 1L, ACCESS, keyRef,
                algorithm, contentCommitment, content, Optional.of(encoding), deadline, cancellation);
    }

    private static void assertFailure(SigningProvider provider, byte[] payload, String algorithm,
            KeyRef keyRef, DetailCode expected) {
        SignRequest request = request(provider, new PkiId("operation-failure-" + expected), payload,
                repeatable(payload, new AtomicInteger()), NAMESPACE, provider.configurationCommitment(),
                keyRef, algorithm, Encoding.BINARY, ContentCommitment.sha256(payload), CancellationSignal.NONE);
        OperationObservation observation = provider.dispatch(request, control());
        assertEquals(ObservationState.FAILED, observation.state());
        assertEquals(expected, observation.detailCode());
        assertTrue(observation.signature().isEmpty());
    }

    private static byte[] rawSignature(byte[] encoded, Encoding encoding) {
        if (encoding != Encoding.PEM) {
            return encoded;
        }
        String pem = new String(encoded, java.nio.charset.StandardCharsets.US_ASCII);
        String base64 = pem.replace("-----BEGIN ZEROECHO SIGNATURE-----", "")
                .replace("-----END ZEROECHO SIGNATURE-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private static RepeatableContent repeatable(byte[] payload, AtomicInteger opens) {
        return new RepeatableContent() {
            @Override public InputStream openStream() {
                opens.incrementAndGet();
                return new ByteArrayInputStream(payload);
            }
            @Override public java.util.OptionalLong length() {
                return java.util.OptionalLong.of(payload.length);
            }
            @Override public String contentId() {
                return "test-content";
            }
            @Override public void close() {
                // Caller owns this fixture.
            }
        };
    }

    private static CallControl control() {
        return new CallControl(Instant.MAX, CancellationSignal.NONE);
    }
}
