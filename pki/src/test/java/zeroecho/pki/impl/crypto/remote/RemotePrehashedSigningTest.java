/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

package zeroecho.pki.impl.crypto.remote;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteCapabilities;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSignRequest;
import zeroecho.pki.testkit.ReferenceRemoteSigner;

final class RemotePrehashedSigningTest {
    private static final String NAMESPACE = "store.zeroecho-remote";
    private static final AccessContext ACCESS = new AccessContext(new Principal("USER", "tester"),
            new Purpose("TEST"), Optional.empty(), Optional.empty());

    @Test
    void prehashedSignaturesVerifyAgainstOriginalMessageIncludingExactPssAndEcTruncation() throws Exception {
        AlgorithmIdentity pss = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA256,
                BootstrapAlgorithmIdentities.SHA384, 20);
        for (AlgorithmIdentity algorithm : List.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, BootstrapAlgorithmIdentities.ECDSA_SHA512, pss)) {
            KeyPair key = key(algorithm);
            RecordingTransport transport = transport(key, algorithm, 32, true);
            try (RemoteSigningProvider provider = provider(transport)) {
                byte[] message = new byte[16_385];
                for (int index = 0; index < message.length; index++) { message[index] = (byte) index; }
                SigningProvider.OperationObservation signed = provider.dispatch(request(provider, algorithm, message),
                        control());
                assertEquals(SigningProvider.ObservationState.SUCCEEDED, signed.state());
                RemoteSignRequest wire = transport.last;
                assertEquals(SigningInputCapabilities.Mode.PREHASHED_DIGEST, wire.inputMode());
                assertEquals(message.length, wire.contentLength());
                assertEquals(SigningInputCapabilities.digestLength(SigningInputCapabilities.requiredDigest(algorithm)),
                        wire.content().length);
                Signature verifier = Signature.getInstance(jcaName(algorithm));
                if (algorithm.equals(pss)) {
                    verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA384, 20, 1));
                }
                verifier.initVerify(key.getPublic());
                verifier.update(message);
                assertTrue(verifier.verify(signed.signature().orElseThrow().bytes()));
                assertEquals(1, transport.submits.get());
            }
        }
    }

    @Test
    void pureEdUsesOriginalMessageAndRawMaximumIsInclusive() throws Exception {
        AlgorithmIdentity algorithm = BootstrapAlgorithmIdentities.ED25519_SIGNATURE;
        KeyPair key = key(algorithm);
        RecordingTransport transport = transport(key, algorithm, 32, false);
        try (RemoteSigningProvider provider = provider(transport)) {
            for (int length : new int[] { 31, 32 }) {
                byte[] message = new byte[length];
                SigningProvider.SignRequest request = request(provider, algorithm, message);
                SigningProvider.OperationObservation signed = provider.dispatch(request, control());
                assertEquals(SigningProvider.ObservationState.SUCCEEDED, signed.state());
                assertEquals(SigningInputCapabilities.Mode.RAW_MESSAGE, transport.last.inputMode());
                assertArrayEquals(message, transport.last.content());
                Signature verifier = Signature.getInstance("Ed25519");
                verifier.initVerify(key.getPublic());
                verifier.update(message);
                assertTrue(verifier.verify(signed.signature().orElseThrow().bytes()));
            }
            assertThrows(IllegalArgumentException.class,
                    () -> provider.dispatch(request(provider, algorithm, new byte[33]), control()));
            assertEquals(2, transport.submits.get());
        }
    }

    @Test
    void conflictingReplayCannotTrustClientFingerprintOrOriginalDigestAssertion() throws Exception {
        AlgorithmIdentity algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
        RecordingTransport transport = transport(key(algorithm), algorithm, 32, true);
        try (RemoteSigningProvider provider = provider(transport)) {
            byte[] message = new byte[64];
            provider.dispatch(request(provider, algorithm, message), control());
            RemoteSignRequest original = transport.last;
            RemoteSigningTransport.RemoteCallControl control = remoteControl();
            assertEquals(RemoteSigningTransport.RemoteSigningState.SIGNED,
                    transport.delegate.submit(original, control).state());
            byte[] altered = original.content();
            altered[0] ^= 1;
            RemoteSignRequest payload = copy(original, original.inputMode(), original.digestId(), altered,
                    original.configurationCommitment());
            assertNotEquals(original.wireFingerprint(), payload.wireFingerprint());
            assertThrows(IllegalStateException.class, () -> transport.delegate.submit(payload, control));
            RemoteSignRequest digest = copy(original, original.inputMode(),
                    BootstrapAlgorithmIdentities.SHA384.canonicalForm(), original.content(),
                    original.configurationCommitment());
            assertThrows(IllegalArgumentException.class, () -> transport.delegate.submit(digest, control));
            RemoteSignRequest mode = copy(original, SigningInputCapabilities.Mode.RAW_MESSAGE, "", message,
                    original.configurationCommitment());
            assertThrows(IllegalArgumentException.class, () -> transport.delegate.submit(mode, control));
            RemoteSignRequest configuration = copy(original, original.inputMode(), original.digestId(),
                    original.content(), new SigningProvider.ConfigurationCommitment(new byte[32]));
            assertThrows(IllegalArgumentException.class, () -> transport.delegate.submit(configuration, control));
        }
    }

    @Test
    void lostResponseReconcilesWithoutResubmitting() throws Exception {
        AlgorithmIdentity algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
        RecordingTransport transport = transport(key(algorithm), algorithm, 32, true);
        transport.loseResponse = true;
        try (RemoteSigningProvider provider = provider(transport)) {
            SigningProvider.SignRequest request = request(provider, algorithm, new byte[64]);
            assertEquals(SigningProvider.ObservationState.RETRYABLE_UNKNOWN,
                    provider.dispatch(request, control()).state());
            assertEquals(SigningProvider.ObservationState.SUCCEEDED,
                    provider.reconcile(request.operationId(), control()).state());
            assertEquals(1, transport.submits.get());
        }
    }

    @Test
    void integrityCancellationDeadlineAndConfigurationFailuresNeverSubmit() throws Exception {
        AlgorithmIdentity algorithm = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
        RecordingTransport transport = transport(key(algorithm), algorithm, 32, true);
        try (RemoteSigningProvider provider = provider(transport)) {
            byte[] message = new byte[64];
            SigningProvider.SignRequest canonical = request(provider, algorithm, message);
            SigningProvider.SignRequest truncated = withContent(canonical, new ImmutableByteContent(new byte[63]),
                    CancellationSignal.NONE, Optional.empty(), canonical.configurationCommitment());
            assertThrows(IllegalArgumentException.class, () -> provider.dispatch(truncated, control()));
            byte[] altered = message.clone();
            altered[0] = 1;
            SigningProvider.SignRequest corrupt = withContent(canonical, new ImmutableByteContent(altered),
                    CancellationSignal.NONE, Optional.empty(), canonical.configurationCommitment());
            assertThrows(IllegalArgumentException.class, () -> provider.dispatch(corrupt, control()));
            AtomicBoolean cancelled = new AtomicBoolean();
            RepeatableContent cancelDuringRead = new RepeatableContent() {
                @Override public String contentId() { return "cancel-during-read"; }
                @Override public OptionalLong length() { return OptionalLong.of(message.length); }
                @Override public void close() { }
                @Override public InputStream openStream() {
                    return new ByteArrayInputStream(message) {
                        @Override public synchronized int read(byte[] bytes, int offset, int length) {
                            cancelled.set(true);
                            return super.read(bytes, offset, length);
                        }
                    };
                }
            };
            SigningProvider.SignRequest cancellation = withContent(canonical, cancelDuringRead,
                    cancelled::get, Optional.empty(), canonical.configurationCommitment());
            assertThrows(IllegalStateException.class, () -> provider.dispatch(cancellation, control()));
            SigningProvider.SignRequest expired = withContent(canonical, canonical.content(), CancellationSignal.NONE,
                    Optional.of(Instant.EPOCH), canonical.configurationCommitment());
            assertThrows(IllegalStateException.class, () -> provider.dispatch(expired, control()));
            assertThrows(IllegalStateException.class, () -> provider.dispatch(canonical,
                    new SigningProvider.CallControl(Instant.EPOCH, CancellationSignal.NONE)));
            SigningProvider.SignRequest drift = withContent(canonical, canonical.content(), CancellationSignal.NONE,
                    Optional.empty(), new SigningProvider.ConfigurationCommitment(new byte[32]));
            assertThrows(IllegalArgumentException.class, () -> provider.dispatch(drift, control()));
            assertEquals(0, transport.submits.get());
        }
    }

    @Test
    void effectiveRawLimitCannotExceedClientCeiling() {
        RemoteCapabilities capabilities = new RemoteCapabilities(Set.of(), new byte[32], 2,
                new SigningInputCapabilities(Long.MAX_VALUE, Map.of()));
        assertEquals(SigningInputCapabilities.REMOTE_RAW_LIMIT, capabilities.effectiveInputs().rawMessageMaximum());
        assertThrows(IllegalArgumentException.class, () -> new RemoteCapabilities(Set.of(), new byte[32], 1,
                new SigningInputCapabilities(32, Map.of())));
    }

    private static RemoteSignRequest copy(RemoteSignRequest request, SigningInputCapabilities.Mode mode,
            String digest, byte[] content, SigningProvider.ConfigurationCommitment commitment) {
        return new RemoteSignRequest(request.submissionId(), request.namespace(), request.semanticFingerprint(),
                request.fencingToken(), request.keyHandle(), request.algorithmId(), request.contentSha256(),
                request.contentLength(), content, request.principalType(), request.principalName(), request.purpose(),
                request.deadline(), request.protocolVersion(), mode, digest, commitment);
    }

    private static SigningProvider.SignRequest withContent(SigningProvider.SignRequest request,
            RepeatableContent content, CancellationSignal cancellation, Optional<Instant> deadline,
            SigningProvider.ConfigurationCommitment configuration) {
        String fingerprint = SigningProvider.SignRequest.fingerprint(configuration, request.namespace(), ACCESS,
                request.keyRef(), request.algorithmId(), request.contentCommitment(),
                request.preferredSignatureEncoding(), deadline);
        return new SigningProvider.SignRequest(request.operationId(), request.namespace(), fingerprint, configuration,
                1, ACCESS, request.keyRef(), request.algorithmId(), request.contentCommitment(), content,
                request.preferredSignatureEncoding(), deadline, cancellation);
    }

    private static SigningProvider.SignRequest request(RemoteSigningProvider provider, AlgorithmIdentity algorithm,
            byte[] message) {
        return SigningProvider.SignRequest.create(new PkiId("request-" + message.length), NAMESPACE,
                provider.configurationCommitment(), 1, ACCESS, new KeyRef("zeroecho-remote:key"),
                algorithm.canonicalForm(), ContentCommitment.sha256(message), new ImmutableByteContent(message),
                Optional.of(Encoding.BINARY), Optional.empty());
    }

    private static RecordingTransport transport(KeyPair key, AlgorithmIdentity algorithm, long limit, boolean prehash) {
        Map<String, AlgorithmIdentity> mappings = prehash
                ? Map.of(algorithm.canonicalForm(), SigningInputCapabilities.requiredDigest(algorithm)) : Map.of();
        RemoteCapabilities capabilities = new RemoteCapabilities(Set.of(algorithm.canonicalForm()), new byte[32], 2,
                new SigningInputCapabilities(limit, mappings));
        return new RecordingTransport(new ReferenceRemoteSigner(Map.of("key", key), false, capabilities));
    }

    private static RemoteSigningProvider provider(RecordingTransport transport) {
        RemoteSigningProvider provider = new RemoteSigningProvider("zeroecho-remote", transport, "zeroecho-remote:",
                Duration.ofDays(90));
        provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
        return provider;
    }

    private static SigningProvider.CallControl control() {
        return new SigningProvider.CallControl(Instant.now().plusSeconds(30), CancellationSignal.NONE);
    }

    private static RemoteSigningTransport.RemoteCallControl remoteControl() {
        return new RemoteSigningTransport.RemoteCallControl(Instant.now().plusSeconds(30), CancellationSignal.NONE);
    }

    private static String jcaName(AlgorithmIdentity algorithm) {
        if (algorithm.parameters() instanceof AlgorithmIdentity.RsaPssParameters) { return "RSASSA-PSS"; }
        if (algorithm.equals(BootstrapAlgorithmIdentities.ECDSA_SHA512)) { return "SHA512withECDSA"; }
        return algorithm.equals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384) ? "SHA384withRSA" : "SHA256withRSA";
    }

    private static KeyPair key(AlgorithmIdentity algorithm) throws Exception {
        if (algorithm.family().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256.family())) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            return generator.generateKeyPair();
        }
        if (algorithm.equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)) {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static final class RecordingTransport implements RemoteSigningTransport {
        private final ReferenceRemoteSigner delegate;
        private final AtomicInteger submits = new AtomicInteger();
        private RemoteSignRequest last;
        private boolean loseResponse;
        private RecordingTransport(ReferenceRemoteSigner delegate) { this.delegate = delegate; }
        @Override public RemoteCapabilities capabilities() { return delegate.capabilities(); }
        @Override public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
            submits.incrementAndGet();
            last = request;
            RemoteSigningStatus status = delegate.submit(request, control);
            if (loseResponse) { throw new RemoteSigningException("Lost response"); }
            return status;
        }
        @Override public RemoteSigningStatus status(String id, RemoteCallControl control) {
            return delegate.status(id, control);
        }
        @Override public RemoteSigningStatus cancel(String id, long fence, String reason, RemoteCallControl control) {
            return delegate.cancel(id, fence, reason, control);
        }
        @Override public byte[] publicKeyInfo(String key, RemoteCallControl control) {
            return delegate.publicKeyInfo(key, control);
        }
        @Override public void close() { delegate.close(); }
    }
}
