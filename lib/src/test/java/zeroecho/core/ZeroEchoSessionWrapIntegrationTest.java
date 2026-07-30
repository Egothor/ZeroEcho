/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import conflux.Ctx;
import conflux.CtxInterface;
import zeroecho.core.alg.aes.AesSpec;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.hmac.HmacSpec;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.xdh.XdhSpec;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.MacContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.ContextAware;
import zeroecho.core.tag.TagEngine;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

class ZeroEchoSessionWrapIntegrationTest {
    private static final AtomicInteger CONTEXT_IDS = new AtomicInteger();

    @BeforeAll
    static void initializeProvider() {
        BouncyCastleActivator.init();
    }

    @Test
    void registeredStreamContexts() throws Exception {
        System.out.println("registeredStreamContexts");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = wrappedSession(listener);
        byte[] message = { 1, 2, 3, 4, 5 };

        SecretKey aesKey = new SecretKeySpec(new byte[16], "AES");
        CtxInterface aesContext = Ctx.INSTANCE.getContext("wrap-integration-" + CONTEXT_IDS.incrementAndGet());
        byte[] ciphertext;
        try (EncryptionContext encryption = session.createContext("AES", KeyUsage.ENCRYPT, aesKey,
                AesSpec.gcm128(null))) {
            assertProxy(encryption);
            ((ContextAware) encryption).setContext(aesContext);
            try (InputStream input = encryption.attach(new ByteArrayInputStream(message))) {
                ciphertext = input.readAllBytes();
            }
        }
        try (EncryptionContext decryption = session.createContext("AES", KeyUsage.DECRYPT, aesKey,
                AesSpec.gcm128(null))) {
            assertProxy(decryption);
            ((ContextAware) decryption).setContext(aesContext);
            try (InputStream input = decryption.attach(new ByteArrayInputStream(ciphertext))) {
                assertArrayEquals(message, input.readAllBytes());
            }
        }

        KeyPair signingKeys = session.keyBuilders().asymmetric().generateKeyPair("Ed25519",
                Ed25519KeyGenSpec.defaultSpec());
        TaggedBody signature;
        try (SignatureContext signer = session.createContext("Ed25519", KeyUsage.SIGN, signingKeys.getPrivate())) {
            assertProxy(signer);
            signature = produceTag(signer, message);
        }
        try (SignatureContext verifier = session.createContext("Ed25519", KeyUsage.VERIFY, signingKeys.getPublic())) {
            assertProxy(verifier);
            verifier.setExpectedTag(signature.tag());
            try (InputStream input = verifier.wrap(new ByteArrayInputStream(message))) {
                assertArrayEquals(message, input.readAllBytes());
            }
        }

        SecretKey hmacKey = new SecretKeySpec(new byte[32], "HmacSHA256");
        try (MacContext mac = session.createContext("HMAC", KeyUsage.MAC, hmacKey, HmacSpec.sha256())) {
            assertProxy(mac);
            assertArrayEquals(message, produceTag(mac, message).body());
        }
        try (DigestContext digest = session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE)) {
            assertProxy(digest);
            assertArrayEquals(message, produceTag(digest, message).body());
        }

        assertEquals(List.of("create:ENCRYPT", "create:DECRYPT", "create:SIGN", "tag", "create:VERIFY", "verify:true",
                "create:MAC", "tag", "create:DIGEST", "tag"), listener.events);
        System.out.println("...contexts=6...events=" + listener.events.size());
        System.out.println("registeredStreamContexts...ok");
    }

    @Test
    void registeredAgreementContexts() throws Exception {
        System.out.println("registeredAgreementContexts");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = wrappedSession(listener);
        KeyPair aliceKeys = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);
        KeyPair bobKeys = session.keyBuilders().asymmetric().generateKeyPair("Xdh", XdhSpec.X25519);

        try (AgreementContext alice = session.createContext("Xdh", KeyUsage.AGREEMENT, aliceKeys.getPrivate(),
                XdhSpec.X25519);
                AgreementContext bob = session.createContext("Xdh", KeyUsage.AGREEMENT, bobKeys.getPrivate(),
                        XdhSpec.X25519)) {
            assertProxy(alice);
            assertProxy(bob);
            alice.setPeerPublic(bobKeys.getPublic());
            bob.setPeerPublic(aliceKeys.getPublic());
            assertArrayEquals(alice.deriveSecret(), bob.deriveSecret());
        }

        try (MessageAgreementContext alice = session.createContext("Xdh", KeyUsage.AGREEMENT, new KeyPairKey(aliceKeys),
                XdhSpec.X25519);
                MessageAgreementContext bob = session.createContext("Xdh", KeyUsage.AGREEMENT, new KeyPairKey(bobKeys),
                        XdhSpec.X25519)) {
            assertProxy(alice);
            assertProxy(bob);
            byte[] aliceMessage = alice.getPeerMessage();
            byte[] bobMessage = bob.getPeerMessage();
            alice.setPeerMessage(bobMessage);
            bob.setPeerMessage(aliceMessage);
            assertArrayEquals(alice.deriveSecret(), bob.deriveSecret());
        }

        assertEquals(List.of("create:AGREEMENT", "create:AGREEMENT", "peer", "peer", "derived", "derived",
                "create:AGREEMENT", "create:AGREEMENT", "message-get", "message-get", "message-set", "message-set",
                "derived", "derived"), listener.events);
        System.out.println("...contexts=4...events=" + listener.events.size());
        System.out.println("registeredAgreementContexts...ok");
    }

    @Test
    void registeredKemContexts() throws Exception {
        System.out.println("registeredKemContexts");
        RecordingListener listener = new RecordingListener();
        ZeroEchoSession session = wrappedSession(listener);
        KeyPair recipient = session.keyBuilders().asymmetric().generateKeyPair("ML-KEM", KyberKeyGenSpec.kyber512());

        KemContext.KemResult encapsulated;
        try (KemContext encapsulator = session.createContext("ML-KEM", KeyUsage.ENCAPSULATE, recipient.getPublic(),
                VoidSpec.INSTANCE);
                KemContext decapsulator = session.createContext("ML-KEM", KeyUsage.DECAPSULATE, recipient.getPrivate(),
                        VoidSpec.INSTANCE)) {
            assertProxy(encapsulator);
            assertProxy(decapsulator);
            encapsulated = encapsulator.encapsulate();
            assertArrayEquals(encapsulated.sharedSecret(), decapsulator.decapsulate(encapsulated.ciphertext()));
        }

        try (MessageAgreementContext initiator = session.createContext("ML-KEM", KeyUsage.AGREEMENT,
                recipient.getPublic(), VoidSpec.INSTANCE);
                MessageAgreementContext responder = session.createContext("ML-KEM", KeyUsage.AGREEMENT,
                        recipient.getPrivate(), VoidSpec.INSTANCE)) {
            assertProxy(initiator);
            assertProxy(responder);
            responder.setPeerMessage(initiator.getPeerMessage());
            assertArrayEquals(initiator.deriveSecret(), responder.deriveSecret());
        }

        assertEquals(List.of("create:ENCAPSULATE", "create:DECAPSULATE", "encapsulated", "decapsulated",
                "create:AGREEMENT", "create:AGREEMENT", "message-get", "message-set", "derived", "derived"),
                listener.events);
        System.out.println("...contexts=4...events=" + listener.events.size());
        System.out.println("registeredKemContexts...ok");
    }

    private static ZeroEchoSession wrappedSession(RecordingListener listener) {
        return new ZeroEchoSession().withAuditListener(listener).withAuditMode(AuditMode.WRAP);
    }

    private static TaggedBody produceTag(TagEngine<?> engine, byte[] body) throws IOException {
        byte[][] tag = new byte[1][];
        int tagLength = engine.tagLength();
        byte[] emittedBody;
        try (InputStream input = new TailStrippingInputStream(engine.wrap(new ByteArrayInputStream(body)), tagLength,
                128) {
            @Override
            protected void processTail(byte[] tail) {
                tag[0] = tail.clone();
            }
        }) {
            emittedBody = input.readAllBytes();
        }
        return new TaggedBody(emittedBody, tag[0]);
    }

    private static void assertProxy(CryptoContext context) {
        assertTrue(Proxy.isProxyClass(context.getClass()));
    }

    private record TaggedBody(byte[] body, byte[] tag) {
    }

    private static final class RecordingListener implements AuditListener {
        private final List<String> events = new ArrayList<>();

        @Override
        public void onContextCreatedMeta(String contextId, String algorithmId, String provider, KeyUsage role,
                String keyFingerprint, Map<String, Object> specMeta) {
            events.add("create:" + role);
        }

        @Override
        public void onTagProduced(String contextId, int tagLength, String policy) {
            events.add("tag");
        }

        @Override
        public void onVerifyResult(String contextId, boolean success, String policy, String expectedSource,
                int tagLength) {
            events.add("verify:" + success);
        }

        @Override
        public void onAgreementPeerSet(String contextId, String peerFingerprint) {
            events.add("peer");
        }

        @Override
        public void onAgreementDerived(String contextId, int secretLength) {
            events.add("derived");
        }

        @Override
        public void onAgreementPeerMessageSet(String contextId, int messageLength) {
            events.add("message-set");
        }

        @Override
        public void onAgreementPeerMessageGet(String contextId, int messageLength) {
            events.add("message-get");
        }

        @Override
        public void onKemEncapsulated(int ciphertextLength, int sharedSecretLength) {
            events.add("encapsulated");
        }

        @Override
        public void onKemDecapsulated(int sharedSecretLength) {
            events.add("decapsulated");
        }
    }
}
