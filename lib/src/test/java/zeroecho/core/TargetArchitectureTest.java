/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.common.agreement.GenericJcaAgreementContext;
import zeroecho.core.audit.AuditListener;
import zeroecho.core.audit.AuditMode;
import zeroecho.core.context.DigestContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Guards the consolidated pre-release architecture against legacy API drift.
 */
class TargetArchitectureTest {

    @Test
    void exactRegisteredKeyOperationMatrix() {
        String name = start("exactRegisteredKeyOperationMatrix");
        Map<KeyOperation, Integer> counts = new EnumMap<>(KeyOperation.class);
        Set<String> registrations = new HashSet<>();

        for (String algorithmId : CryptoAlgorithms.available()) {
            CryptoAlgorithm algorithm = CryptoAlgorithms.require(algorithmId);
            for (KeyOperationInfo info : algorithm.keyOperations()) {
                String registration = algorithmId + "|" + info.operation() + "|" + info.specType().getName();
                assertTrue(registrations.add(registration), registration);
                assertLookupSucceeds(algorithm, info);
                counts.merge(info.operation(), 1, Integer::sum);
            }
        }

        assertEquals(20, counts.getOrDefault(KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE, 0));
        assertEquals(20, counts.getOrDefault(KeyOperation.ASYMMETRIC_PUBLIC_IMPORT, 0));
        assertEquals(20, counts.getOrDefault(KeyOperation.ASYMMETRIC_PRIVATE_IMPORT, 0));
        assertEquals(4, counts.getOrDefault(KeyOperation.SYMMETRIC_GENERATE, 0));
        assertEquals(4, counts.getOrDefault(KeyOperation.SYMMETRIC_IMPORT, 0));
        progress("registrations=" + registrations.size());
        ok(name);
    }

    @Test
    void obsoleteArchitectureTypesAreAbsent() {
        String name = start("obsoleteArchitectureTypesAreAbsent");
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("zeroecho.core.spi.ContextConstructorKS"));
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("zeroecho.core.spi.SymmetricKeyBuilder"));
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("zeroecho.core.spi.AsymmetricKeyBuilder"));

        for (Method method : CryptoAlgorithms.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers())) {
                assertTrue(method.getName().equals("available") || method.getName().equals("require"),
                        method.toString());
            }
        }
        for (Field field : CryptoAlgorithms.class.getDeclaredFields()) {
            assertTrue(Modifier.isFinal(field.getModifiers()), field.toString());
        }
        Set<String> removedConveniences = Set.of("generateSecret", "importSecret", "generateKeyPair",
                "importPublic", "importPrivate");
        for (Method method : CryptoAlgorithm.class.getDeclaredMethods()) {
            assertFalse(removedConveniences.contains(method.getName()), method.toString());
        }
        progress("registryStatics=readOnly");
        ok(name);
    }

    @Test
    void agreementImplementationIsFinal() {
        String name = start("agreementImplementationIsFinal");
        assertTrue(Modifier.isFinal(GenericJcaAgreementContext.class.getModifiers()));
        progress("final=true");
        ok(name);
    }

    @Test
    void auditListenerFailureCannotChangeOperationOutcome() throws Exception {
        String name = start("auditListenerFailureCannotChangeOperationOutcome");
        AuditListener failing = new AuditListener() {
            @Override
            public void onContextCreatedMeta(String contextId, String algorithmId, String provider,
                    KeyUsage role, String keyFingerprint, Map<String, Object> metadata) {
                throw new AssertionError("controlled listener failure");
            }

            @Override
            public void onContextClosed(String contextId, long bodyBytes, long trailerBytes,
                    long durationMillis) {
                throw new AssertionError("controlled listener failure");
            }
        };

        for (AuditMode mode : new AuditMode[] { AuditMode.OFF, AuditMode.WRAP }) {
            ZeroEchoSession session = new ZeroEchoSession().withAuditListener(failing).withAuditMode(mode);
            try (DigestContext context = assertDoesNotThrow(
                    () -> session.createContext("DIGEST", KeyUsage.DIGEST, NullKey.INSTANCE))) {
                assertFalse(context.algorithm().id().isBlank());
            }
        }
        progress("modes=OFF,WRAP");
        ok(name);
    }

    @SuppressWarnings("unchecked")
    private static void assertLookupSucceeds(CryptoAlgorithm algorithm, KeyOperationInfo info) {
        Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) info.specType();
        switch (info.operation()) {
            case ASYMMETRIC_KEY_PAIR_GENERATE ->
                assertDoesNotThrow(() -> algorithm.asymmetricKeyPairGenerator(specType));
            case ASYMMETRIC_PUBLIC_IMPORT ->
                assertDoesNotThrow(() -> algorithm.publicKeyImporter(specType));
            case ASYMMETRIC_PRIVATE_IMPORT ->
                assertDoesNotThrow(() -> algorithm.privateKeyImporter(specType));
            case SYMMETRIC_GENERATE ->
                assertDoesNotThrow(() -> algorithm.symmetricKeyGenerator(specType));
            case SYMMETRIC_IMPORT ->
                assertDoesNotThrow(() -> algorithm.symmetricKeyImporter(specType));
        }
    }

    private static String start(String routine) {
        String label = routine.length() <= 30 ? routine : routine.substring(0, 27) + "...";
        System.out.println(label);
        return label;
    }

    private static void progress(String detail) {
        System.out.println("..." + detail);
    }

    private static void ok(String name) {
        System.out.println(name + "...ok");
    }
}
