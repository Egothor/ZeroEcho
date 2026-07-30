/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.DigestContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Verifies stable value semantics for capability metadata defaults.
 */
class CapabilityValueSemanticsTest {

    @Test
    void semanticallyEqualCapabilitiesHaveEqualHashes() {
        System.out.println("semanticallyEqualCapabilitiesHaveEqualHashes");
        Capability first = capability(() -> new TestSpec("SHA-256"));
        Capability second = capability(() -> new TestSpec("SHA-256"));

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());

        System.out.println("...hash=" + first.hashCode());
        System.out.println("semanticallyEqualCapabilitiesHaveEqualHashes...ok");
    }

    @Test
    void defaultSupplierIsResolvedOnceAndRepeatedAccessIsStable() {
        System.out.println("defaultSupplierIsResolvedOnceAndRepeatedAccessIsStable");
        AtomicInteger evaluations = new AtomicInteger();
        Capability capability = capability(() -> {
            evaluations.incrementAndGet();
            return new TestSpec("SHA-256");
        });

        ContextSpec first = capability.defaultSpec();
        ContextSpec second = capability.defaultSpec();
        assertEquals(1, evaluations.get());
        assertSame(first, second);

        System.out.println("...evaluations=" + evaluations.get());
        System.out.println("defaultSupplierIsResolvedOnceAndRepeatedAccessIsStable...ok");
    }

    @Test
    void semanticallyDifferentCapabilitiesAreNotEqual() {
        System.out.println("semanticallyDifferentCapabilitiesAreNotEqual");
        Capability first = capability(() -> new TestSpec("SHA-256"));
        Capability second = capability(() -> new TestSpec("SHA-512"));

        assertNotEquals(first, second);

        System.out.println("...firstDefault=" + first.defaultSpec());
        System.out.println("...secondDefault=" + second.defaultSpec());
        System.out.println("semanticallyDifferentCapabilitiesAreNotEqual...ok");
    }

    @Test
    void nullAndIncompatibleDefaultsAreRejectedAtConstruction() {
        System.out.println("nullAndIncompatibleDefaultsAreRejectedAtConstruction");
        assertThrows(NullPointerException.class, () -> capability(() -> null));
        assertThrows(IllegalArgumentException.class, () -> new Capability("DIGEST", AlgorithmFamily.DIGEST,
                KeyUsage.DIGEST, DigestContext.class, NullKey.class, TestSpec.class, new OtherSpec()));

        System.out.println("...invalidDefaultsRejected=true");
        System.out.println("nullAndIncompatibleDefaultsAreRejectedAtConstruction...ok");
    }

    @Test
    void metadataMemoizationDoesNotChangeRuntimeSupplierLifecycle() throws IOException {
        System.out.println("metadataMemoizationDoesNotChangeRuntimeSupplierLifecycle");
        AtomicInteger evaluations = new AtomicInteger();
        List<TestSpec> runtimeSpecs = new ArrayList<>();
        TestAlgorithm algorithm = new TestAlgorithm(evaluations, runtimeSpecs);
        Capability capability = algorithm.listCapabilities().get(0);

        ContextSpec metadataFirst = capability.defaultSpec();
        ContextSpec metadataSecond = capability.defaultSpec();
        algorithm.createContext(KeyUsage.DIGEST, NullKey.INSTANCE, null);
        algorithm.createContext(KeyUsage.DIGEST, NullKey.INSTANCE, null);

        assertSame(metadataFirst, metadataSecond);
        assertEquals(3, evaluations.get());
        assertNotEquals(runtimeSpecs.get(0), runtimeSpecs.get(1));
        System.out.println("...evaluations=" + evaluations.get());
        System.out.println("...runtimeDefaults=" + runtimeSpecs.size());
        System.out.println("metadataMemoizationDoesNotChangeRuntimeSupplierLifecycle...ok");
    }

    private static Capability capability(java.util.function.Supplier<? extends ContextSpec> defaultSpec) {
        return new Capability("DIGEST", AlgorithmFamily.DIGEST, KeyUsage.DIGEST, DigestContext.class, NullKey.class,
                TestSpec.class, defaultSpec.get());
    }

    private record TestSpec(String name) implements ContextSpec {
    }

    private static final class OtherSpec implements ContextSpec {
    }

    private static final class TestAlgorithm extends AbstractCryptoAlgorithm {
        private TestAlgorithm(AtomicInteger evaluations, List<TestSpec> runtimeSpecs) {
            super("TEST", "Test", "test");
            capability(AlgorithmFamily.DIGEST, KeyUsage.DIGEST, DigestContext.class, NullKey.class, TestSpec.class,
                    (key, spec) -> {
                        runtimeSpecs.add(spec);
                        return mock(DigestContext.class);
                    }, () -> new TestSpec(Integer.toString(evaluations.incrementAndGet())));
        }
    }
}
