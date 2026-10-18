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
