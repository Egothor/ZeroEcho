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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import zeroecho.core.context.KemContext;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

class ParameterRegistryContractTest {
    @BeforeAll
    static void provider() {
        BouncyCastleActivator.init();
    }

    @TestFactory
    Stream<DynamicTest> everyAdvertisedConcreteSpecExecutes() {
        List<DynamicTest> tests = new ArrayList<>();
        for (String id : CryptoAlgorithms.available()) {
            CryptoAlgorithm algorithm = CryptoAlgorithms.require(id);
            List<ParameterSetDescriptor<? extends AlgorithmKeySpec>> descriptors = algorithm.parameterSets();
            tests.add(DynamicTest.dynamicTest(id + ":metadata", () -> {
                assertSame(algorithm, CryptoAlgorithms.require(id));
                assertSame(descriptors, algorithm.parameterSets());
                assertEquals(id, algorithm.id());
                assertEquals(descriptors.stream().map(ParameterSetDescriptor::id).toList(),
                        algorithm.parameterSets().stream().map(ParameterSetDescriptor::id).toList());
                assertEquals(descriptors.size(), descriptors.stream().map(ParameterSetDescriptor::id).distinct().count());
                assertThrows(UnsupportedOperationException.class, () -> descriptors.add(null));
                for (ParameterSetDescriptor<?> descriptor : descriptors) {
                    assertFalse(descriptor.id().isBlank());
                    assertFalse(descriptor.displayName().isBlank());
                }
            }));
            for (ParameterSetDescriptor<?> descriptor : descriptors) {
                if (descriptor instanceof ParameterSetDescriptor.Concrete<?> concrete) {
                    tests.add(DynamicTest.dynamicTest(id + ":" + descriptor.id(), () -> execute(algorithm, concrete.spec())));
                }
            }
        }
        assertFalse(tests.isEmpty());
        return tests.stream();
    }

    private static void execute(CryptoAlgorithm algorithm, AlgorithmKeySpec spec) throws Exception {
        String id = algorithm.id();
        KeyOperationInfo operation = algorithm.keyOperations().stream()
                .filter(info -> info.specType() == spec.getClass()
                        && (info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE
                        || info.operation() == KeyOperation.SYMMETRIC_GENERATE))
                .findFirst().orElseThrow(() -> new AssertionError("Unregistered advertised spec: " + id));
        ZeroEchoSession session = new ZeroEchoSession();
        if (operation.operation() == KeyOperation.SYMMETRIC_GENERATE) {
            assertNotNull(session.keyBuilders().symmetric().generate(id, spec).getEncoded());
        } else {
            KeyPair pair = session.keyBuilders().asymmetric().generateKeyPair(id, spec);
            assertNotNull(pair.getPublic().getEncoded());
            assertNotNull(pair.getPrivate().getEncoded());
            if (algorithm.roles().contains(KeyUsage.ENCAPSULATE)) {
                try (KemContext encapsulator = session.createContext(id, KeyUsage.ENCAPSULATE, pair.getPublic());
                        KemContext decapsulator = session.createContext(id, KeyUsage.DECAPSULATE, pair.getPrivate())) {
                    assertSame(algorithm, encapsulator.algorithm());
                    KemContext.KemResult result = encapsulator.encapsulate();
                    assertTrue(result.ciphertext().length > 0);
                    assertArrayEquals(result.sharedSecret(), decapsulator.decapsulate(result.ciphertext()));
                }
            }
        }
        assertEquals(id, algorithm.id());
        assertSame(algorithm, CryptoAlgorithms.require(id));
    }
}
