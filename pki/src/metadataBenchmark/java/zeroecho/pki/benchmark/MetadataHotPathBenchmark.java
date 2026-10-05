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
package zeroecho.pki.benchmark;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;

/** Isolated metadata measurements; no key generation or cryptographic operation is timed. */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Fork(2)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class MetadataHotPathBenchmark {

    /** One pre-resolved identity at a representative catalog position or parameterized rule. */
    @State(Scope.Thread)
    public static class ResolutionState {
        @Param({"RSA_SHA256", "ED448", "ML_DSA_44", "SLH_DSA_SHAKE_256F", "RSA_PSS_SALT48", "EC_P384"})
        public String scenario;

        private X509BindingCatalog catalog;
        private AlgorithmIdentity identity;
        private X509AlgorithmRole role;
        private String bindingId;

        /** Resolves workload inputs outside measured operations and checks both lookup forms. */
        @Setup(Level.Trial)
        public void setup() {
            catalog = StandardX509Bindings.catalog();
            role = X509AlgorithmRole.SIGNATURE_ALGORITHM;
            switch (scenario) {
                case "RSA_SHA256" -> identity = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256;
                case "ED448" -> identity = BootstrapAlgorithmIdentities.ED448_SIGNATURE;
                case "ML_DSA_44" -> identity = BootstrapAlgorithmIdentities.ML_DSA_44_SIGNATURE;
                case "SLH_DSA_SHAKE_256F" -> identity = BootstrapAlgorithmIdentities.SLH_DSA_SHAKE_256F_SIGNATURE;
                case "RSA_PSS_SALT48" -> identity = BootstrapAlgorithmIdentities.rsaPss(
                        BootstrapAlgorithmIdentities.SHA256, BootstrapAlgorithmIdentities.SHA256, 48);
                case "EC_P384" -> {
                    identity = BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY;
                    role = X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM;
                }
                default -> throw new IllegalArgumentException("Unknown benchmark scenario");
            }
            X509AlgorithmIdentifier expected = catalog.resolve(identity, role);
            bindingId = catalog.bindingId(expected, role);
            if (!expected.equals(catalog.resolve(bindingId, identity, role))) {
                throw new IllegalStateException("Explicit and implicit lookup disagree");
            }
            System.out.println("Metadata workload: rules=" + catalog.rules().size()
                    + ", standardDescriptors=" + StandardX509Bindings.descriptors().size());
        }
    }

    /** Captures algorithm providers once; each measured walk obtains their current descriptor lists. */
    @State(Scope.Thread)
    public static class CatalogState {
        private List<CryptoAlgorithm> algorithms;

        /** Loads providers and reports actual workload size outside the timed region. */
        @Setup(Level.Trial)
        public void setup() {
            List<CryptoAlgorithm> loaded = new ArrayList<>();
            int descriptors = 0;
            for (String id : CryptoAlgorithms.available()) {
                CryptoAlgorithm algorithm = CryptoAlgorithms.require(id);
                loaded.add(algorithm);
                descriptors += algorithm.parameterSets().size();
            }
            algorithms = List.copyOf(loaded);
            System.out.println("Metadata workload: algorithms=" + algorithms.size()
                    + ", parameterDescriptors=" + descriptors
                    + ", standardDescriptors=" + StandardX509Bindings.descriptors().size());
        }
    }

    /** Measures implicit role-and-identity lookup. */
    @Benchmark
    public X509AlgorithmIdentifier implicitResolution(ResolutionState state) {
        return state.catalog.resolve(state.identity, state.role);
    }

    /** Measures explicit binding identifier lookup. */
    @Benchmark
    public X509AlgorithmIdentifier explicitResolution(ResolutionState state) {
        return state.catalog.resolve(state.bindingId, state.identity, state.role);
    }

    /** Measures complete standard descriptor retrieval and consumption. */
    @Benchmark
    public void standardBindingWalk(CatalogState state, Blackhole blackhole) {
        for (X509AlgorithmBinding binding : StandardX509Bindings.descriptors()) {
            blackhole.consume(binding);
        }
    }

    /** Measures complete built-in parameter metadata retrieval and consumption. */
    @Benchmark
    public void cryptoParameterWalk(CatalogState state, Blackhole blackhole) {
        for (CryptoAlgorithm algorithm : state.algorithms) {
            for (ParameterSetDescriptor<? extends AlgorithmKeySpec> descriptor : algorithm.parameterSets()) {
                blackhole.consume(descriptor);
            }
        }
    }
}
