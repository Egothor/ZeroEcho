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
package zeroecho.pki.testkit;

import java.util.List;
import java.util.Optional;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509BindingRule;
import zeroecho.pki.spi.algorithm.X509AlgorithmBindingProvider;

/** Deterministic deployer binding provider used only by service-loading tests. */
public final class TestX509AlgorithmBindingProvider implements X509AlgorithmBindingProvider {
    /** Stable provider identity. */
    public static final String ID = "test.deployer.bindings";
    /** Deployer-owned PEN test root. */
    public static final String PEN_ROOT = "1.3.6.1.4.1.55555.42";
    /** Egothor deployment-local test root. */
    public static final String EGOTHOR_ROOT = "1.3.6.1.4.1.31424.1.2.4242";

    private static final X509AlgorithmBinding CERTIFICATE = binding("test.ed25519.certificate.v1",
            X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE, PEN_ROOT + ".1");
    private static final X509AlgorithmBinding CRL = binding("test.ed25519.crl.v1",
            X509AlgorithmBinding.Role.CRL_SIGNATURE, EGOTHOR_ROOT + ".1");

    @Override
    public String providerId() {
        return ID;
    }

    @Override
    public String bindingSetVersion() {
        return "test-bindings-v1";
    }

    @Override
    public List<X509AlgorithmBinding> bindings() {
        return List.of(CERTIFICATE, CRL);
    }

    @Override
    public List<X509BindingRule> rules() {
        return List.of(new Rule(CERTIFICATE), new Rule(CRL));
    }

    private static X509AlgorithmBinding binding(String id, X509AlgorithmBinding.Role role, String oid) {
        return new X509AlgorithmBinding(id, BootstrapAlgorithmIdentities.ED25519_SIGNATURE, role, oid,
                X509AlgorithmBinding.Origin.DEPLOYER_PRIVATE, 1, X509AlgorithmBinding.ParameterRule.ABSENT,
                X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE,
                X509AlgorithmBinding.SignatureEncoding.OPAQUE,
                X509AlgorithmBinding.Interoperability.DEPLOYER_ECOSYSTEM, Optional.of(ID), id + "|v1");
    }

    private record Rule(X509AlgorithmBinding binding) implements X509BindingRule {
        @Override
        public String id() {
            return binding.bindingId();
        }

        @Override
        public X509AlgorithmRole role() {
            return X509AlgorithmRole.SIGNATURE_ALGORITHM;
        }

        @Override
        public String oid() {
            return binding.oid();
        }

        @Override
        public String semanticFingerprint() {
            return binding.semanticCommitment();
        }

        @Override
        public SignatureEncoding signatureEncoding() {
            return SignatureEncoding.OPAQUE;
        }

        @Override
        public PublicKeyEncoding publicKeyEncoding() {
            return PublicKeyEncoding.NOT_APPLICABLE;
        }

        @Override
        public List<X509AlgorithmBinding> bindings() {
            return List.of(binding);
        }

        @Override
        public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return binding.algorithmIdentity().equals(identity)
                    ? Optional.of(X509AlgorithmIdentifier.absent(binding.oid())) : Optional.empty();
        }

        @Override
        public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            if (!binding.oid().equals(identifier.oid())) {
                return Optional.empty();
            }
            if (identifier.parameterForm() != X509AlgorithmIdentifier.ParameterForm.ABSENT) {
                throw new IllegalArgumentException("Test binding parameters must be absent");
            }
            return Optional.of(binding.algorithmIdentity());
        }
    }
}
