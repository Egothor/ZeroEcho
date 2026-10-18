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
import zeroecho.pki.impl.framework.x509.X509BindingRuleProvider;

/** Configured test-only certificate representation absent from every built-in catalog. */
public final class AcceptancePrivateBinding implements X509BindingRuleProvider, X509BindingRule {
    public static final X509AlgorithmBinding DESCRIPTOR = new X509AlgorithmBinding(
            "test.acceptance.rsa.certificate.v1", BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
            X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE, "1.3.6.1.4.1.55555.77.1",
            X509AlgorithmBinding.Origin.DEPLOYER_PRIVATE, 1, X509AlgorithmBinding.ParameterRule.ABSENT,
            X509AlgorithmBinding.PublicKeyEncoding.NOT_APPLICABLE, X509AlgorithmBinding.SignatureEncoding.OPAQUE,
            X509AlgorithmBinding.Interoperability.DEPLOYER_ECOSYSTEM, Optional.of("test.acceptance"), "acceptance-rsa-v1");

    @Override public List<X509BindingRule> rules() { return List.of(this); }
    @Override public List<X509AlgorithmBinding> bindings() { return List.of(DESCRIPTOR); }
    @Override public String id() { return DESCRIPTOR.bindingId(); }
    @Override public X509AlgorithmRole role() { return X509AlgorithmRole.SIGNATURE_ALGORITHM; }
    @Override public String oid() { return DESCRIPTOR.oid(); }
    @Override public String semanticFingerprint() { return DESCRIPTOR.semanticCommitment(); }
    @Override public SignatureEncoding signatureEncoding() { return SignatureEncoding.OPAQUE; }
    @Override public PublicKeyEncoding publicKeyEncoding() { return PublicKeyEncoding.NOT_APPLICABLE; }
    @Override public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
        return identity.equals(DESCRIPTOR.algorithmIdentity()) ? Optional.of(X509AlgorithmIdentifier.absent(oid())) : Optional.empty();
    }
    @Override public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
        if (!oid().equals(identifier.oid())) { return Optional.empty(); }
        if (identifier.parameterForm() != X509AlgorithmIdentifier.ParameterForm.ABSENT) {
            throw new IllegalArgumentException("Acceptance private signature parameters must be absent");
        }
        return Optional.of(DESCRIPTOR.algorithmIdentity());
    }
}
