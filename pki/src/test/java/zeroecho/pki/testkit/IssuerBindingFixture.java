/*
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

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.impl.core.IssuerBindingResolver;
import zeroecho.pki.impl.framework.x509.*;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Explicit public authority for low-level store fixtures; callers must name the known outgoing signer.
 */
public final class IssuerBindingFixture {
    /**
     * Exact closed standard registry used by these explicit fixture generations.
     */
    public static final String BINDING_SET_COMMITMENT = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors()).commitment();
    private IssuerBindingFixture() { }
    /**
     * Publishes a generation with public evidence from its actual fixture certificate.
     * This deliberately does not infer intermediate outgoing algorithms from incoming signatures.
     * @param store fixture store
     * @param generation exact immutable generation
     * @param signature explicit algorithm selected by the fixture's signing provider
     */
    public static void put(PkiStore store, IssuerGeneration generation, AlgorithmIdentity signature) {
        try {
            var credential = store.getCredential(generation.credentialId()).orElseThrow();
            if (!(credential.profileBinding() instanceof CaProfileBinding profile)) {
                throw new IllegalArgumentException("Generation fixture requires a CA profile binding");
            }
            byte[] der = PkiTestRuntime.readContent(store, credential.content());
            var certificate = zeroecho.pkix.Pkix.parseCertificate(der);
            var publicKey = new EncodedObject(Encoding.DER, zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate));
            var verifier = new BcX509VerificationExecutor();
            var authority = X509AuthoritySnapshot.compose(List.of(), List.of(verifier),
                    List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID, Direction.VERIFY, verifier)),
                    (suite, direction) -> direction == Direction.VERIFY);
            var registry = ImmutableX509AlgorithmBindingRegistry.create(StandardX509Bindings.descriptors());
            if (!generation.x509BindingCommitment().equals(BINDING_SET_COMMITMENT)) {
                throw new IllegalArgumentException("Fixture generation must explicitly name its actual binding registry");
            }
            var binding = IssuerBindingResolver.create(generation, der, credential.formatId().value(), signature, Optional.empty(),
                    reference -> { if (!generation.signingKeyRef().equals(reference)) { throw new IllegalArgumentException("Unexpected fixture key"); } return publicKey; },
                    authority, IssuerCryptographicBinding.HybridSignatureBaseline.NONE, profile.reference(), registry.commitment());
            store.putIssuerGeneration(generation, binding);
        } catch (IOException failure) { throw new IllegalStateException("Invalid issuer fixture public evidence", failure); }
    }
}
