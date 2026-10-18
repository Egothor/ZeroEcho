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

package zeroecho.pki.impl.core;

import java.util.Objects;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pkix.AlgorithmIdentifier;

/** Shared exact representation matching for frozen request and issuance policies. */
final class X509ProfileBindingMatcher {
    private final X509AuthoritySnapshot authority;
    private final X509AlgorithmBindingRegistry bindings;

    /* default */ X509ProfileBindingMatcher(X509AuthoritySnapshot authority, X509AlgorithmBindingRegistry bindings) {
        this.authority = Objects.requireNonNull(authority, "authority");
        this.bindings = Objects.requireNonNull(bindings, "bindings");
    }

    /* default */ AlgorithmIdentifier select(AlgorithmIdentity algorithm, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(algorithm, role).orElseThrow(
                        () -> new IllegalArgumentException("Required standard binding unavailable")));
        if (selected.role() != role || !selected.algorithmIdentity().equals(algorithm)
                || reference.isPresent() && selected.origin() == X509AlgorithmBinding.Origin.STANDARD) {
            throw new IllegalArgumentException("Binding role or algorithm mismatch");
        }
        X509AlgorithmRole x509Role = role == X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY
                ? X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM : X509AlgorithmRole.SIGNATURE_ALGORITHM;
        X509AlgorithmIdentifier encoded = authority.bindings().resolve(selected.bindingId(), algorithm, x509Role);
        return BcX509AlgorithmAdapter.toLib(encoded);
    }

    /* default */ void require(AlgorithmIdentifier actual, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        X509AlgorithmRole x509Role = role == X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY
                ? X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM : X509AlgorithmRole.SIGNATURE_ALGORITHM;
        AlgorithmIdentifier expected = select(new BcX509AlgorithmAdapter(authority.bindings()).decode(actual, x509Role), role, reference);
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException("Request binding differs from profile");
        }
    }
}
