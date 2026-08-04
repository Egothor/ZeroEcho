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
package zeroecho.pki.api.algorithm;

import java.util.List;
import java.util.Optional;

import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Immutable active X.509 algorithm-binding registry shared by one PKI session.
 *
 * <p>Implementations provide deterministic constant-time identifier lookup and
 * linear-time ordered listing. Returned collections are immutable snapshots.</p>
 */
public interface X509AlgorithmBindingRegistry {

    /** @return deterministic immutable binding order */
    List<X509AlgorithmBinding> bindings();

    /**
     * Resolves a stable binding identifier.
     *
     * @param bindingId stable identifier
     * @return exact descriptor, or empty when inactive
     */
    Optional<X509AlgorithmBinding> find(String bindingId);

    /**
     * Resolves the standard default for one identity and role.
     *
     * @param identity exact cryptographic identity
     * @param role X.509 role
     * @return official binding, or empty when no official binding exists
     */
    Optional<X509AlgorithmBinding> standard(AlgorithmIdentity identity, X509AlgorithmBinding.Role role);

    /** @return deterministic SHA-256 commitment to the complete active set */
    String commitment();

    /**
     * Requires that one explicit binding remains active with an exact commitment.
     *
     * @param bindingId stable binding identifier
     * @param expectedCommitment persisted binding-contract commitment
     * @return validated binding
     * @throws IllegalArgumentException if the binding is absent or changed
     */
    X509AlgorithmBinding require(String bindingId, String expectedCommitment);
}
