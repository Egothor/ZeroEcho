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
package zeroecho.pki.impl.framework.x509;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmIdentityCodec;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Trusted installed-code contribution of additive X.509 binding rules.
 *
 * <p>
 * This interface is not an administrative configuration surface. Catalog
 * composition rejects every collision with built-in or previously installed
 * semantics.
 * </p>
 */
public interface X509BindingRuleProvider {

    /**
     * Returns trusted parameter codecs required by contributed identities.
     *
     * @return immutable codec contribution
     */
    default Collection<AlgorithmIdentityCodec> codecs() {
        return List.of();
    }

    /**
     * Returns exact identities introduced by this installed extension.
     *
     * @return immutable identity contribution
     */
    default Collection<AlgorithmIdentity> identities() {
        return List.of();
    }

    /**
     * Returns component bindings used by parameterized rules.
     *
     * @return immutable component contribution
     */
    default List<X509ComponentCatalog.Component> components() {
        return List.of();
    }

    /**
     * Returns immutable additive binding rules.
     *
     * @return trusted rules; never {@code null}
     */
    default List<X509BindingRule> rules() {
        return List.of();
    }

    /**
     * Returns finite compatibility aliases. Aliases are never canonical identity
     * data.
     *
     * @return immutable alias contribution
     */
    default Map<String, AlgorithmIdentity> aliases() {
        return Map.of();
    }

    /**
     * Returns additive explicitly versioned defaults.
     *
     * @return immutable default contribution
     */
    default Map<String, AlgorithmSuite> defaults() {
        return Map.of();
    }
}
