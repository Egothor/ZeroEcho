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

import java.security.Key;
import java.util.Objects;

import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Immutable value descriptor of one algorithm context capability.
 *
 * <p>
 * The default specification is resolved once during provider construction. All
 * components therefore have stable value semantics and are safe for concurrent
 * reads.
 * </p>
 *
 * @param algorithmId canonical algorithm identifier
 * @param family      algorithm family
 * @param role        supported key usage
 * @param contextType produced context type
 * @param keyType     accepted key type
 * @param specType    accepted specification type
 * @param defaultSpec non-null resolved default specification
 * @since 1.0
 */
public record Capability(String algorithmId, AlgorithmFamily family, KeyUsage role,
        Class<? extends CryptoContext> contextType, Class<? extends Key> keyType, Class<? extends ContextSpec> specType,
        ContextSpec defaultSpec) {

    /**
     * Validates the capability metadata.
     *
     * @throws NullPointerException     if a component is {@code null}
     * @throws IllegalArgumentException if {@code defaultSpec} is incompatible with
     *                                  {@code specType}
     */
    public Capability {
        Objects.requireNonNull(algorithmId, "algorithmId must not be null");
        Objects.requireNonNull(family, "family must not be null");
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(contextType, "contextType must not be null");
        Objects.requireNonNull(keyType, "keyType must not be null");
        Objects.requireNonNull(specType, "specType must not be null");
        Objects.requireNonNull(defaultSpec, "defaultSpec must not be null");
        if (!specType.isInstance(defaultSpec)) {
            throw new IllegalArgumentException("defaultSpec must be an instance of " + specType.getName());
        }
    }
}
