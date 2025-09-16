/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core;

import java.security.Key;
import java.util.Objects;
import java.util.function.Supplier;

import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.ContextConstructorKS;

/**
 * Immutable descriptor of an algorithm capability.
 *
 * <p>
 * A {@code Capability} describes one role supported by a
 * {@link CryptoAlgorithm}, including:
 * </p>
 * <ul>
 * <li>the algorithm identifier,</li>
 * <li>its high-level {@link AlgorithmFamily},</li>
 * <li>the {@link KeyUsage} role (e.g., ENCRYPT, VERIFY),</li>
 * <li>the expected {@link CryptoContext} type,</li>
 * <li>the accepted {@link Key} type,</li>
 * <li>the accepted {@link ContextSpec} type, and</li>
 * <li>a supplier for a default spec.</li>
 * </ul>
 *
 * <h2>Purpose</h2> Capabilities allow discovery, inspection, and documentation
 * of what an algorithm can do. Higher layers (e.g., protocol builders,
 * registries, tooling) can enumerate capabilities via
 * {@link CryptoAlgorithm#listCapabilities()} and adapt automatically.
 *
 * <p>
 * Each capability corresponds to a call to
 * {@link AbstractCryptoAlgorithm#capability(AlgorithmFamily, KeyUsage, Class, Class, Class, ContextConstructorKS, Supplier)}.
 * </p>
 *
 * <h2>Thread-safety</h2> {@code Capability} instances are immutable and safe to
 * share across threads.
 *
 * @since 1.0
 */
public record Capability(String algorithmId, AlgorithmFamily family, KeyUsage role,
        Class<? extends CryptoContext> contextType, Class<? extends Key> keyType, Class<? extends ContextSpec> specType,
        Supplier<? extends ContextSpec> defaultSpec) {

    /**
     * Creates a new capability descriptor.
     *
     * @param algorithmId identifier of the algorithm this capability belongs to
     * @param family      high-level algorithm family classification
     * @param role        supported {@link KeyUsage} role
     * @param contextType expected {@link CryptoContext} type for this role
     * @param keyType     accepted {@link Key} type for this role
     * @param specType    accepted {@link ContextSpec} type for this role
     * @param defaultSpec supplier of a default spec (used when {@code null} is
     *                    passed)
     * @throws NullPointerException if any argument is {@code null}
     */
    public Capability(String algorithmId, AlgorithmFamily family, KeyUsage role,
            Class<? extends CryptoContext> contextType, Class<? extends Key> keyType,
            Class<? extends ContextSpec> specType, Supplier<? extends ContextSpec> defaultSpec) {
        this.algorithmId = Objects.requireNonNull(algorithmId, "algorithmId must not be null");
        this.family = Objects.requireNonNull(family, "family must not be null");
        this.role = Objects.requireNonNull(role, "role must not be null");
        this.contextType = Objects.requireNonNull(contextType, "contextType must not be null");
        this.keyType = Objects.requireNonNull(keyType, "keyType must not be null");
        this.specType = Objects.requireNonNull(specType, "specType must not be null");
        this.defaultSpec = Objects.requireNonNull(defaultSpec, "defaultSpec must not be null");
    }
}
