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

import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Describes a named, discoverable parameter set (or parameterized template)
 * for a {@link CryptoAlgorithm}.
 *
 * <p>
 * This interface enables runtime discovery of all key-generation configurations
 * an algorithm supports. Callers (e.g., UIs, provisioning tools, policy
 * engines) can enumerate parameter sets without prior knowledge of the concrete
 * algorithm.
 * </p>
 *
 * <p>
 * Two variants exist:
 * </p>
 * <ul>
 * <li>{@link Concrete} — a fully pre-built, named configuration. The spec
 * instance is already constructed and ready to pass to a key generator.</li>
 * <li>{@link Template} — a family of related parameter sets driven by
 * user-supplied arguments. The caller provides a map of named values and the
 * template factory produces the concrete spec.</li>
 * </ul>
 *
 * <h2>Guaranteed uniqueness</h2>
 * Within a single {@code CryptoAlgorithm}, every {@code ParameterSetDescriptor}
 * must have a unique {@link #id()} value. Algorithms are responsible for
 * enforcing this invariant.
 *
 * @param <S> the {@link AlgorithmKeySpec} type produced by this descriptor
 * @since 1.0
 */
public sealed interface ParameterSetDescriptor<S extends AlgorithmKeySpec>
        permits ParameterSetDescriptor.Concrete, ParameterSetDescriptor.Template {

    /**
     * Machine-readable identifier, unique within the algorithm
     * (e.g., {@code "ML-KEM-768"}, {@code "RSA-3072"}, {@code "rsa-custom"}).
     *
     * @return non-null, non-empty identifier
     */
    String id();

    /**
     * Human-readable label for UIs and documentation
     * (e.g., {@code "ML-KEM-768 (NIST Level 3)"}).
     *
     * @return non-null display name
     */
    String displayName();

    /**
     * Security level of this parameter set or template's default.
     *
     * @return non-null security level
     */
    SecurityLevel securityLevel();

    /**
     * A fully pre-built, named parameter set carrying a ready-to-use spec.
     *
     * <p>
     * Use this variant when the parameter space is finite and enumerable
     * (e.g., {@code ML-KEM-512/768/1024}, {@code AES-128/192/256}).
     * </p>
     *
     * @param <S> the {@link AlgorithmKeySpec} type
     * @param id nonblank machine identifier
     * @param displayName nonblank display label
     * @param securityLevel security estimate
     * @param spec ready-to-use specification
     */
    record Concrete<S extends AlgorithmKeySpec>(
            String id,
            String displayName,
            SecurityLevel securityLevel,
            S spec) implements ParameterSetDescriptor<S> {

        /**
         * Validates a concrete descriptor.
         * @throws NullPointerException if any field is {@code null}
         * @throws IllegalArgumentException if the identifier or label is blank
         */
        public Concrete {
            Objects.requireNonNull(id, "id must not be null");
            Objects.requireNonNull(displayName, "displayName must not be null");
            if (id.isBlank() || displayName.isBlank()) {
                throw new IllegalArgumentException("Descriptor ID and label must not be blank");
            }
            Objects.requireNonNull(securityLevel, "securityLevel must not be null");
            Objects.requireNonNull(spec, "spec must not be null");
        }
    }

    /**
     * A parameterized family of parameter sets driven by user-supplied arguments.
     *
     * <p>
     * Use this variant when the parameter space is too large to enumerate (e.g.,
     * RSA with an arbitrary key size, HMAC with an arbitrary MAC name and key
     * length). The caller supplies a {@code Map<String, Object>} keyed by
     * {@link TemplateParameter#name()} values and the {@link #factory()} produces
     * the concrete spec.
     * </p>
     *
     * @param <S> the {@link AlgorithmKeySpec} type produced by the factory
     * @param id nonblank machine identifier
     * @param displayName nonblank display label
     * @param securityLevel security estimate
     * @param parameters ordered presentation metadata
     * @param factory factory wrapped with centralized validation
     */
    record Template<S extends AlgorithmKeySpec>(
            String id,
            String displayName,
            SecurityLevel securityLevel,
            List<TemplateParameter> parameters,
            Function<Map<String, Object>, S> factory) implements ParameterSetDescriptor<S> {

        /**
         * Snapshots metadata and validates argument names and types before factory
         * invocation. Without an explicit schema, omitted arguments remain the
         * delegate's responsibility; descriptions are never parsed for constraints.
         * @throws NullPointerException if any field is {@code null}
         * @throws IllegalArgumentException if identifiers are blank or names repeat
         */
        public Template {
            Objects.requireNonNull(id, "id must not be null");
            Objects.requireNonNull(displayName, "displayName must not be null");
            if (id.isBlank() || displayName.isBlank()) {
                throw new IllegalArgumentException("Descriptor ID and label must not be blank");
            }
            Objects.requireNonNull(securityLevel, "securityLevel must not be null");
            Objects.requireNonNull(parameters, "parameters must not be null");
            Objects.requireNonNull(factory, "factory must not be null");
            parameters = List.copyOf(parameters);
            List<ParameterConstraint> constraints = factory instanceof TemplateFactory<?> validated
                    ? validated.constraints() : TemplateFactory.legacy(parameters);
            factory = new TemplateFactory<>(parameters, constraints, factory);
        }

        /**
         * Creates a template with a complete, ordered validation schema.
         * The factory rejects unknown, missing, null, wrongly typed and out-of-range
         * arguments with {@link IllegalArgumentException} before invoking the delegate.
         * The original five-argument constructor preserves legacy omission behavior;
         * it cannot infer defaults or required flags from descriptions.
         * @param id machine identifier
         * @param displayName nonblank label
         * @param securityLevel security estimate
         * @param parameters ordered presentation metadata
         * @param constraints ordered constraints matching the parameters
         * @param factory specification factory, receiving an immutable validated map
         * @throws IllegalArgumentException if the schema is inconsistent
         * @throws NullPointerException if a required constructor argument is null
         */
        public Template(String id, String displayName, SecurityLevel securityLevel,
                List<TemplateParameter> parameters, List<ParameterConstraint> constraints,
                Function<Map<String, Object>, S> factory) {
            this(id, displayName, securityLevel, parameters,
                    new TemplateFactory<>(parameters, constraints, factory));
        }

        /**
         * Returns immutable ordered constraints. Legacy metadata uses LEGACY kind
         * and optional parameters; omission remains the original factory's concern.
         * @return the validation schema
         */
        public List<ParameterConstraint> constraints() {
            return ((TemplateFactory<?>) factory).constraints();
        }
    }

    /**
     * Snapshots a provider's descriptors, rejecting duplicate identifiers.
     * @param descriptors ordered descriptors
     * @return immutable ordered snapshot
     * @throws IllegalArgumentException if identifiers repeat
     * @throws NullPointerException if the list or a descriptor is null
     */
    static List<ParameterSetDescriptor<? extends AlgorithmKeySpec>> snapshot(
            List<ParameterSetDescriptor<? extends AlgorithmKeySpec>> descriptors) {
        List<ParameterSetDescriptor<? extends AlgorithmKeySpec>> result = List.copyOf(descriptors);
        Set<String> ids = new HashSet<>();
        for (ParameterSetDescriptor<?> descriptor : result) {
            if (!ids.add(descriptor.id())) {
                throw new IllegalArgumentException("Duplicate parameter-set ID: " + descriptor.id());
            }
        }
        return result;
    }
}
