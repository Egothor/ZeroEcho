/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
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
