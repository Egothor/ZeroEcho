/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Immutable metadata for one exact key operation.
 *
 * @param operation operation guaranteed by the associated lookup
 * @param specType exact accepted specification type
 * @param defaultSpec resolved generation default, or {@code null} for import
 *                    operations and generators without a default
 * @since 1.0
 */
public record KeyOperationInfo(KeyOperation operation,
        Class<? extends AlgorithmKeySpec> specType, AlgorithmKeySpec defaultSpec) {

    /**
     * Validates the metadata invariant.
     *
     * @throws NullPointerException if {@code operation} or {@code specType} is
     *                              {@code null}
     * @throws IllegalArgumentException if a default is incompatible with
     *                                  {@code specType}, or an import operation
     *                                  declares a default
     */
    public KeyOperationInfo {
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(specType, "specType must not be null");
        if (defaultSpec != null && !specType.isInstance(defaultSpec)) {
            throw new IllegalArgumentException("defaultSpec must be an instance of " + specType.getName());
        }
        if (defaultSpec != null && (operation == KeyOperation.SYMMETRIC_IMPORT
                || operation == KeyOperation.ASYMMETRIC_PUBLIC_IMPORT
                || operation == KeyOperation.ASYMMETRIC_PRIVATE_IMPORT)) {
            throw new IllegalArgumentException("import operations cannot declare a default specification");
        }
    }
}
