/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Generates symmetric keys for one exact specification type. Implementations
 * must be stateless or otherwise safe for concurrent invocation.
 *
 * @param <S> specification type
 * @since 1.0
 */
@FunctionalInterface
public interface SymmetricKeyGenerator<S extends AlgorithmKeySpec> {
    /**
     * Generates a symmetric key.
     *
     * @param spec generation parameters
     * @return generated key
     * @throws GeneralSecurityException if generation fails
     */
    SecretKey generateSecret(S spec) throws GeneralSecurityException;
}
