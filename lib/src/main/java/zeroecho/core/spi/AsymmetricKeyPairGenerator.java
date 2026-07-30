/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Generates asymmetric key pairs for one exact specification type.
 * Implementations must be stateless or otherwise safe for concurrent
 * invocation.
 *
 * @param <S> specification type
 * @since 1.0
 */
@FunctionalInterface
public interface AsymmetricKeyPairGenerator<S extends AlgorithmKeySpec> {
    /**
     * Generates a key pair.
     *
     * @param spec generation parameters
     * @return generated key pair
     * @throws GeneralSecurityException if generation fails
     */
    KeyPair generateKeyPair(S spec) throws GeneralSecurityException;
}
