/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Imports symmetric keys for one exact specification type. Implementations must
 * be stateless or otherwise safe for concurrent invocation.
 *
 * @param <S> specification type
 * @since 1.0
 */
@FunctionalInterface
public interface SymmetricKeyImporter<S extends AlgorithmKeySpec> {
    /**
     * Imports a symmetric key.
     *
     * @param spec encoded key material and parameters
     * @return imported key
     * @throws GeneralSecurityException if validation or import fails
     */
    SecretKey importSecret(S spec) throws GeneralSecurityException;
}
