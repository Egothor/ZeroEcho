/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Imports private keys for one exact specification type. Implementations must
 * be stateless or otherwise safe for concurrent invocation.
 *
 * @param <S> specification type
 * @since 1.0
 */
@FunctionalInterface
public interface PrivateKeyImporter<S extends AlgorithmKeySpec> {
    /**
     * Imports a private key.
     *
     * @param spec encoded key material and parameters
     * @return imported private key
     * @throws GeneralSecurityException if validation or import fails
     */
    PrivateKey importPrivate(S spec) throws GeneralSecurityException;
}
