/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Imports public keys for one exact specification type. Implementations must be
 * stateless or otherwise safe for concurrent invocation.
 *
 * @param <S> specification type
 * @since 1.0
 */
@FunctionalInterface
public interface PublicKeyImporter<S extends AlgorithmKeySpec> {
    /**
     * Imports a public key.
     *
     * @param spec encoded key material and parameters
     * @return imported public key
     * @throws GeneralSecurityException if validation or import fails
     */
    PublicKey importPublic(S spec) throws GeneralSecurityException;
}
