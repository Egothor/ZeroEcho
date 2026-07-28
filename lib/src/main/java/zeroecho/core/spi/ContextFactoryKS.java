/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core.spi;

import java.security.Key;

import zeroecho.core.context.CryptoContext;
import zeroecho.core.spec.ContextSpec;

/**
 * Creates a cryptographic context from a key and a context specification.
 *
 * <p>Implementations report provider and parameter failures with unchecked
 * exceptions; context construction is a pure in-memory operation and does not
 * expose an I/O failure contract. Factories must be stateless or otherwise safe
 * for concurrent invocation; returned contexts retain their own documented
 * thread-safety contracts.</p>
 *
 * @param <C> context type produced
 * @param <K> key type accepted
 * @param <S> specification type accepted
 * @since 1.0
 */
@FunctionalInterface
public interface ContextFactoryKS<C extends CryptoContext, K extends Key, S extends ContextSpec> {
    /**
     * Creates a context bound to the supplied key and specification.
     *
     * @param key non-null key
     * @param spec non-null resolved context specification
     * @return a newly created context
     */
    C createContext(K key, S spec);
}
