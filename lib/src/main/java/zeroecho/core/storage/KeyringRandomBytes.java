/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

/**
 * Fills keyring randomness buffers.
 *
 * <p>This package-private seam supports deterministic format tests; production
 * creation uses the authoritative shared secure random source.</p>
 */
@FunctionalInterface
interface KeyringRandomBytes {
    /**
     * Fills a destination buffer.
     *
     * @param destination buffer to fill completely
     */
    void nextBytes(byte[] destination);
}
