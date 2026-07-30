/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.spi;

import java.io.IOException;

import zeroecho.core.storage.KeyringPassword;

/**
 * Supplies a fresh destroyable password for one keyring open operation.
 *
 * <p>
 * Ownership of the returned object transfers to the receiver, which must
 * destroy it in a {@code finally} block immediately after the keyring has been
 * opened. Implementations must not source passwords from immutable strings,
 * process arguments, system properties, environment fallbacks, persistent
 * files, or global mutable state.
 * </p>
 */
@FunctionalInterface
public interface KeyringUnlockProvider {
    /**
     * Supplies unlock material for one operation.
     *
     * @return a fresh password owner whose ownership transfers to the receiver
     * @throws IOException if unlock material cannot be supplied
     */
    KeyringPassword acquire() throws IOException;
}
