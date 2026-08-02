/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.spi.store;

import java.io.IOException;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.core.io.CancellationSignal;

/**
 * Closeable one-pass history of one credential in credential-local revision order.
 *
 * <p>The cursor reads authenticated authoritative frames incrementally. Its
 * auxiliary heap is independent of the number of transitions. Opening is
 * constant time. The first advance validates the captured prefix, and complete
 * consumption costs at most two linear passes over the global log prefix.</p>
 */
public interface RevocationHistory extends AutoCloseable {

    /** @return exact credential identity selected for this history */
    PkiId credentialId();

    /**
     * Advances to the next transition.
     *
     * @param cancellation cancellation signal checked during scanning
     * @return {@code true} when {@link #current()} is available
     * @throws IOException if the authoritative history is unreadable or invalid
     */
    boolean next(CancellationSignal cancellation) throws IOException;

    /**
     * Advances without external cancellation.
     *
     * @return {@code true} when a transition is available
     * @throws IOException if the authoritative history is unreadable or invalid
     */
    default boolean next() throws IOException {
        return next(CancellationSignal.NONE);
    }

    /**
     * Returns the current transition.
     *
     * @return current transition
     * @throws IllegalStateException if the cursor is not positioned
     */
    RevocationTransition current();

    /**
     * Closes the underlying authoritative-log channel. Repeated close is harmless.
     *
     * @throws IOException if channel closure fails
     */
    @Override
    void close() throws IOException;
}
