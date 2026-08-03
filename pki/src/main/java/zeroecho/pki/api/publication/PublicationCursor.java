/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.api.publication;

import java.io.IOException;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;

/**
 * Closeable snapshot-consistent cursor over publication records.
 *
 * <p>Records are returned in canonical publication-identity order. Cursor heap
 * does not grow with the number of returned records.</p>
 */
public interface PublicationCursor extends AutoCloseable {
    /**
     * Advances by at most one matching record.
     *
     * @param cancellation cooperative cancellation signal
     * @return next record, or empty at end of input
     * @throws IOException if the stable metadata view cannot be read
     */
    Optional<PublicationRecord> next(CancellationSignal cancellation) throws IOException;

    /** Closes the underlying stable metadata view idempotently. */
    @Override
    void close();
}
