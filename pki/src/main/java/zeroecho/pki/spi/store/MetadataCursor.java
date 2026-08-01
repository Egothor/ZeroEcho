/*
 * Copyright (c) 2025 ZeroEcho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package zeroecho.pki.spi.store;

import java.io.IOException;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;

/**
 * A closeable, snapshot-consistent streaming metadata cursor.
 *
 * <p>Records are returned in deterministic {@link MetadataKey} order without
 * requiring complete namespace materialization. A cursor is bound to its
 * issuing snapshot and cannot be used after close.
 */
public interface MetadataCursor extends AutoCloseable {

    /**
     * Advances the cursor by at most one record.
     *
     * @param cancellation cooperative cancellation signal
     * @return the next record, or empty when exhausted
     * @throws IOException when record traversal fails
     * @throws MetadataStoreException when the cursor is closed or foreign
     */
    Optional<MetadataSnapshot.Record> next(CancellationSignal cancellation) throws IOException;

    /**
     * Closes this cursor idempotently.
     */
    @Override
    void close();
}
