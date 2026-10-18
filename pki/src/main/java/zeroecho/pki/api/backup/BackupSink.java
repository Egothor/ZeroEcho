/* *****************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.api.backup;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import zeroecho.pki.api.PkiId;

/**
 * Bounded file-backed ingestion. An incomplete sink is never a consumable artifact.
 * This interface is single-owner and is not thread-safe.
 */
public interface BackupSink extends AutoCloseable {
    /**
     * Creates owned storage under a caller-controlled directory.
     * @param directory existing private work directory
     * @param backupId identifier to attach to completed storage
     * @param limits archive resource limits
     * @return new incomplete sink
     * @throws IOException if private storage cannot be created
     */
    static BackupSink create(Path directory, PkiId backupId, BackupLimits limits) throws IOException {
        return FileBackupSink.create(directory, backupId, limits);
    }

    /**
     * Returns the same bounded stream on each call. Closing that stream does not
     * publish the artifact; call {@link #complete()} to transfer ownership.
     * @return sink-owned output
     * @throws IOException if the sink is completed, failed or closed
     */
    OutputStream outputStream() throws IOException;

    /**
     * Forces data and atomically publishes an immutable file, then transfers its
     * deletion ownership to the result. Failure leaves this sink responsible for
     * cleanup. There is no non-atomic publication fallback.
     * @return completed file-backed source
     * @throws IOException if writing, forcing or publication fails
     */
    BackupSource complete() throws IOException;

    /**
     * Deletes incomplete storage; after successful completion it does not close
     * or delete the transferred source. Failed cleanup is explicit and retryable.
     * @throws IOException if cleanup fails
     */
    @Override void close() throws IOException;
}
