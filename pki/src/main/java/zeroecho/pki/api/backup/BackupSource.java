/*******************************************************************************
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
import java.io.InputStream;
import zeroecho.pki.api.PkiId;

/**
 * Repeatable file-backed backup input with an explicit owner.
 * Metadata is a commitment, not proof of authenticity. Verifiers must count and
 * hash actual input even when an implementation advertises trusted-looking values.
 * Callers close each stream and finally the source. A source must not be consumed
 * concurrently with its close operation.
 */
public interface BackupSource extends AutoCloseable {
    /**
     * Returns the identifier committed by the backup manifest.
     * @return stable backup identifier
     */
    PkiId backupId();
    /**
     * Returns the complete archive length.
     * @return nonnegative byte count
     */
    long contentLength();
    /**
     * Returns the commitment to the complete archive bytes.
     * @return lowercase hexadecimal SHA-256
     */
    String sha256();
    /**
     * Opens an independent stream at offset zero.
     * @return caller-owned input stream
     * @throws IOException if opening fails or the source is closed
     */
    InputStream openStream() throws IOException;
    /**
     * Releases owned input and storage. File-backed sources close their open
     * streams and delete their own file. Successful repeated close is harmless;
     * failed deletion is reported and can be retried.
     * @throws IOException if resource release or deletion fails
     */
    @Override void close() throws IOException;
}
