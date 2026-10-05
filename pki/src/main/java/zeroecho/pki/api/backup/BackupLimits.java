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

/**
 * Resource limits for the version-1 backup envelope. Limits apply to actual
 * consumption as well as declared metadata. ZIP64 is not supported.
 *
 * @param compressedBytes maximum complete archive bytes, below 4 GiB
 * @param expandedBytes maximum total expanded bytes, including the manifest
 * @param entryBytes maximum expanded bytes in one entry
 * @param entryCount maximum entries, including the manifest, below 65535
 * @param pathBytes maximum UTF-8 bytes in an entry path
 * @param manifestBytes maximum expanded manifest bytes
 * @param compressionRatio maximum expanded/compressed ratio per entry
 * @param legacyBytes maximum bytes accepted by the legacy array adapter
 * @param recordBytes maximum decode buffer for one legacy domain record
 */
public record BackupLimits(long compressedBytes, long expandedBytes, long entryBytes,
        int entryCount, int pathBytes, int manifestBytes, int compressionRatio, int legacyBytes, int recordBytes) {
    /** Validates all positive limits and ZIP32 representation bounds. */
    public BackupLimits {
        if (compressedBytes <= 0 || compressedBytes >= 0xffffffffL
                || expandedBytes <= 0 || entryBytes <= 0 || entryBytes >= 0xffffffffL
                || entryBytes > expandedBytes || entryCount <= 0 || entryCount >= 65_535
                || pathBytes <= 0 || pathBytes > 65_535 || manifestBytes <= 0
                || manifestBytes > entryBytes || compressionRatio <= 0
                || legacyBytes <= 0 || legacyBytes > compressedBytes || recordBytes <= 0 || recordBytes > entryBytes) {
            throw new IllegalArgumentException("Invalid backup limits");
        }
    }

    /**
     * Conservative defaults: 1 GiB archive, 4 GiB expanded, 512 MiB per entry,
     * 60000 entries, 1024-byte paths, 16 MiB manifest and record decode buffers,
     * ratio 1000, and 2 MiB legacy.
     *
     * @return immutable default limits
     */
    public static BackupLimits defaults() {
        return new BackupLimits(1L << 30, 4L << 30, 512L << 20,
                60_000, 1024, 16 << 20, 1000, 2 << 20, 16 << 20);
    }
}
