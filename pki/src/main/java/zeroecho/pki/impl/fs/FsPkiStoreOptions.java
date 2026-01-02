/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Options for {@link FilesystemPkiStore}.
 *
 * <p>
 * This options container configures the filesystem store behavior while keeping
 * the {@code PkiStore} SPI stable. All options have deterministic semantics and
 * should be suitable for tests and for reference deployments.
 * </p>
 *
 * <h2>History tracking</h2>
 * <p>
 * Some records are mutable and are therefore stored as {@code current.bin} with
 * optional historical snapshots under {@code history/}. The individual history
 * policies allow tuning the retention behavior without changing the store
 * contract.
 * </p>
 *
 * @param caHistoryPolicy         history policy for CA records
 * @param profileHistoryPolicy    history policy for certificate profiles
 * @param revocationHistoryPolicy history policy for revocation records
 * @param workflowHistoryPolicy   history policy for workflow continuation state
 * @param strictSnapshotExport    whether snapshot export is strict
 *                                (fail-closed)
 */
public record FsPkiStoreOptions(FsHistoryPolicy caHistoryPolicy, FsHistoryPolicy profileHistoryPolicy,
        FsHistoryPolicy revocationHistoryPolicy, FsHistoryPolicy workflowHistoryPolicy, boolean strictSnapshotExport) {

    /**
     * Canonical constructor with validation.
     *
     * @throws NullPointerException if any history policy is {@code null}
     */
    public FsPkiStoreOptions {
        Objects.requireNonNull(caHistoryPolicy, "caHistoryPolicy");
        Objects.requireNonNull(profileHistoryPolicy, "profileHistoryPolicy");
        Objects.requireNonNull(revocationHistoryPolicy, "revocationHistoryPolicy");
        Objects.requireNonNull(workflowHistoryPolicy, "workflowHistoryPolicy");
    }

    /**
     * Returns default options (history enabled with 90 days retention).
     *
     * <p>
     * The default is suitable for a reference deployment and for integration tests,
     * but production systems may tune retention windows and cleanup strategies
     * based on operational requirements.
     * </p>
     *
     * @return default options
     */
    public static FsPkiStoreOptions defaults() {
        FsHistoryPolicy ninetyDays = FsHistoryPolicy.onWrite(Optional.of(Duration.ofDays(90)));
        return new FsPkiStoreOptions(ninetyDays, ninetyDays, ninetyDays, ninetyDays, true);
    }
}
