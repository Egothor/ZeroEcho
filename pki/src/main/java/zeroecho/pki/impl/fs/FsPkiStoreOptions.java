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
 * Configuration for {@link FilesystemPkiStore}.
 *
 * <p>
 * This type is intentionally placed in an implementation package. It is not a
 * public PKI API contract. It exists to keep the {@code PkiStore} SPI stable,
 * while still allowing a professional-grade reference implementation to be
 * configured and tested.
 * </p>
 *
 * <p>
 * All options have deterministic semantics.
 * </p>
 */
public record FsPkiStoreOptions(FsHistoryPolicy caHistoryPolicy, FsHistoryPolicy profileHistoryPolicy,
        FsHistoryPolicy revocationHistoryPolicy, boolean strictSnapshotExport) {

    /**
     * Canonical constructor with validation.
     */
    public FsPkiStoreOptions {
        Objects.requireNonNull(caHistoryPolicy, "caHistoryPolicy");
        Objects.requireNonNull(profileHistoryPolicy, "profileHistoryPolicy");
        Objects.requireNonNull(revocationHistoryPolicy, "revocationHistoryPolicy");
    }

    /**
     * Returns default options (history enabled with 90 days retention).
     *
     * @return default options
     */
    public static FsPkiStoreOptions defaults() {
        FsHistoryPolicy ninetyDays = FsHistoryPolicy.onWrite(Optional.of(Duration.ofDays(90)));
        return new FsPkiStoreOptions(ninetyDays, ninetyDays, ninetyDays, true);
    }
}
