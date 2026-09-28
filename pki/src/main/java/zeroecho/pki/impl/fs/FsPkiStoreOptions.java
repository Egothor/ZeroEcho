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
package zeroecho.pki.impl.fs;

import java.time.Duration;
import java.math.BigInteger;
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
 * @param signingOperationHorizon maximum stable signing identifier and record
 *                                retention horizon
 * @param signingIdPermittedSkew  permitted future signing identifier clock skew
 * @param signingMaximumGroupSize maximum number of newly committed signing WAL
 *                                requests per durability group, from 1 through 32
 * @param signingResidentIndexBudgetBytes maximum conservatively accounted
 *                                        resident bytes shared by the signing
 *                                        indexes; must be positive
 * @param signingCompactionTransientBudgetBytes maximum conservatively accounted
 *                                               resident bytes available only to
 *                                               detached compaction work; must be
 *                                               positive
 * @param signingEvidenceAudit whether optional best-effort signing/proof evidence is appended; defaults to false
 * @param initialCrlNumber initial number for a newly created CRL scope counter,
 *                         from zero through {@code 2^159 - 1}; defaults to one
 */
@SuppressWarnings("PMD.LongVariable") // Public option names remain explicit and configuration-stable.
public record FsPkiStoreOptions(FsHistoryPolicy caHistoryPolicy, FsHistoryPolicy profileHistoryPolicy,
        FsHistoryPolicy revocationHistoryPolicy, FsHistoryPolicy workflowHistoryPolicy, boolean strictSnapshotExport,
        Duration signingOperationHorizon, Duration signingIdPermittedSkew, int signingMaximumGroupSize,
        long signingResidentIndexBudgetBytes, long signingCompactionTransientBudgetBytes,
        BigInteger initialCrlNumber, boolean signingEvidenceAudit) {

    private static final int DEFAULT_SIGNING_MAXIMUM_GROUP_SIZE = 32;
    private static final int MAXIMUM_SIGNING_GROUP_SIZE = 32;
    /* default */ static final long DEFAULT_RESIDENT_INDEX_BUDGET_BYTES = 512L * 1024L * 1024L;
    /* default */ static final long DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES = 512L * 1024L * 1024L;
    private static final long MINIMUM_RESIDENT_INDEX_BUDGET_BYTES = 1L;

    /**
     * Canonical constructor with validation.
     *
     * @throws NullPointerException     if a required object value is {@code null}
     * @throws IllegalArgumentException if a duration, signing group size, or
     *                                  resident-index budget or initial CRL number is outside its
     *                                  supported range
     */
    public FsPkiStoreOptions {
        Objects.requireNonNull(caHistoryPolicy, "caHistoryPolicy");
        Objects.requireNonNull(profileHistoryPolicy, "profileHistoryPolicy");
        Objects.requireNonNull(revocationHistoryPolicy, "revocationHistoryPolicy");
        Objects.requireNonNull(workflowHistoryPolicy, "workflowHistoryPolicy");
        Objects.requireNonNull(signingOperationHorizon, "signingOperationHorizon");
        Objects.requireNonNull(signingIdPermittedSkew, "signingIdPermittedSkew");
        Objects.requireNonNull(initialCrlNumber, "initialCrlNumber");
        if (initialCrlNumber.signum() < 0 || initialCrlNumber.bitLength() > 159) {
            throw new IllegalArgumentException("initialCrlNumber must be from zero through 2^159 - 1");
        }
        if (signingOperationHorizon.isZero() || signingOperationHorizon.isNegative()) {
            throw new IllegalArgumentException("signingOperationHorizon must be positive");
        }
        if (signingIdPermittedSkew.isNegative()) {
            throw new IllegalArgumentException("signingIdPermittedSkew must not be negative");
        }
        if (signingMaximumGroupSize < 1
                || signingMaximumGroupSize > MAXIMUM_SIGNING_GROUP_SIZE) {
            throw new IllegalArgumentException("signingMaximumGroupSize must be from 1 through 32");
        }
        if (signingResidentIndexBudgetBytes < MINIMUM_RESIDENT_INDEX_BUDGET_BYTES) {
            throw new IllegalArgumentException("signingResidentIndexBudgetBytes must be positive");
        }
        if (signingCompactionTransientBudgetBytes < MINIMUM_RESIDENT_INDEX_BUDGET_BYTES) {
            throw new IllegalArgumentException("signingCompactionTransientBudgetBytes must be positive");
        }
        try {
            Math.addExact(signingResidentIndexBudgetBytes, signingCompactionTransientBudgetBytes);
        } catch (ArithmeticException overflow) {
            throw new IllegalArgumentException("combined signing index budget exceeds the supported range", overflow);
        }
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
        return new FsPkiStoreOptions(ninetyDays, ninetyDays, ninetyDays, ninetyDays, true, Duration.ofDays(90),
                Duration.ZERO, DEFAULT_SIGNING_MAXIMUM_GROUP_SIZE,
                DEFAULT_RESIDENT_INDEX_BUDGET_BYTES, DEFAULT_TRANSIENT_INDEX_BUDGET_BYTES, BigInteger.ONE, false);
    }

    /**
     * Returns a copy using the supplied maximum signing durability-group size.
     *
     * <p>The setting constrains only groups written after the store is opened.
     * Existing valid groups remain readable up to the persistent format limit of
     * 32 requests.</p>
     *
     * @param maximumGroupSize maximum requests per newly committed group, from 1
     *                         through 32
     * @return an immutable copy with the supplied group size
     * @throws IllegalArgumentException if {@code maximumGroupSize} is outside the
     *                                  supported range
     */
    public FsPkiStoreOptions withSigningMaximumGroupSize(int maximumGroupSize) {
        return new FsPkiStoreOptions(caHistoryPolicy, profileHistoryPolicy,
                revocationHistoryPolicy, workflowHistoryPolicy, strictSnapshotExport,
                signingOperationHorizon, signingIdPermittedSkew, maximumGroupSize,
                signingResidentIndexBudgetBytes, signingCompactionTransientBudgetBytes, initialCrlNumber, signingEvidenceAudit);
    }

    /**
     * Returns a copy using the supplied shared resident signing-index budget.
     *
     * <p>The budget is conservative accounting used to reject an index update
     * before it can exceed the configured resident-memory envelope. It applies
     * equally when creating a store and rebuilding its indexes during open.</p>
     *
     * @param maximumBytes maximum conservatively accounted resident bytes; must
     *                     be positive
     * @return an immutable copy with the supplied resident-index budget
     * @throws IllegalArgumentException if {@code maximumBytes} is not positive
     */
    public FsPkiStoreOptions withSigningResidentIndexBudgetBytes(long maximumBytes) {
        return new FsPkiStoreOptions(caHistoryPolicy, profileHistoryPolicy,
                revocationHistoryPolicy, workflowHistoryPolicy, strictSnapshotExport,
                signingOperationHorizon, signingIdPermittedSkew, signingMaximumGroupSize,
                maximumBytes, signingCompactionTransientBudgetBytes, initialCrlNumber, signingEvidenceAudit);
    }

    /**
     * Returns a copy using the supplied detached-compaction resident budget.
     *
     * @param maximumBytes maximum conservatively accounted transient bytes; must
     *                     be positive and must form a representable combined
     *                     envelope with the steady resident-index budget
     * @return an immutable copy with the supplied transient budget
     * @throws IllegalArgumentException if the budget is invalid
     */
    public FsPkiStoreOptions withSigningCompactionTransientBudgetBytes(long maximumBytes) {
        return new FsPkiStoreOptions(caHistoryPolicy, profileHistoryPolicy,
                revocationHistoryPolicy, workflowHistoryPolicy, strictSnapshotExport,
                signingOperationHorizon, signingIdPermittedSkew, signingMaximumGroupSize,
                signingResidentIndexBudgetBytes, maximumBytes, initialCrlNumber, signingEvidenceAudit);
    }

    /**
     * Returns an immutable copy with the initial number for new CRL scope counters.
     * This setting does not reset an existing counter.
     *
     * @param number initial issued number, from zero through {@code 2^159 - 1}
     * @return an immutable copy preserving all other options
     * @throws NullPointerException if {@code number} is {@code null}
     * @throws IllegalArgumentException if {@code number} is outside the issued range
     */
    public FsPkiStoreOptions withInitialCrlNumber(BigInteger number) {
        return new FsPkiStoreOptions(caHistoryPolicy, profileHistoryPolicy,
                revocationHistoryPolicy, workflowHistoryPolicy, strictSnapshotExport,
                signingOperationHorizon, signingIdPermittedSkew, signingMaximumGroupSize,
                signingResidentIndexBudgetBytes, signingCompactionTransientBudgetBytes, number, signingEvidenceAudit);
    }
    /**
     * Returns a copy enabling or disabling best-effort terminal signing and internal-proof evidence.
     * Enabled evidence costs a separate metadata commit per new entry. Missing entries are
     * recoverable only while their authoritative workflow remains retained; this option does
     * not delay retirement or purge and creates no delivery worker.
     * @param enabled whether the optional signing evidence feed is maintained
     * @return an immutable copy preserving every other option
     */
    public FsPkiStoreOptions withSigningEvidenceAudit(boolean enabled) {
        return new FsPkiStoreOptions(caHistoryPolicy, profileHistoryPolicy,
                revocationHistoryPolicy, workflowHistoryPolicy, strictSnapshotExport,
                signingOperationHorizon, signingIdPermittedSkew, signingMaximumGroupSize,
                signingResidentIndexBudgetBytes, signingCompactionTransientBudgetBytes, initialCrlNumber, enabled);
    }
}
