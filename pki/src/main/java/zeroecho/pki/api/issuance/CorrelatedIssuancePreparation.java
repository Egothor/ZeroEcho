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

package zeroecho.pki.api.issuance;

import java.util.Objects;

import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;

/**
 * Closed result of correlated end-entity preparation. The immutable result either
 * describes retained accepted work or carries exclusive, single-use preparation
 * custody. Neither variant grants authorization or registers a runtime activity.
 */
public sealed interface CorrelatedIssuancePreparation
        permits CorrelatedIssuancePreparation.Existing, CorrelatedIssuancePreparation.Prepared {
    /**
     * Immutable snapshot of exactly matching retained work, including failed,
     * cancelled or expired work. No new preparation is owned by this result.
     *
     * @param operation authoritative retained semantic snapshot
     */
    record Existing(SemanticSigningOperation operation) implements CorrelatedIssuancePreparation {
        /**
         * Creates a snapshot result.
         * @throws NullPointerException if the operation is null
         */
        public Existing { Objects.requireNonNull(operation, "operation"); }
    }

    /**
     * Immutable carrier of one unused preparation. Its single-use custody must
     * be accepted or discarded through the preparing session's semantic service.
     * Preparation is not durable acceptance and does not reserve the correlation.
     *
     * @param prepared opaque preparation exclusively owning its staged candidate
     */
    record Prepared(PreparedSemanticSigningRequest prepared) implements CorrelatedIssuancePreparation {
        /**
         * Creates a custody carrier.
         * @throws NullPointerException if the preparation is null
         */
        public Prepared { Objects.requireNonNull(prepared, "prepared"); }
    }
}
