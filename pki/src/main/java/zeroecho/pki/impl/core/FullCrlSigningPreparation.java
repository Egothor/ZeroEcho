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

package zeroecho.pki.impl.core;

import java.io.IOException;
import java.time.Clock;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Stateless session-owned composition of full-CRL policy validation and TBS staging.
 * No signing dispatch or durable acceptance occurs. Instances are thread-safe when
 * their store is thread-safe. Time, bounded auxiliary memory and staged disk costs
 * are those of the existing two-pass {@link FullCrlTbsPreparation}.
 */
public final class FullCrlSigningPreparation {
    private final FullCrlPreparation validation;
    private final FullCrlTbsPreparation staging;

    /**
     * Binds preparation to the exact session store and selected provider authority.
     * @param store authoritative store
     * @param clock evaluation clock
     * @param authority SIGN authority bound to the selected provider instance
     * @param bindings immutable configured X.509 bindings
     * @param signatureAlgorithm canonical configured signature identity
     */
    public FullCrlSigningPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        validation = new FullCrlPreparation(store, clock, authority, bindings, signatureAlgorithm);
        staging = new FullCrlTbsPreparation(store);
    }

    /**
     * Validates issuer and capability before reserving a number and staging TBS.
     * Success transfers exclusive unowned content custody to the caller, which
     * must adopt or retire it. Failure cleans up invocation-owned content. A
     * reserved number is consumed even if later staging, adoption or acceptance fails.
     * @param request exact issuer generation and requested validity
     * @param cancellation cooperative pre-acceptance cancellation
     * @return frozen TBS carrier for immediate semantic adoption
     * @throws IOException if staging or cancellation fails
     * @throws RuntimeException if policy, issuer or capability validation fails
     */
    public PreparedFullCrlTbs prepare(FullCrlRequest request, CancellationSignal cancellation) throws IOException {
        return staging.prepare(validation.prepare(request, cancellation), cancellation);
    }

    /**
     * Selects and verifies one full CRL base before freezing a delta snapshot and
     * reserving its number. Content custody and permanent number gaps follow
     * {@link #prepare(FullCrlRequest, CancellationSignal)}.
     * @param request exact generation and validity
     * @param pureEdDsaMaximum configured finite bound for actual base TBS verification
     * @param cancellation cooperative preparation cancellation
     * @return one frozen delta TBS ready for semantic adoption
     * @throws IOException if content, prefix validation, staging or cancellation fails
     */
    public PreparedFullCrlTbs prepare(DeltaCrlRequest request, long pureEdDsaMaximum,
            CancellationSignal cancellation) throws IOException {
        return staging.prepare(validation.prepare(request, pureEdDsaMaximum, cancellation), cancellation);
    }
}
