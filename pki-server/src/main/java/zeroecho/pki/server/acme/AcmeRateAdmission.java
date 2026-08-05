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
 *******************************************************************************/
package zeroecho.pki.server.acme;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;

import zeroecho.pki.server.PkiServerConfiguration;

/** Bounded restart-local ACME rate and finalization admission authority. */
@SuppressWarnings({ "PMD.AvoidSynchronizedAtMethodLevel", "PMD.ControlStatementBraces" })
public final class AcmeRateAdmission {
    private final Duration window;
    private final int accountLimit;
    private final int orderLimit;
    private final int validationLimit;
    private final int maximumKeys;
    private final Clock clock;
    private final Map<String, Counter> counters = new HashMap<>();
    private final Semaphore finalizations;

    /** Creates admission limits from one exact ACME listener configuration. */
    public AcmeRateAdmission(PkiServerConfiguration.AcmeListener configuration, Clock clock) {
        this.window = configuration.admissionWindow();
        this.accountLimit = configuration.maximumNewAccountsPerWindow();
        this.orderLimit = configuration.maximumNewOrdersPerAccountWindow();
        this.validationLimit = configuration.maximumChallengeValidationsPerAccountWindow();
        this.maximumKeys = Math.min(1_000_000, configuration.maximumOutstandingNonces());
        this.clock = Objects.requireNonNull(clock, "clock");
        this.finalizations = new Semaphore(configuration.maximumConcurrentFinalizations(), true);
    }

    /** Admits one new-account request within the directory-wide window. */
    public synchronized boolean admitAccount(String directoryId) {
        return admit("account:" + directoryId, accountLimit);
    }

    /** Admits one new-order request within the exact account window. */
    public synchronized boolean admitOrder(String accountId) { return admit("order:" + accountId, orderLimit); }

    /** Admits one explicit challenge-validation attempt. */
    public synchronized boolean admitValidation(String accountId) {
        return admit("validation:" + accountId, validationLimit);
    }

    /** Acquires one listener-wide finalization permit without waiting. */
    public boolean tryAcquireFinalization() { return finalizations.tryAcquire(); }

    /** Releases one previously acquired finalization permit. */
    public void releaseFinalization() { finalizations.release(); }

    /** @return bounded live counter population */
    public synchronized int trackedKeys() { expire(clock.instant()); return counters.size(); }

    private boolean admit(String key, int limit) {
        Instant now = clock.instant(); expire(now);
        Counter current = counters.get(key);
        if (current == null) {
            if (counters.size() >= maximumKeys) return false;
            counters.put(key, new Counter(1, now.plus(window))); return true;
        }
        if (current.count() >= limit) return false;
        counters.put(key, new Counter(current.count() + 1, current.expiresAt())); return true;
    }

    private void expire(Instant now) { counters.entrySet().removeIf(entry -> !entry.getValue().expiresAt().isAfter(now)); }
    private record Counter(int count, Instant expiresAt) { }
}
