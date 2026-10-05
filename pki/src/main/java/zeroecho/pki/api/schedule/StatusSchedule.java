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
package zeroecho.pki.api.schedule;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.status.StatusObjectType;

/**
 * Configures the automatic generation interval for one status-object family.
 *
 * <p>A schedule with {@code enabled=false} is stored but suppresses fresh automatic claims;
 * accepted work still completes during recovery.
 * Durable worker progress retains the next due instant separately from this
 * configuration. A new schedule is immediately due; overdue runs are coalesced.</p>
 *
 * <p>Revision 0 is the sentinel for "not yet stored". All stored schedules have revision &ge; 1.</p>
 *
 * @param caId              exact authority identifier
 * @param statusType        kind of status object
 * @param formatId          encoding format for generated objects
 * @param interval          mandatory positive interval (minimum PT1M)
 * @param graceSeconds      lead time before next update, leaving at least one whole second of cadence
 * @param enabled           whether the worker should fire automatically
 * @param publicationTarget optional automatic publication destination; empty = generate only
 * @param createdAt         wall-clock creation time
 * @param updatedAt         wall-clock last-update time
 * @param revision          optimistic-concurrency version; 0 = unsaved
 */
public record StatusSchedule(
        PkiId caId,
        StatusObjectType statusType,
        FormatId formatId,
        Duration interval,
        long graceSeconds,
        boolean enabled,
        Optional<PublicationTarget> publicationTarget,
        Instant createdAt,
        Instant updatedAt,
        long revision) {

    /** Minimum configurable interval. */
    public static final Duration MINIMUM_INTERVAL = Duration.ofMinutes(1L);

    /** Validates the schedule. */
    public StatusSchedule {
        Objects.requireNonNull(caId, "caId");
        int index = 0;
        while (index < caId.value().length()) {
            char current = caId.value().charAt(index++);
            if (Character.isHighSurrogate(current)) {
                if (index == caId.value().length() || !Character.isLowSurrogate(caId.value().charAt(index++))) {
                    throw new IllegalArgumentException("Schedule authority identity is not valid Unicode");
                }
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException("Schedule authority identity is not valid Unicode");
            }
        }
        Objects.requireNonNull(statusType, "statusType");
        Objects.requireNonNull(formatId, "formatId");
        Objects.requireNonNull(interval, "interval");
        if (interval.isNegative() || interval.isZero() || interval.compareTo(MINIMUM_INTERVAL) < 0) {
            throw new IllegalArgumentException("interval must be at least PT1M");
        }
        if (graceSeconds < 0 || graceSeconds >= interval.getSeconds()) {
            throw new IllegalArgumentException("graceSeconds must leave at least one whole second of cadence");
        }
        publicationTarget = Objects.requireNonNull(publicationTarget, "publicationTarget");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (revision < 0) {
            throw new IllegalArgumentException("revision must not be negative");
        }
    }
}
