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
import java.util.Objects;
import java.util.Optional;

/**
 * History configuration for mutable entities stored by
 * {@link FilesystemPkiStore}.
 *
 * <p>
 * "Mutable" here means: the entity may be replaced/updated over time, but every
 * replacement must remain audit-able. This implementation achieves that by
 * writing an immutable history record (append-only) and then updating
 * {@code current.bin} atomically.
 * </p>
 */
public final class FsHistoryPolicy {

    /**
     * Supported cleanup strategy.
     *
     * <p>
     * {@code ON_WRITE} means retention cleanup is executed as part of a write
     * operation, which is deterministic and does not require background tasks.
     * </p>
     */
    public enum CleanupStrategy {
        /**
         * Cleanup happens during write operations only.
         */
        ON_WRITE
    }

    private final boolean enabled;
    private final CleanupStrategy cleanupStrategy;
    private final Optional<Duration> retentionWindow;

    private FsHistoryPolicy(final boolean enabled, final CleanupStrategy cleanupStrategy,
            final Optional<Duration> retentionWindow) {

        this.enabled = enabled;
        this.cleanupStrategy = Objects.requireNonNull(cleanupStrategy, "cleanupStrategy");
        this.retentionWindow = Objects.requireNonNull(retentionWindow, "retentionWindow");
    }

    /**
     * Creates a history policy with {@link CleanupStrategy#ON_WRITE}.
     *
     * @param retentionWindow optional retention window; when present, entries older
     *                        than {@code now - retentionWindow} are deleted during
     *                        writes (best-effort, deterministic order)
     * @return policy
     */
    public static FsHistoryPolicy onWrite(final Optional<Duration> retentionWindow) {
        return new FsHistoryPolicy(true, CleanupStrategy.ON_WRITE, retentionWindow);
    }

    /**
     * Disables history tracking.
     *
     * <p>
     * Disabling history implies that updates to the entity are still atomic, but
     * audit reconstruction and snapshot export may be limited or impossible.
     * </p>
     *
     * @return policy
     */
    public static FsHistoryPolicy disabled() {
        return new FsHistoryPolicy(false, CleanupStrategy.ON_WRITE, Optional.empty());
    }

    /**
     * Whether history is enabled.
     *
     * @return true if enabled
     */
    public boolean enabled() {
        return this.enabled;
    }

    /**
     * Cleanup strategy.
     *
     * @return strategy
     */
    public CleanupStrategy cleanupStrategy() {
        return this.cleanupStrategy;
    }

    /**
     * Optional retention window.
     *
     * @return retention window
     */
    public Optional<Duration> retentionWindow() {
        return this.retentionWindow;
    }
}
