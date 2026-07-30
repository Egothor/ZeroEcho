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
package zeroecho.pki;

import java.io.IOException;
import java.io.InputStream;
import java.lang.Thread.UncaughtExceptionHandler;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Internal bootstrap utilities for JUL configuration in the {@code pki} module.
 *
 * <p>
 * This helper intentionally avoids logging any potentially sensitive material.
 * In particular, it never logs:
 * </p>
 * <ul>
 * <li>command-line arguments,</li>
 * <li>key material, seeds, shared secrets,</li>
 * <li>private configuration values (tokens, passphrases).</li>
 * </ul>
 *
 * <p>
 * Configuration strategy:
 * </p>
 * <ul>
 * <li>If a {@code /zeroecho-pki-logging.properties} resource is present on the
 * classpath, it will be loaded via
 * {@link LogManager#readConfiguration(InputStream)}.</li>
 * <li>If not present, JUL defaults remain in place (minimal bootstrap
 * behavior).</li>
 * </ul>
 */
final class PkiLogging {

    /**
     * Optional classpath resource for JUL configuration.
     */
    private static final String LOGGING_PROPERTIES_RESOURCE = "/zeroecho-pki-logging.properties";

    private static final Logger LOG = Logger.getLogger(PkiLogging.class.getName());

    /**
     * One-shot guard ensuring JUL configuration is attempted at most once.
     */
    private static final AtomicBoolean CONFIGURED = new AtomicBoolean(false);

    private PkiLogging() {
        throw new AssertionError("No instances.");
    }

    /**
     * Configures JUL from an optional classpath resource, if present.
     *
     * <p>
     * This method is idempotent and safe to call multiple times.
     * </p>
     */
    /* default */ static void configureIfPresent() {
        // Fast-path: already configured
        if (!CONFIGURED.compareAndSet(false, true)) {
            return;
        }

        // getResourceAsStream() may return null; try-with-resources handles null safely
        try (InputStream is = PkiLogging.class.getResourceAsStream(LOGGING_PROPERTIES_RESOURCE)) {
            if (is == null) {
                return;
            }
            LogManager.getLogManager().readConfiguration(is);
            LOG.info("JUL configured from classpath resource.");
        } catch (IOException ex) {
            // Keep message generic; do not leak environment specifics.
            LOG.log(Level.WARNING, "Failed to load JUL configuration; continuing with defaults.", ex);
        }
    }

    /**
     * Installs a process-wide uncaught exception handler that logs failures via
     * JUL.
     *
     * <p>
     * The handler emits a generic message and includes the throwable. It
     * deliberately does not serialize additional contextual data that might contain
     * secrets.
     * </p>
     */
    /* default */ static void installUncaughtExceptionHandler() {
        UncaughtExceptionHandler handler = (Thread thread, Throwable throwable) -> { // NOPMD
            Objects.requireNonNull(thread, "thread");
            Objects.requireNonNull(throwable, "throwable");
            Logger logger = Logger.getLogger(PkiApplication.class.getName());
            if (logger.isLoggable(Level.SEVERE)) {
                logger.log(Level.SEVERE, "Uncaught exception in thread: " + thread.getName(), throwable);
            }
        };

        Thread.setDefaultUncaughtExceptionHandler(handler); // NOPMD
    }

    /**
     * Emits a shutdown message in a way that remains visible even during late JVM
     * teardown.
     *
     * <p>
     * The primary path is JUL. As a fallback, a constant message is written to
     * {@code System.err}. This avoids logging any secrets and improves reliability
     * in environments where JUL output may be lost during shutdown.
     * </p>
     *
     * @param logger  logger to use for the primary JUL emission
     * @param message message to emit; must not contain secrets
     * @throws NullPointerException if {@code logger} or {@code message} is
     *                              {@code null}
     */
    /* default */ static void emitShutdownMessage(Logger logger, String message) {
        Objects.requireNonNull(logger, "logger");
        Objects.requireNonNull(message, "message");

        // Primary path: JUL
        logger.info(message);

        // Flush root handlers (covers parent-handler delegation).
        Logger root = Logger.getLogger("");
        for (java.util.logging.Handler handler : root.getHandlers()) {
            try {
                handler.flush();
            } catch (RuntimeException ignored) { // NOPMD
                // Never throw during shutdown
            }
        }

        // Fallback: direct stderr write
        try {
            System.err.println(message);
            System.err.flush();
        } catch (RuntimeException ignored) { // NOPMD
            // Never throw during shutdown
        }
    }

}
