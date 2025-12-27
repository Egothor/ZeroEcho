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
package zeroecho.pki;

import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Minimal bootstrap entry point for the {@code pki} module.
 *
 * <p>
 * This class is intentionally limited to process bootstrap concerns only:
 * </p>
 * <ul>
 * <li>initializes JUL logging conventions (without leaking secrets),</li>
 * <li>installs an uncaught-exception handler,</li>
 * <li>emits a minimal startup/shutdown signal.</li>
 * </ul>
 *
 * <p>
 * No cryptography, persistence, or domain/business logic is performed here. The
 * public PKI API resides under {@code zeroecho.pki.api.*} and is not modified
 * by this bootstrap.
 * </p>
 */
public final class PkiApplication {

    private static final Logger LOG = Logger.getLogger(PkiApplication.class.getName());

    private PkiApplication() {
        throw new AssertionError("No instances.");
    }

    /**
     * Starts the PKI process.
     *
     * <p>
     * Security note: command-line arguments are not logged because they can contain
     * sensitive material (paths, tokens, passphrases).
     * </p>
     *
     * @param args command-line arguments (never logged)
     */
    public static void main(String[] args) {
        Objects.requireNonNull(args, "args");

        PkiLogging.configureIfPresent();
        PkiLogging.installUncaughtExceptionHandler();

        LOG.info("ZeroEcho PKI starting.");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Logger shutdownLogger = Logger.getLogger(PkiApplication.class.getName());
            PkiLogging.emitShutdownMessage(shutdownLogger, "ZeroEcho PKI stopping.");
        }, "zeroecho-pki-shutdown"));

        try {
            // Intentionally no business logic yet. Bootstrap only.
            LOG.info("ZeroEcho PKI started (bootstrap only).");
        } catch (RuntimeException ex) {
            // Do not include user-provided inputs in the message; log the exception object.
            LOG.log(Level.SEVERE, "Fatal error during PKI bootstrap.", ex);
            throw ex;
        }
    }
}
