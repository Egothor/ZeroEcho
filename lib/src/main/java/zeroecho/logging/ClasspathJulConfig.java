/* *****************************************************************************
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
package zeroecho.logging;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Handler;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * Configures {@link java.util.logging} (JUL) from a {@code jul.properties}
 * resource on the classpath.
 *
 * <p>
 * When constructed, this class attempts to locate {@code jul.properties} using
 * the current thread’s context class loader. If none is available, it falls
 * back to the defining class loader. The located resource is then parsed by
 * {@link java.util.logging.LogManager#readConfiguration(InputStream)} to
 * install JUL handlers, formatters, and levels as specified.
 * </p>
 *
 * <h2>Error handling</h2>
 * <ul>
 * <li>If the resource is not found, construction fails with
 * {@link IllegalStateException}.</li>
 * <li>If a {@link SecurityException} or {@link IOException} occurs while
 * applying the configuration, the exception stack trace is printed directly to
 * {@code System.err}. This ensures diagnostic visibility even before JUL itself
 * is configured.</li>
 * </ul>
 *
 * <h2>JSON structured logging</h2>
 * <p>
 * When the system property {@code zeroecho.logging.json} is set to {@code true}
 * before construction, a {@link JsonLogFormatter} is installed on every handler
 * attached to the root logger. Each record is then emitted as a single-line JSON
 * object, making log ingestion by Splunk, ELK, or Datadog trivial without grok
 * patterns.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Enable JSON output before initialising logging:
 * System.setProperty("zeroecho.logging.json", "true");
 * new ClasspathJulConfig();
 *
 * // Afterwards, all log records are emitted as newline-delimited JSON.
 * Logger log = Logger.getLogger("my.app");
 * log.info("Configured via classpath resource");
 * }</pre>
 *
 * @since 1.0
 */
public final class ClasspathJulConfig {
    /**
     * Loads {@code jul.properties} from the classpath and applies it as the current
     * {@link java.util.logging.LogManager} configuration.
     *
     * @throws IllegalStateException if the resource {@code jul.properties} is not
     *                               found
     */
    public ClasspathJulConfig() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = ClasspathJulConfig.class.getClassLoader(); // NOPMD
        }
        try (InputStream in = cl.getResourceAsStream("jul.properties")) {
            if (in == null) {
                throw new IllegalStateException("jul.properties not found on classpath");
            }
            LogManager.getLogManager().readConfiguration(in);
        } catch (SecurityException | IOException e) {
            // As a last resort, print — logging may not be configured yet.
            System.err.println(e.getMessage()); //
        }
        if (Boolean.getBoolean("zeroecho.logging.json")) {
            Logger root = Logger.getLogger("");
            for (Handler h : root.getHandlers()) {
                h.setFormatter(JsonLogFormatter.INSTANCE);
            }
        }
    }
}
