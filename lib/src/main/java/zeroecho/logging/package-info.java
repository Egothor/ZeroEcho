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
/**
 * Provides lightweight logging utilities and configuration helpers for Java
 * Util Logging (JUL).
 *
 * <h2>Overview</h2>
 * <p>
 * This package complements the standard {@code java.util.logging} framework
 * with tools for streamlined configuration and more compact log output. It is
 * designed for applications that prefer JUL over third-party logging frameworks
 * but still require concise, production-ready log formatting.
 * </p>
 *
 * <h2>Components</h2>
 * <ul>
 * <li>{@code ClasspathJulConfig} – loads a {@code jul.properties} configuration
 * file from the application classpath and applies it to the global
 * {@link java.util.logging.LogManager}. This allows declarative setup of
 * handlers, levels, and formatters without manual bootstrap code.</li>
 * <li>{@code CompactOneLineFormatter} – a formatter that produces single-line
 * log records with timestamps, thread names, class/method context, and optional
 * exception summaries. The output is compact enough for terminals and log
 * aggregation systems, while still preserving diagnostic detail.</li>
 * </ul>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li><b>Simplicity</b> – avoid external dependencies and keep JUL setup
 * minimal.</li>
 * <li><b>Compactness</b> – formatters collapse whitespace and abbreviate fully
 * qualified class names to keep logs dense but readable.</li>
 * <li><b>Safety</b> – exception details are reduced to single-line summaries,
 * preventing multi-line stack traces from overwhelming logs in production.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Automatically loads jul.properties from the classpath
 * new ClasspathJulConfig();
 *
 * Logger logger = Logger.getLogger("demo");
 * logger.info("Hello world");
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho.logging;
