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
package zeroecho.logging;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * A compact single-line {@link java.util.logging.Formatter} for JUL log
 * records.
 *
 * <p>
 * Each record is rendered into one line containing:
 * </p>
 * <ul>
 * <li>timestamp in {@code yyyy-MM-dd HH:mm:ss.SSS} format (local time
 * zone),</li>
 * <li>log level name,</li>
 * <li>current thread name,</li>
 * <li>source class and method (abbreviated),</li>
 * <li>the formatted message with whitespace collapsed,</li>
 * <li>and, if present, exception information: exception type, message, and
 * first stack frame, rendered inline.</li>
 * </ul>
 *
 * <p>
 * This formatter is designed for console or file logs where compactness and
 * readability in a single line per record are preferred over multi-line stack
 * traces. Exception stack traces are summarized to avoid overwhelming output;
 * only the first frame is shown.
 * </p>
 *
 * <h2>Example output</h2> <pre>{@code
 * 2025-09-10 22:15:32.184 INFO [main] c.e.d.p.MyService#start - Started service
 * 2025-09-10 22:15:33.201 SEVERE [worker-1] c.e.d.p.Worker#run - Task failed
 *   | ex=IllegalStateException: bad state @ Worker.java:42
 * }</pre>
 *
 * <h2>Abbreviation rules</h2>
 * <ul>
 * <li>Package names are reduced to their initials (e.g.,
 * {@code com.example.deep.package.MyService} → {@code c.e.d.p.MyService}).</li>
 * <li>Simple class names are shortened by keeping uppercase letters before the
 * last uppercase, and then the last uppercase plus the suffix (e.g.,
 * {@code MyServiceManager} → {@code MSManager}, {@code XmlHttpRequest} →
 * {@code XHR}, {@code UserDAO} → {@code UDAO}, {@code FooBar} →
 * {@code FBar}).</li>
 * </ul>
 *
 * @since 1.0
 */
public final class CompactOneLineFormatter extends Formatter {
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneId.systemDefault());

    /**
     * Creates a formatter using the system time zone for timestamps.
     */
    public CompactOneLineFormatter() {
        super();
        // Stateless apart from the immutable shared timestamp formatter.
    }

    /**
     * Formats a {@link LogRecord} into a single line.
     *
     * <p>
     * The message text has runs of whitespace collapsed to a single space. If
     * {@link LogRecord#getThrown()} is non-null, the formatter appends a compact
     * suffix in the form {@code " | ex=<Type>: <message> @ <firstStackFrame>"}.
     * </p>
     *
     * @param r the log record to format
     * @return formatted line ending with the platform line separator
     */
    @Override
    public String format(LogRecord r) {
        String ts = TS.format(Instant.ofEpochMilli(r.getMillis()));
        String level = r.getLevel().getName();
        String clazz = compactFast(r.getSourceClassName() != null ? r.getSourceClassName() : r.getLoggerName());
        String method = r.getSourceMethodName() != null ? r.getSourceMethodName() : "-";
        String thread = Thread.currentThread().getName(); // NOPMD
        String msg = collapseWhitespace(formatMessage(r)).trim();

        String thrown = "";
        if (r.getThrown() != null) {
            Throwable t = r.getThrown();
            StringBuilder sb = new StringBuilder(64);
            sb.append(" | ex=").append(t.getClass().getSimpleName());
            String m = t.getMessage();
            if (m != null && !m.isEmpty()) {
                sb.append(": ").append(collapseWhitespace(m));
            }
            StackTraceElement[] st = t.getStackTrace();
            if (st.length > 0) {
                sb.append(" @ ").append(st[0]);
            }
            thrown = sb.toString();
        }

        return ts + " " + level + " [" + thread + "] " + clazz + "#" + method + " - " + msg + thrown
                + System.lineSeparator();
    }

    /**
     * Collapses runs of Unicode whitespace into a single ASCII space without using
     * regex.
     *
     * <p>
     * Null or empty input yields an empty string. The algorithm is linear in the
     * input length and minimizes allocations for use on logging hot paths.
     * </p>
     *
     * @param s input text
     * @return text with runs of whitespace replaced by a single space
     */
    private static String collapseWhitespace(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder out = new StringBuilder(s.length());
        boolean inWs = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ws = Character.isWhitespace(c);
            if (ws) {
                if (!inWs) {
                    out.append(' ');
                    inWs = true;
                }
            } else {
                out.append(c);
                inWs = false;
            }
        }
        return out.toString();
    }

    /**
     * Compacts a fully qualified class name to package initials plus a shortened
     * simple name.
     *
     * <p>
     * Example: {@code com.example.deep.package.MyService} becomes
     * {@code c.e.d.p.MyService}. If the input has no package, only the shortened
     * simple name is returned.
     * </p>
     *
     * @param fqcn fully qualified class name, or null
     * @return compact representation or "-" if {@code fqcn} is null or empty
     */
    private static String compactFast(String fqcn) {
        if (fqcn == null || fqcn.isEmpty()) {
            return "-";
        }
        int lastDot = fqcn.lastIndexOf('.');
        if (lastDot < 0) {
            return shorten(fqcn);
        }

        StringBuilder sb = new StringBuilder(fqcn.length());
        // Package initials
        int start = 0;
        while (true) {
            int dot = fqcn.indexOf('.', start);
            if (dot < 0 || dot >= lastDot) {
                break;
            }
            if (dot > start) {
                sb.append(fqcn.charAt(start)).append('.');
            }
            start = dot + 1;
        }
        // Simple class
        sb.append(shorten(fqcn.substring(lastDot + 1)));
        return sb.toString();
    }

    /**
     * Shortens a simple class name according to abbreviation rules.
     *
     * <p>
     * Rule: keep all uppercase letters before the last uppercase, then keep the
     * last uppercase and everything after it.
     * </p>
     *
     * <h2>Examples</h2>
     * <ul>
     * <li>{@code Service} → {@code Service}</li>
     * <li>{@code MyServiceManager} → {@code MSManager}</li>
     * <li>{@code XmlHttpRequest} → {@code XHR}</li>
     * <li>{@code UserDAO} → {@code UDAO}</li>
     * <li>{@code FooBar} → {@code FBar}</li>
     * </ul>
     *
     * @param simple the simple class name
     * @return shortened representation of the class name
     */
    private static String shorten(String simple) {
        if (simple.isEmpty()) {
            return simple;
        }

        char[] chars = simple.toCharArray();

        // find index of last uppercase
        int lastUpper = -1;
        for (int i = chars.length - 1; i >= 0; i--) {
            if (Character.isUpperCase(chars[i])) {
                lastUpper = i;
                break;
            }
        }

        if (lastUpper == -1) {
            return simple; // no uppercase at all
        }

        StringBuilder out = new StringBuilder();

        // keep uppercase letters before the last one
        for (int i = 0; i < lastUpper; i++) {
            if (Character.isUpperCase(chars[i])) {
                out.append(chars[i]);
            }
        }

        // keep the last uppercase and the tail
        out.append(simple.substring(lastUpper));

        return out.toString();
    }
}
