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

import java.time.Instant;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/**
 * A newline-delimited JSON log formatter for {@link java.util.logging.Handler}.
 *
 * <p>
 * Each log record is emitted as a single JSON object on one line, followed by a
 * newline character. The format is suitable for structured ingestion by log
 * aggregation systems such as Splunk, Elasticsearch/ELK, or Datadog without
 * requiring grok patterns. Activate this formatter by setting the system
 * property {@code zeroecho.logging.json=true} before logging is initialised,
 * or install it programmatically on any {@link java.util.logging.Handler}.
 * </p>
 *
 * <h2>Output format</h2>
 * <pre>{@code
 * {"timestamp":"2026-09-30T12:34:56.789Z","level":"INFO","logger":"zeroecho.foo.Bar","message":"text"}
 * {"timestamp":"...","level":"WARNING","logger":"...","message":"...","thrown":"ExceptionClass: msg"}
 * }</pre>
 *
 * <h2>Field semantics</h2>
 * <ul>
 * <li>{@code timestamp} — ISO-8601 UTC instant derived from the log record's
 *     epoch-millisecond timestamp.</li>
 * <li>{@code level} — JUL level name (e.g. {@code INFO}, {@code WARNING}).</li>
 * <li>{@code logger} — logger name, or an empty string when not set.</li>
 * <li>{@code message} — formatted message with parameters substituted; control
 *     characters and JSON-special characters are escaped.</li>
 * <li>{@code thrown} — present only when the record carries a {@link Throwable};
 *     formatted as {@code ClassName: message}.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Instances are stateless and thread-safe.
 * </p>
 *
 * @since 1.0
 */
final class JsonLogFormatter extends Formatter {
    private static final int FIRST_PRINTABLE = 0x20;

    /** Single reusable instance; stateless so sharing is safe. */
    /* default */ static final JsonLogFormatter INSTANCE = new JsonLogFormatter();

    /**
     * Formats one log record as a single-line JSON object.
     *
     * @param record the log record to format; never {@code null}
     * @return a JSON object string terminated with a newline; never {@code null}
     */
    @Override
    public String format(LogRecord record) {
        String timestamp = Instant.ofEpochMilli(record.getMillis()).toString();
        String level = record.getLevel().getName();
        String logger = record.getLoggerName() == null ? "" : record.getLoggerName();
        String message = escape(formatMessage(record));

        StringBuilder sb = new StringBuilder(128);
        sb.append("{\"timestamp\":\"").append(timestamp)
          .append("\",\"level\":\"").append(level)
          .append("\",\"logger\":\"").append(escape(logger))
          .append("\",\"message\":\"").append(message).append('"');

        Throwable thrown = record.getThrown();
        if (thrown != null) {
            String thrownMsg = thrown.getMessage();
            String thrownText = thrown.getClass().getName()
                    + (thrownMsg != null ? ": " + thrownMsg : "");
            sb.append(",\"thrown\":\"").append(escape(thrownText)).append('"');
        }

        sb.append("}\n");
        return sb.toString();
    }

    /**
     * Escapes a string value for embedding in a JSON string literal.
     *
     * <p>
     * The following characters are replaced with their JSON escape sequences:
     * {@code "} → {@code \"}, {@code \} → {@code \\},
     * {@code \n} → {@code \n}, {@code \r} → {@code \r},
     * {@code \t} → {@code \t}. All other control characters in the range
     * U+0000 through U+001F are encoded as &#92;uXXXX (six-character JSON escape).
     * </p>
     *
     * @param value the string to escape; must not be {@code null}
     * @return the JSON-safe escaped string; never {@code null}
     */
    private static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> {
                    if (c < FIRST_PRINTABLE) {
                        sb.append("\\u00").append("0123456789abcdef".charAt(c >>> 4))
                                .append("0123456789abcdef".charAt(c & 0xf));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
