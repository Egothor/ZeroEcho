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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.Test;

class JsonLogFormatterTest {
    @Test
    void everyControlCharacterAndJsonDelimiterHasCanonicalEscaping() {
        StringBuilder controls = new StringBuilder();
        for (char value = 0; value < 32; value++) controls.append(value);
        LogRecord record = new LogRecord(Level.INFO, controls.toString());
        record.setInstant(Instant.parse("2026-10-05T12:00:00Z"));
        record.setLoggerName("quote\"slash\\unicodeé");
        String escaped = "\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\u0008"
                + "\\t\\n\\u000b\\u000c\\r\\u000e\\u000f"
                + "\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017"
                + "\\u0018\\u0019\\u001a\\u001b\\u001c\\u001d\\u001e\\u001f";
        assertEquals("{\"timestamp\":\"2026-10-05T12:00:00Z\",\"level\":\"INFO\","
                + "\"logger\":\"quote\\\"slash\\\\unicodeé\",\"message\":\"" + escaped + "\"}\n",
                JsonLogFormatter.INSTANCE.format(record));
    }
}
