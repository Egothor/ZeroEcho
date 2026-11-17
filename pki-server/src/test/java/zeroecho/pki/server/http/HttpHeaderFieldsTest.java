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
package zeroecho.pki.server.http;

import com.sun.net.httpserver.Headers;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies that header access preserves JDK header lookup, validation and list mutability.
 */
class HttpHeaderFieldsTest {
    @Test
    void firstRetainsMissingEmptyAndCaseInsensitiveHeaderSemantics() {
        Headers headers = new Headers();
        assertNull(HttpHeaderFields.first(headers, "Missing"));
        headers.put("Empty", new ArrayList<>());
        assertEquals(headers.getFirst("empty"), HttpHeaderFields.first(headers, "empty"));
        headers.put("X-Values", new ArrayList<>(List.of("first", "second")));
        assertEquals(headers.getFirst("x-values"), HttpHeaderFields.first(headers, "x-values"));
    }

    @Test
    void replacementRetainsJdkValidationAndMutableHeaderValues() {
        Headers expected = new Headers();
        Headers actual = new Headers();
        expected.set("X-Value", "first");
        HttpHeaderFields.set(actual, "x-value", "first");
        assertEquals(expected, actual);
        expected.add("x-value", "second");
        actual.add("X-VALUE", "second");
        assertEquals(expected, actual);
        assertThrows(IllegalArgumentException.class, () -> expected.set("X-Value", "bad\nvalue"));
        assertThrows(IllegalArgumentException.class, () -> HttpHeaderFields.set(actual, "X-Value", "bad\nvalue"));
        assertThrows(IllegalArgumentException.class, () -> HttpHeaderFields.set(actual, "bad\nname", "value"));
        assertEquals(expected, actual);
    }
}
