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

package zeroecho.pki.api.ca;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;

/** Local structural validation only; strict UTF-8 counting allocates no encoded byte arrays. */
final class CaCommandInputs {
    private CaCommandInputs() { }

    /* default */ static void required(Object value) {
        if (value == null) { throw invalid(); }
    }

    /* default */ static void identifier(PkiId value) {
        required(value);
        text(value.value(), 4096);
    }

    /* default */ static void profile(String value) { text(value, 256); }

    /* default */ static void key(KeyRef value) {
        required(value);
        text(value.value(), 1_048_576);
    }

    /* default */ // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
                  @SuppressWarnings({ "PMD.PreserveStackTrace" })
                  static void proof(PkiId value) {
        identifier(value);
        try { SigningSubmissionId.parse(value); }
        catch (IllegalArgumentException malformed) { throw invalid(); }
    }

    private static void text(String value, int maximumBytes) {
        required(value);
        if (value.length() > maximumBytes || value.isBlank()) { throw invalid(); }
        int bytes = 0;
        int index = 0;
        while (index < value.length()) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (++index == value.length() || !Character.isLowSurrogate(value.charAt(index))) { throw invalid(); }
                bytes += 4;
            } else if (Character.isLowSurrogate(current)) {
                throw invalid();
            } else {
                bytes += current < 0x80 ? 1 : current < 0x800 ? 2 : 3;
            }
            if (bytes > maximumBytes) { throw invalid(); }
            index++;
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("CA command component is invalid");
    }
}
