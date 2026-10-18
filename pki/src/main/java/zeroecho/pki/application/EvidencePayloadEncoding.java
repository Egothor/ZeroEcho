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

package zeroecho.pki.application;

import java.nio.charset.StandardCharsets;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;

/** Bounded transport decoding shared only by typed evidence families. */
final class EvidencePayloadEncoding {
    private static final int MAXIMUM_ENCODED_BYTES = (786_432 * 4 / 3) + 4;

    private EvidencePayloadEncoding() { }

    /* default */ static AttributeSet decode(byte[] payload) {
        if (payload == null || payload.length > MAXIMUM_ENCODED_BYTES) { throw invalid(); }
        for (byte value : payload) {
            if (!(value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
                    || value >= '0' && value <= '9' || value == '-' || value == '_')) {
                throw invalid();
            }
        }
        // Bound and ASCII validation precede String/base64 allocation. The domain decoder
        // enforces canonical framing, the decoded-byte bound and attribute-entry limits.
        return DomainAttributeEncoding.decode(new String(payload, StandardCharsets.US_ASCII));
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Execution evidence payload is invalid");
    }
}
