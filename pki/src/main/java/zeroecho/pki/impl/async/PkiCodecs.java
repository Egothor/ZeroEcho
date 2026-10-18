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
package zeroecho.pki.impl.async;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.util.async.codec.IdCodec;

/**
 * PKI-specific codecs used to instantiate the generic async bus.
 */
public final class PkiCodecs {

    private PkiCodecs() {
        throw new AssertionError("No instances.");
    }

    /**
     * Codec for {@link PkiId}.
     */
    public static final IdCodec<PkiId> PKI_ID = new IdCodec<>() {
        @Override
        public String encode(PkiId value) {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
            return value.value();
        }

        @Override
        public PkiId decode(String token) {
            return new PkiId(token);
        }
    };

    /**
     * Codec for {@link Principal}.
     *
     * <p>
     * Encoded form: {@code type:name}. Both parts are treated as non-secret
     * identifiers.
     * </p>
     */
    public static final IdCodec<Principal> PRINCIPAL = new IdCodec<>() {
        @Override
        public String encode(Principal value) {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
            return value.type() + ":" + value.name();
        }

        @Override
        public Principal decode(String token) {
            int idx = token.indexOf(':');
            if (idx <= 0 || idx >= token.length() - 1) {
                throw new IllegalArgumentException("Invalid principal token.");
            }
            String type = token.substring(0, idx);
            String name = token.substring(idx + 1);
            return new Principal(type, name);
        }
    };

    /**
     * Codec for endpoint ids represented as strings.
     */
    public static final IdCodec<String> STRING = new IdCodec<>() {
        @Override
        public String encode(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("value must not be null/blank");
            }
            return value;
        }

        @Override
        public String decode(String token) {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null/blank");
            }
            return token;
        }
    };
}
