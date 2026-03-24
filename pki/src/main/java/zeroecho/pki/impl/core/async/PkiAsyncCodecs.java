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
package zeroecho.pki.impl.core.async;

import java.util.Base64;
import java.util.Objects;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.util.async.codec.IdCodec;
import zeroecho.pki.util.async.codec.ResultCodec;

/**
 * Collection of PKI-specific codecs used by the durable asynchronous
 * orchestration layer.
 *
 * <p>
 * These codecs adapt PKI domain values such as {@link PkiId},
 * {@link Principal}, and {@link EncodedObject} to the string-oriented
 * persistence contracts used by {@code zeroecho.pki.util.async}. They provide
 * stable and explicit text representations suitable for append-only stores,
 * durable bus records, and restart-safe workflow reconstruction.
 * </p>
 *
 * <p>
 * The codecs in this utility class are intentionally simple and deterministic.
 * They do not perform schema negotiation, versioning, or backward-compatibility
 * handling beyond the currently encoded textual forms.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>These codecs serialize identifiers and payload objects; callers must
 * avoid exposing persisted tokens in unsafe logs when those tokens may carry
 * operationally sensitive data.</li>
 * <li>{@link EncodedObjectResultCodec} persists payload bytes in Base64URL form
 * and therefore does not provide confidentiality by itself.</li>
 * <li>{@link PrincipalCodec} uses a simple delimiter-based representation and
 * therefore assumes that the encoded principal token is consumed only by
 * trusted runtime components honoring the same contract.</li>
 * </ul>
 */
public final class PkiAsyncCodecs { // NOPMD

    private PkiAsyncCodecs() {
        // utility
    }

    /**
     * Codec for representing {@link PkiId} values by their stable string form.
     *
     * <p>
     * This codec performs no transformation beyond delegating to
     * {@link PkiId#value()}. It is therefore appropriate only when the persisted
     * async store is expected to preserve the exact identifier value unchanged.
     * </p>
     */
    public static final class PkiIdCodec implements IdCodec<PkiId> {

        /**
         * Encodes the identifier as its stable string value.
         *
         * @param value identifier to encode; must not be {@code null}
         * @return stable string representation of the identifier
         * @throws NullPointerException if {@code value} is {@code null}
         */
        @Override
        public String encode(PkiId value) {
            Objects.requireNonNull(value, "value");
            return value.value();
        }

        /**
         * Decodes a persisted identifier token back into a {@link PkiId}.
         *
         * @param token persisted token; must not be {@code null} or blank
         * @return decoded PKI identifier
         * @throws IllegalArgumentException if {@code token} is {@code null} or blank
         */
        @Override
        public PkiId decode(String token) {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null/blank");
            }
            return new PkiId(token);
        }
    }

    /**
     * Codec for representing {@link Principal} values as {@code type:name}.
     *
     * <p>
     * The first colon character acts as the structural delimiter between the
     * principal type and principal name. The current implementation therefore
     * assumes that the persisted token can be parsed unambiguously under that rule.
     * </p>
     */
    public static final class PrincipalCodec implements IdCodec<Principal> {

        /**
         * Encodes the principal as {@code type:name}.
         *
         * @param value principal to encode; must not be {@code null}
         * @return encoded principal token
         * @throws NullPointerException if {@code value} is {@code null}
         */
        @Override
        public String encode(Principal value) {
            Objects.requireNonNull(value, "value");
            return value.type() + ":" + value.name();
        }

        /**
         * Decodes a principal token in {@code type:name} form.
         *
         * @param token persisted principal token; must not be {@code null} or blank
         * @return decoded principal
         * @throws IllegalArgumentException if {@code token} is {@code null}, blank, or
         *                                  does not contain a valid delimiter-separated
         *                                  form
         */
        @Override
        public Principal decode(String token) {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null/blank");
            }
            int idx = token.indexOf(':');
            if (idx <= 0 || idx == token.length() - 1) {
                throw new IllegalArgumentException("Invalid Principal token");
            }
            String type = token.substring(0, idx);
            String name = token.substring(idx + 1);
            return new Principal(type, name);
        }
    }

    /**
     * Trivial identity codec for endpoint identifiers.
     *
     * <p>
     * The endpoint identifier is persisted unchanged and therefore must already be
     * in a durable, text-safe form when supplied to this codec.
     * </p>
     */
    public static final class StringIdCodec implements IdCodec<String> {

        /**
         * Returns the endpoint identifier unchanged.
         *
         * @param value endpoint identifier; must not be {@code null} or blank
         * @return unchanged endpoint identifier
         * @throws IllegalArgumentException if {@code value} is {@code null} or blank
         */
        @Override
        public String encode(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("value must not be null/blank");
            }
            return value;
        }

        /**
         * Returns the persisted endpoint token unchanged.
         *
         * @param token persisted endpoint token; must not be {@code null} or blank
         * @return unchanged endpoint identifier
         * @throws IllegalArgumentException if {@code token} is {@code null} or blank
         */
        @Override
        public String decode(String token) {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null/blank");
            }
            return token;
        }
    }

    /**
     * Result codec for persisting {@link EncodedObject} values as
     * {@code &lt;ENCODING&gt;:&lt;base64url-without-padding&gt;}.
     *
     * <p>
     * The codec stores the {@link Encoding} symbolic name and the raw bytes in
     * Base64URL form without padding. The {@code persists} constructor flag
     * controls whether the surrounding async runtime should persist results at all.
     * </p>
     */
    public static final class EncodedObjectResultCodec implements ResultCodec<EncodedObject> {

        private final boolean persists;

        /**
         * Creates the result codec.
         *
         * @param persists whether the surrounding async runtime should persist encoded
         *                 results produced through this codec
         */
        public EncodedObjectResultCodec(boolean persists) {
            this.persists = persists;
        }

        /**
         * Indicates whether async results should be durably persisted.
         *
         * @return {@code true} when results should be persisted, otherwise
         *         {@code false}
         */
        @Override
        public boolean persistsResults() {
            return persists;
        }

        /**
         * Encodes an {@link EncodedObject} into a text-safe durable form.
         *
         * @param value encoded object to persist; must not be {@code null}
         * @return token in {@code encoding:base64url} form
         * @throws NullPointerException if {@code value} is {@code null}
         */
        @Override
        public String encode(EncodedObject value) {
            Objects.requireNonNull(value, "value");
            String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(value.bytes());
            return value.encoding().name() + ":" + b64;
        }

        /**
         * Decodes a previously persisted {@link EncodedObject} token.
         *
         * @param token persisted token in {@code encoding:base64url} form; must not be
         *              {@code null} or blank
         * @return decoded encoded object
         * @throws IllegalArgumentException if {@code token} is {@code null}, blank,
         *                                  malformed, or contains an unknown encoding
         *                                  name
         */
        @Override
        public EncodedObject decode(String token) {
            if (token == null || token.isBlank()) {
                throw new IllegalArgumentException("token must not be null/blank");
            }
            int idx = token.indexOf(':');
            if (idx <= 0 || idx == token.length() - 1) {
                throw new IllegalArgumentException("Invalid EncodedObject token");
            }
            Encoding enc = Encoding.valueOf(token.substring(0, idx));
            byte[] bytes = Base64.getUrlDecoder().decode(token.substring(idx + 1));
            return new EncodedObject(enc, bytes);
        }
    }
}
