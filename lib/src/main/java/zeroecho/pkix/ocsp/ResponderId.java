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
package zeroecho.pkix.ocsp;

import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

/**
 * An OCSP {@code ResponderID} (RFC 6960): the responder identity, either by name
 * or by key hash.
 */
public sealed interface ResponderId permits ResponderId.ByName, ResponderId.ByKey {

    /**
     * Responder identified by its distinguished name.
     *
     * @param name the responder DN
     */
    record ByName(X500Principal name) implements ResponderId {
        /** Canonicalizing constructor. */
        public ByName {
            Objects.requireNonNull(name, "name");
        }
    }

    /**
     * Responder identified by the SHA-1 hash of its public key.
     *
     * @param keyHash the responder key hash
     */
    record ByKey(byte[] keyHash) implements ResponderId {
        /** Canonicalizing constructor. */
        public ByKey {
            Objects.requireNonNull(keyHash, "keyHash");
            keyHash = keyHash.clone();
        }

        /**
         * Returns the responder key hash without exposing the record's internal array.
         *
         * @return a defensive copy of the responder public-key hash
         */
        @Override
        public byte[] keyHash() {
            return keyHash.clone();
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof ByKey that && Arrays.equals(keyHash, that.keyHash);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(keyHash);
        }

        @Override
        public String toString() {
            return "ByKey[keyHash=" + keyHash.length + " bytes]";
        }
    }

    /**
     * Creates a name-based responder id.
     *
     * @param name the responder DN
     * @return the responder id
     */
    static ResponderId byName(X500Principal name) {
        return new ByName(name);
    }

    /**
     * Creates a key-hash-based responder id.
     *
     * @param keyHash the responder key hash
     * @return the responder id
     */
    static ResponderId byKey(byte[] keyHash) {
        return new ByKey(keyHash);
    }
}
