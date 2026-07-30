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
package zeroecho.sdk.guard;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

import zeroecho.sdk.util.Kdf;

/**
 * Defines the single KEM-recipient KEK derivation contract.
 */
final class KemKeyDerivation {
    private static final String INFO_PREFIX = "KDF:";

    private KemKeyDerivation() {
    }

    /**
     * Derives a KEK bound to the KEM algorithm identifier.
     *
     * @param sharedSecret KEM shared secret
     * @param salt         HKDF salt
     * @param algorithmId  canonical KEM algorithm identifier
     * @param outputBytes  requested KEK size
     * @return newly allocated KEK bytes
     * @throws GeneralSecurityException if HKDF fails
     */
    /* default */ static byte[] derive(byte[] sharedSecret, byte[] salt, String algorithmId, int outputBytes)
            throws GeneralSecurityException {
        Objects.requireNonNull(algorithmId, "algorithmId must not be null");
        byte[] info = (INFO_PREFIX + algorithmId).getBytes(StandardCharsets.US_ASCII);
        return Kdf.hkdfSha256(sharedSecret, salt, info, outputBytes);
    }
}
