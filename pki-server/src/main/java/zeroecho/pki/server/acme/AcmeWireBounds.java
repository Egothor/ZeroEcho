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
package zeroecho.pki.server.acme;

import java.net.URI;
import java.util.Objects;

import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

/** Exact bounded ACME wire-size calculations shared by configuration and transport. */
public final class AcmeWireBounds {
    /** Maximum canonical unpadded Base64url proof-response characters. */
    public static final int MAX_PROOF_B64URL_CHARS =
            base64UrlLength(KeyPossessionProofResponse.MAXIMUM_BYTES);

    private static final int MAXIMUM_ALIAS_CHARACTERS = 63;
    private static final int MAXIMUM_ACME_ID_CHARACTERS = 128;
    private static final int NONCE_CHARACTERS = 43;
    private static final int ES256_SIGNATURE_CHARACTERS = 86;

    private AcmeWireBounds() {
    }

    /**
     * Returns the exact minimum listener body limit capable of carrying the
     * largest version-1 proof-completion JWS under the configured URL authority.
     *
     * @param externalBaseUri exact configured external ACME URL authority
     * @return required inclusive flattened-JWS byte limit
     * @throws NullPointerException if {@code externalBaseUri} is {@code null}
     * @throws IllegalArgumentException if the derived bound exceeds an integer
     */
    public static int minimumCompletionDocumentBytes(URI externalBaseUri) {
        URI base = Objects.requireNonNull(externalBaseUri, "externalBaseUri");
        String alias = "a".repeat(MAXIMUM_ALIAS_CHARACTERS);
        String identifier = "a".repeat(MAXIMUM_ACME_ID_CHARACTERS);
        String kid = base.resolve("/acme/" + alias + "/account/" + identifier).toASCIIString();
        String url = base.resolve("/acme/" + alias
                + "/credential-confirmation/v1/complete/" + identifier).toASCIIString();
        long protectedBytes = asciiLength("{\"alg\":\"ES256\",\"kid\":\"\",\"nonce\":\"\",\"url\":\"\"}")
                + kid.length() + NONCE_CHARACTERS + url.length();
        long payloadBytes = asciiLength("{\"expectedLifecycleRevision\":9223372036854775807,"
                + "\"expectedLifecycleRecordCommitment\":\"\","
                + "\"expectedChallengeRecordCommitment\":\"\",\"response\":\"\"}")
                + 64L + 64L + MAX_PROOF_B64URL_CHARS;
        long documentBytes = asciiLength("{\"protected\":\"\",\"payload\":\"\",\"signature\":\"\"}")
                + base64UrlLength(protectedBytes) + base64UrlLength(payloadBytes)
                + ES256_SIGNATURE_CHARACTERS;
        if (documentBytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("ACME external base URI makes the request bound unrepresentable");
        }
        return (int) documentBytes;
    }

    private static int asciiLength(String value) {
        return value.length();
    }

    private static int base64UrlLength(long bytes) {
        long complete = Math.multiplyExact(bytes / 3L, 4L);
        long remainder = bytes % 3L;
        long result = Math.addExact(complete, remainder == 0L ? 0L : remainder + 1L);
        if (result > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("ACME Base64url bound exceeds the supported range");
        }
        return (int) result;
    }
}
