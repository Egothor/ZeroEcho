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
package zeroecho.pki.api.confirmation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Immutable issuance-profile policy for credential confirmation.
 *
 * <p>The commitment is a domain-separated canonical SHA-256 digest of the
 * disclosure policy, exact confirmation window, and exact proof-suite
 * reference. Runtime and client-provided state are deliberately excluded.</p>
 *
 * @param disclosurePolicy disclosure state frozen by issuance
 * @param confirmationWindow positive confirmation interval, at most 100 years
 * @param proofSuite exact proof-suite configuration frozen by issuance
 */
public record CredentialConfirmationPolicy(ConfirmationDisclosurePolicy disclosurePolicy,
        Duration confirmationWindow, ConfirmationProofSuiteRef proofSuite) {
    /** Largest accepted confirmation window. */
    public static final Duration MAXIMUM_CONFIRMATION_WINDOW = Duration.ofDays(36_525L);
    private static final byte[] DOMAIN =
            "zeroecho:credential-confirmation-policy:v1".getBytes(StandardCharsets.US_ASCII);

    /** Validates the complete immutable policy. */
    public CredentialConfirmationPolicy {
        Objects.requireNonNull(disclosurePolicy, "disclosurePolicy");
        Objects.requireNonNull(confirmationWindow, "confirmationWindow");
        Objects.requireNonNull(proofSuite, "proofSuite");
        if (confirmationWindow.isZero() || confirmationWindow.isNegative()
                || confirmationWindow.compareTo(MAXIMUM_CONFIRMATION_WINDOW) > 0) {
            throw new IllegalArgumentException("Confirmation window is outside the supported range");
        }
    }

    /**
     * Returns the canonical lowercase hexadecimal SHA-256 policy commitment.
     *
     * @return 64-character policy commitment
     */
    public String configurationCommitment() {
        MessageDigest digest = sha256();
        text(digest, DOMAIN);
        integer32(digest, disclosurePolicy.code());
        integer64(digest, confirmationWindow.getSeconds());
        integer32(digest, confirmationWindow.getNano());
        text(digest, proofSuite.suiteId().getBytes(StandardCharsets.US_ASCII));
        text(digest, proofSuite.configurationCommitment().getBytes(StandardCharsets.US_ASCII));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void text(MessageDigest digest, byte[] value) {
        integer32(digest, value.length);
        digest.update(value);
    }

    private static void integer32(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static void integer64(MessageDigest digest, long value) {
        digest.update((byte) (value >>> 56));
        digest.update((byte) (value >>> 48));
        digest.update((byte) (value >>> 40));
        digest.update((byte) (value >>> 32));
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Required SHA-256 digest is unavailable", impossible);
        }
    }
}
