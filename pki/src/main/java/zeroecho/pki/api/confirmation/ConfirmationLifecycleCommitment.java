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
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/** Canonical domain-separated SHA-256 commitment encoder for lifecycle record version 2. */
final class ConfirmationLifecycleCommitment {
    private static final byte[] DOMAIN =
            "zeroecho:credential-confirmation-lifecycle:v2".getBytes(StandardCharsets.UTF_8);

    private ConfirmationLifecycleCommitment() { }

    /* default */ static String calculate(PkiId credentialId, long revision,
            ConfirmationDisclosurePolicy initialPolicy,
            String initialPolicyCommitment, boolean confirmationRequired, Instant confirmationReviewAt,
            ConfirmationProofSuiteRef proofSuite, Optional<String> consumedChallengeCommitment,
            Optional<Instant> confirmedAt) {
        MessageDigest digest = sha256();
        text(digest, DOMAIN);
        text(digest, credentialId.value());
        integer64(digest, revision);
        integer32(digest, initialPolicy.code());
        text(digest, initialPolicyCommitment);
        code(digest, confirmationRequired ? 1 : 0);
        instant(digest, confirmationReviewAt);
        text(digest, proofSuite.suiteId());
        text(digest, proofSuite.configurationCommitment());
        code(digest, consumedChallengeCommitment.isPresent() ? 1 : 0);
        consumedChallengeCommitment.ifPresent(value -> text(digest, value));
        code(digest, confirmedAt.isPresent() ? 1 : 0);
        confirmedAt.ifPresent(value -> instant(digest, value));
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void text(MessageDigest digest, String value) {
        text(digest, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void text(MessageDigest digest, byte[] value) {
        integer32(digest, value.length);
        digest.update(value);
    }

    private static void instant(MessageDigest digest, Instant value) {
        integer64(digest, value.getEpochSecond());
        integer32(digest, value.getNano());
    }

    private static void code(MessageDigest digest, int value) {
        digest.update((byte) value);
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
