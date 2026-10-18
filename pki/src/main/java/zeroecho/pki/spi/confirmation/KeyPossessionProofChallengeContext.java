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
package zeroecho.pki.spi.confirmation;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;

/**
 * Immutable authoritative persisted context for stateless key-possession challenge work.
 *
 * <p>This value contains no certificate, public key, store, mutation capability,
 * actor, owner, requester, proof response, or verification result. The persisted
 * nonce is copied on input and output.</p>
 *
 * @param realm exact persisted realm binding
 * @param serverAudience exact strict UTF-8 audience, 1 through 512 bytes and without ISO controls
 * @param credentialId exact credential identity
 * @param proofSuiteBinding exact persisted proof-suite binding
 * @param rawChallenge exact persisted 32-byte nonce
 * @param expiresAt authoritative whole-second challenge expiry in the supported UTC range
 */
public record KeyPossessionProofChallengeContext(ConfirmationRealmBinding realm,
        String serverAudience, PkiId credentialId,
        ConfirmationProofSuiteBinding proofSuiteBinding, byte[] rawChallenge,
        Instant expiresAt) {
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;

    /**
     * Validates all bounded authoritative coordinates and defensively owns the nonce.
     *
     * @throws NullPointerException if a reference coordinate is {@code null}
     * @throws IllegalArgumentException if an audience, identity, time, or nonce bound is invalid
     */
    public KeyPossessionProofChallengeContext {
        Objects.requireNonNull(realm, "realm");
        serverAudience = requireServerAudience(serverAudience);
        credentialId = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        if (rawChallenge == null
                || rawChallenge.length != CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES) {
            throw new IllegalArgumentException("Proof context challenge must contain exactly 32 bytes");
        }
        rawChallenge = rawChallenge.clone();
        expiresAt = requireWholeSecondExpiry(expiresAt);
    }

    /**
     * Returns a defensive copy of the persisted nonce.
     *
     * @return exact raw challenge bytes
     */
    @Override
    public byte[] rawChallenge() {
        return rawChallenge.clone();
    }

    /** Compares nonce bytes by content. */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof KeyPossessionProofChallengeContext candidate)) {
            return false;
        }
        return realm.equals(candidate.realm)
                && serverAudience.equals(candidate.serverAudience)
                && credentialId.equals(candidate.credentialId)
                && proofSuiteBinding.equals(candidate.proofSuiteBinding)
                && Arrays.equals(rawChallenge, candidate.rawChallenge)
                && expiresAt.equals(candidate.expiresAt);
    }

    /** Returns a content-based hash code for every coordinate. */
    @Override
    public int hashCode() {
        return 31 * Objects.hash(realm, serverAudience, credentialId, proofSuiteBinding, expiresAt)
                + Arrays.hashCode(rawChallenge);
    }

    /** Returns a structural description with nonce bytes redacted. */
    @Override
    public String toString() {
        return "KeyPossessionProofChallengeContext[realm=" + realm
                + ", serverAudience=" + serverAudience + ", credentialId=" + credentialId
                + ", proofSuiteBinding=" + proofSuiteBinding
                + ", rawChallenge=<32 bytes>, expiresAt=" + expiresAt + ']';
    }

    private static String requireServerAudience(String value) {
        Objects.requireNonNull(value, "serverAudience");
        if (value.isEmpty() || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Proof context server audience is invalid");
        }
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            if (encoded.remaining() > CredentialConfirmationChallenge.MAXIMUM_SERVER_AUDIENCE_UTF8_BYTES) {
                throw new IllegalArgumentException("Proof context server audience is too long");
            }
        } catch (CharacterCodingException failure) {
            throw new IllegalArgumentException("Proof context server audience is not strict UTF-8", failure);
        }
        return value;
    }

    private static Instant requireWholeSecondExpiry(Instant value) {
        Instant exact = Objects.requireNonNull(value, "expiresAt");
        if (exact.getEpochSecond() < 0L || exact.getEpochSecond() > MAXIMUM_EPOCH_SECOND
                || exact.getNano() != 0) {
            throw new IllegalArgumentException("Proof context expiry is not a supported whole-second instant");
        }
        return exact;
    }
}
