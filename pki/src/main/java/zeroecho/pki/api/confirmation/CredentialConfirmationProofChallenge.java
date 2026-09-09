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
package zeroecho.pki.api.confirmation;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

/**
 * Immutable safe presentation of one issued credential-confirmation proof challenge.
 *
 * <p>The challenge-record commitment inside {@code proofCas} is a non-secret
 * correlation and compare-and-set coordinate. Possession of it grants no
 * authorization, disclosure access, or evidence of key possession.</p>
 *
 * @param proofCas exact pending lifecycle and issued challenge correlation coordinates
 * @param proofSuiteBinding exact suite binding used to construct the presentation
 * @param expiresAt authoritative whole-second challenge expiry
 * @param maximumResponseBytes inclusive response bound from 1 through 16384 bytes
 * @param presentation non-empty suite-defined presentation, at most 2048 bytes
 */
public record CredentialConfirmationProofChallenge(CredentialConfirmationProofCas proofCas,
        ConfirmationProofSuiteBinding proofSuiteBinding, Instant expiresAt,
        int maximumResponseBytes, byte[] presentation) {
    private static final long MAXIMUM_EPOCH_SECOND = 253_402_300_799L;

    /**
     * Validates exact public coordinates and defensively owns presentation bytes.
     *
     * @throws NullPointerException if a reference component is {@code null}
     * @throws IllegalArgumentException if an expiry or byte bound is invalid
     */
    public CredentialConfirmationProofChallenge {
        Objects.requireNonNull(proofCas, "proofCas");
        Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
        expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        if (expiresAt.getEpochSecond() < 0L || expiresAt.getEpochSecond() > MAXIMUM_EPOCH_SECOND
                || expiresAt.getNano() != 0) {
            throw new IllegalArgumentException("Proof challenge expiry is not a supported whole-second instant");
        }
        if (maximumResponseBytes < 1
                || maximumResponseBytes > KeyPossessionProofResponse.MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Proof challenge response bound is outside the supported range");
        }
        if (presentation == null || presentation.length == 0
                || presentation.length > KeyPossessionProofPresentation.MAXIMUM_BYTES) {
            throw new IllegalArgumentException("Proof challenge presentation length is outside the supported range");
        }
        presentation = presentation.clone();
    }

    /**
     * Returns a defensive copy of the suite-defined presentation.
     *
     * @return challenge presentation bytes
     */
    @Override
    public byte[] presentation() {
        return presentation.clone();
    }

    /** Compares presentation bytes by content. */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CredentialConfirmationProofChallenge candidate)) {
            return false;
        }
        return maximumResponseBytes == candidate.maximumResponseBytes
                && proofCas.equals(candidate.proofCas)
                && proofSuiteBinding.equals(candidate.proofSuiteBinding)
                && expiresAt.equals(candidate.expiresAt)
                && Arrays.equals(presentation, candidate.presentation);
    }

    /** Returns a content-based hash code for every component. */
    @Override
    public int hashCode() {
        return 31 * Objects.hash(proofCas, proofSuiteBinding, expiresAt, maximumResponseBytes)
                + Arrays.hashCode(presentation);
    }

    /** Returns a structural description without presentation bytes. */
    @Override
    public String toString() {
        return "CredentialConfirmationProofChallenge[proofCas=" + proofCas
                + ", proofSuiteBinding=" + proofSuiteBinding + ", expiresAt=" + expiresAt
                + ", maximumResponseBytes=" + maximumResponseBytes + ", presentation=<"
                + presentation.length + " bytes>]";
    }
}
