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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Reduced immutable administrative view of one pending credential confirmation.
 *
 * <p>The view deliberately excludes certificate content, requester identity,
 * proof material, challenge state, and cryptographic-policy commitments.</p>
 *
 * @param credentialId canonical credential identity
 * @param authorityId exact logical issuing authority
 * @param profileId exact logical issuance profile
 * @param confirmationReviewAt authoritative confirmation-review boundary
 * @param initialDisclosurePolicy disclosure policy frozen at initialization
 */
public record CredentialConfirmationReview(PkiId credentialId, PkiId authorityId,
        String profileId, Instant confirmationReviewAt,
        ConfirmationDisclosurePolicy initialDisclosurePolicy) {
    /** Maximum strict UTF-8 byte length of an authority identifier in this view. */
    @SuppressWarnings("PMD.LongVariable")
    public static final int MAXIMUM_AUTHORITY_ID_UTF8_BYTES = 256;
    /** Maximum strict UTF-8 byte length of a profile identifier in this view. */
    @SuppressWarnings("PMD.LongVariable")
    public static final int MAXIMUM_PROFILE_ID_UTF8_BYTES = 256;

    /** Validates the bounded reduced view. */
    public CredentialConfirmationReview {
        credentialId = CredentialConfirmationInitialization.requireCanonicalCredentialId(credentialId);
        authorityId = requireTextId(authorityId, MAXIMUM_AUTHORITY_ID_UTF8_BYTES, "authorityId");
        profileId = requireText(profileId, MAXIMUM_PROFILE_ID_UTF8_BYTES, "profileId");
        confirmationReviewAt = requireInstant(confirmationReviewAt);
        Objects.requireNonNull(initialDisclosurePolicy, "initialDisclosurePolicy");
    }

    private static PkiId requireTextId(PkiId value, int maximumBytes, String name) {
        PkiId exact = Objects.requireNonNull(value, name);
        requireText(exact.value(), maximumBytes, name);
        return exact;
    }

    private static String requireText(String value, int maximumBytes, String name) {
        Objects.requireNonNull(value, name);
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (value.isBlank() || encoded.length > maximumBytes
                || !value.equals(new String(encoded, StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException(name + " is not bounded strict UTF-8");
        }
        return value;
    }

    private static Instant requireInstant(Instant value) {
        Instant exact = Objects.requireNonNull(value, "confirmationReviewAt");
        if (exact.getEpochSecond() < 0L || exact.getEpochSecond() > 253_402_300_799L) {
            throw new IllegalArgumentException("confirmationReviewAt is outside the supported UTC range");
        }
        return exact;
    }
}
