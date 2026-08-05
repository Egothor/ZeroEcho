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
package zeroecho.pki.api.issuance;

import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Durable idempotency and frozen-selection authority for one issuance request.
 *
 * <p>The identifier is supplied by a trusted orchestration layer such as ACME.
 * It is not a credential, secret, bearer token, or operation permission. Reuse is
 * valid only when the complete command commitment and frozen PKI selection match.</p>
 *
 * @param issuanceId stable caller correlation identity
 * @param commandCommitment SHA-256 commitment of canonical safe issuance input
 * @param expectedProfile exact activated profile reference
 * @param expectedIssuerId exact issuer generation
 * @param expectedChainPathId exact issuance chain path
 * @param expectedChainPathCommitment frozen chain-path commitment
 */
public record IssuanceIntent(String issuanceId, String commandCommitment,
        CertificateProfileRef expectedProfile, PkiId expectedIssuerId,
        PkiId expectedChainPathId, String expectedChainPathCommitment) {
    /** Stable internal metadata attribute carrying the non-secret issuance identity. */
    public static final AttributeId ID_ATTRIBUTE = new AttributeId("urn:zeroecho:pki:issuance-id:v1");
    /** Stable internal metadata attribute carrying the canonical command commitment. */
    public static final AttributeId COMMITMENT_ATTRIBUTE =
            new AttributeId("urn:zeroecho:pki:issuance-command-commitment:v1");
    /** Validates the transport-neutral frozen issuance authority. */
    public IssuanceIntent {
        if (issuanceId == null || !issuanceId.matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
            throw new IllegalArgumentException("Issuance identity is invalid");
        }
        requireDigest(commandCommitment);
        Objects.requireNonNull(expectedProfile, "expectedProfile");
        Objects.requireNonNull(expectedIssuerId, "expectedIssuerId");
        Objects.requireNonNull(expectedChainPathId, "expectedChainPathId");
        requireDigest(expectedChainPathCommitment);
    }

    private static void requireDigest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Issuance commitment is invalid");
        }
    }
}
