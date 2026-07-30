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
package zeroecho.pki.api.credential;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Issued credential with mandatory core metadata and universal attributes.
 *
 * <p>
 * The PKI core does not assume X.509 semantics. The {@code serialOrUniqueId}
 * field maps to X.509 serial numbers when applicable, but can represent another
 * framework's unique identifier.
 * </p>
 *
 * <p>
 * The {@code publicKeyId} is intended to group multiple credentials for the
 * same key (e.g., cross-signing, migrations, or parallel classical/PQC chains).
 * </p>
 *
 * @param credentialId     stable identifier for the credential (typically a
 *                         fingerprint of encoded bytes)
 * @param formatId         framework identifier
 * @param issuerRef        issuing CA reference
 * @param subjectRef       normalized subject reference
 * @param validity         validity interval
 * @param serialOrUniqueId framework-specific unique identifier (serial for
 *                         X.509)
 * @param publicKeyId      stable identifier derived from the subject public key
 * @param profileBinding   closed profile identity governing issuance
 * @param status           persisted issuance and inventory metadata; this value
 *                         is not sufficient for a trust decision because
 *                         current revocation state and evaluation time are
 *                         external runtime inputs. Security-sensitive callers
 *                         must use {@link EffectiveCredentialStatusResolver}.
 * @param encoded          encoded credential bytes
 * @param attributes       universal attribute set
 */
public record Credential(PkiId credentialId, FormatId formatId, IssuerRef issuerRef, SubjectRef subjectRef,
        Validity validity, String serialOrUniqueId, PkiId publicKeyId, CredentialProfileBinding profileBinding,
        CredentialStatus status, EncodedObject encoded, AttributeSet attributes) {

    /**
     * Creates a credential record.
     *
     * @throws IllegalArgumentException if mandatory inputs are invalid
     */
    public Credential {
        if (credentialId == null) {
            throw new IllegalArgumentException("credentialId must not be null");
        }
        if (formatId == null) {
            throw new IllegalArgumentException("formatId must not be null");
        }
        if (issuerRef == null) {
            throw new IllegalArgumentException("issuerRef must not be null");
        }
        if (subjectRef == null) {
            throw new IllegalArgumentException("subjectRef must not be null");
        }
        if (validity == null) {
            throw new IllegalArgumentException("validity must not be null");
        }
        if (serialOrUniqueId == null || serialOrUniqueId.isBlank()) {
            throw new IllegalArgumentException("serialOrUniqueId must not be null/blank");
        }
        if (publicKeyId == null) {
            throw new IllegalArgumentException("publicKeyId must not be null");
        }
        if (profileBinding == null) {
            throw new IllegalArgumentException("profileBinding must not be null");
        }
        if (status == null) {
            throw new IllegalArgumentException("status must not be null");
        }
        if (encoded == null) {
            throw new IllegalArgumentException("encoded must not be null");
        }
        if (attributes == null) {
            throw new IllegalArgumentException("attributes must not be null");
        }
    }

}
