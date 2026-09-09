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

import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;

/**
 * Durable, auditable supersession lineage between a superseding credential and
 * the predecessor it replaces.
 *
 * <p>
 * When a credential is produced by {@code replace} or {@code reissue}, the newly
 * issued credential carries a forward pointer to the predecessor it supersedes.
 * The pointer lives in credential metadata attributes, not in the signed
 * certificate bytes, so it never changes the content-addressed credential
 * identity or the signing path. Combined with permanent revocation of the
 * predecessor under {@link zeroecho.pki.api.revocation.RevocationReason#SUPERSEDED},
 * this yields a queryable, enterprise-grade certificate lineage.
 * </p>
 */
public final class CredentialLineage {

    /** Metadata attribute carrying the predecessor credential identity superseded by this credential. */
    public static final AttributeId SUPERSEDES_CREDENTIAL_ID =
            new AttributeId("urn:zeroecho:pki:supersedes-credential-id:v1");

    /** Metadata attribute carrying the operator-declared supersession reason token. */
    public static final AttributeId SUPERSESSION_REASON =
            new AttributeId("urn:zeroecho:pki:supersession-reason:v1");

    private CredentialLineage() {
    }

    /**
     * Reads the predecessor credential identity a credential supersedes, if any.
     *
     * @param attributes credential metadata attributes; must not be {@code null}
     * @return predecessor credential id, or empty when the credential supersedes nothing
     */
    public static Optional<PkiId> supersededCredentialId(AttributeSet attributes) {
        return attributes.get(SUPERSEDES_CREDENTIAL_ID)
                .filter(AttributeValue.StringValue.class::isInstance)
                .map(AttributeValue.StringValue.class::cast)
                .map(AttributeValue.StringValue::value)
                .map(PkiId::new);
    }
}
