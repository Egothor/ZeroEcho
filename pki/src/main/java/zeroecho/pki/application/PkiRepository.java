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
package zeroecho.pki.application;

import java.util.List;
import java.util.Optional;
import java.math.BigInteger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.status.StatusObject;

/** Read-only authoritative repository facade owned by one {@link PkiSession}. */
public interface PkiRepository {
    /** Returns an exact logical authority. */
    Optional<CaRecord> authority(PkiId authorityId);
    /** Returns a finite canonical authority page after an optional exclusive key. */
    List<CaRecord> authorities(Optional<PkiId> afterAuthorityId, int limit);
    /** Returns an exact issuer generation. */
    Optional<IssuerGeneration> issuer(PkiId issuerId);
    /** Returns an exact immutable issuer chain path. */
    Optional<IssuerChainPath> chainPath(PkiId pathId);
    /** Returns an exact credential metadata record. */
    Optional<Credential> credential(PkiId credentialId);
    /** Returns an exact credential through the issuer-generation/serial index. */
    default Optional<Credential> credential(PkiId issuerId, BigInteger serial) {
        java.util.Objects.requireNonNull(issuerId, "issuerId");
        java.util.Objects.requireNonNull(serial, "serial");
        return Optional.empty();
    }
    /** Returns an exact status-object metadata record. */
    Optional<StatusObject> statusObject(PkiId statusObjectId);
    /** Opens validated immutable certificate content. */
    PkiRepositoryContent openCredential(PkiId credentialId);
    /** Opens validated immutable status-object content. */
    PkiRepositoryContent openStatusObject(PkiId statusObjectId);
}
