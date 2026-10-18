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
package zeroecho.pki.application;

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.EndEntityProfileBinding;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.store.PkiStore;

/** Store-backed scope resolver that exposes identifiers only. */
final class DefaultPkiResourceScopeResolver implements PkiResourceScopeResolver {
    private final PkiStore store;
    private final Runnable openCheck;

    /* default */ DefaultPkiResourceScopeResolver(PkiStore store, Runnable openCheck) {
        this.store = Objects.requireNonNull(store, "store");
        this.openCheck = Objects.requireNonNull(openCheck, "openCheck");
    }

    @Override
    public Optional<CredentialScope> credentialScope(PkiId credentialId) {
        openCheck.run();
        return store.getCredential(Objects.requireNonNull(credentialId, "credentialId"))
                .map(credential -> {
                    if (!(credential.profileBinding() instanceof EndEntityProfileBinding binding)) {
                        throw new IllegalStateException("Credential is not bound to an end-entity profile");
                    }
                    return new CredentialScope(credential.issuerRef().caId(),
                            binding.reference().profileId());
                });
    }

    @Override
    public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) {
        openCheck.run();
        return store.getStatusObject(Objects.requireNonNull(statusObjectId, "statusObjectId"))
                .map(StatusObject::issuerCaId);
    }

    @Override
    public Optional<CredentialScope> holdCredentialScope(PkiId credentialId) {
        openCheck.run();
        return store.getCredential(Objects.requireNonNull(credentialId, "credentialId"))
                .map(credential -> new CredentialScope(credential.issuerRef().caId(),
                        switch (credential.profileBinding()) {
                            case EndEntityProfileBinding binding -> binding.reference().profileId();
                            case CaProfileBinding binding -> binding.reference().profileId();
                        }));
    }

    @Override
    public Optional<PkiId> publicationAuthority(PkiId publicationId) {
        openCheck.run();
        Optional<PublicationRecord> record = store.getPublicationRecord(
                Objects.requireNonNull(publicationId, "publicationId"));
        return record.flatMap(value -> value.sourceType() == PublicationSourceType.CREDENTIAL
                ? credentialScope(value.sourceId()).map(CredentialScope::authorityId)
                : statusObjectAuthority(value.sourceId()));
    }
}
