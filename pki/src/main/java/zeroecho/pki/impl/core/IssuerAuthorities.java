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
package zeroecho.pki.impl.core;

import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.spi.store.PkiStore;

/** Exact issuer-generation and chain-path composition shared by PKI services. */
final class IssuerAuthorities {
    private IssuerAuthorities() {
        // utility
    }

    /* default */ static IssuerGeneration current(PkiStore store, CaRecord authority) {
        IssuerGeneration generation = store.getIssuerGeneration(authority.currentIssuanceIssuerId())
                .orElseThrow(() -> new PkiException("Current issuer generation not found"));
        if (!authority.caId().equals(generation.authorityId()) || generation.state() != IssuerGenerationState.ACTIVE) {
            throw new PkiException("Current issuer generation unavailable");
        }
        return generation;
    }

    /* default */ static IssuerChainPath issuancePath(PkiStore store, CaRecord authority) {
        IssuerChainPath path = store.getIssuerChainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new PkiException("Issuance chain path not found"));
        if (!authority.caId().equals(path.authorityId())
                || !authority.currentIssuanceIssuerId().equals(path.issuerId())) {
            throw new PkiException("Issuance chain selection mismatch");
        }
        return path;
    }

    /* default */ static Credential currentCredential(PkiStore store, CaRecord authority) {
        IssuerGeneration generation = current(store, authority);
        return store.getCredential(generation.credentialId())
                .orElseThrow(() -> new PkiException("Current issuer credential not found"));
    }

    /* default */ static IssuerGeneration generation(PkiId authorityId, zeroecho.pki.api.KeyRef keyRef,
            Credential credential) {
        CertificateProfileRef profile = ((CaProfileBinding) credential.profileBinding()).reference();
        String profileCommitment = HexFormat.of().formatHex(profile.canonicalSha256());
        return new IssuerGeneration(IssuerGeneration.idFor(authorityId, credential.credentialId()), authorityId,
                credential.credentialId(), keyRef, IssuerGenerationState.ACTIVE, profileCommitment,
                profileCommitment);
    }

    /* default */ static Credential withIssuer(Credential credential, IssuerRef issuerRef) {
        Objects.requireNonNull(credential, "credential");
        return new Credential(credential.credentialId(), credential.formatId(), issuerRef, credential.subjectRef(),
                credential.validity(), credential.serialOrUniqueId(), credential.publicKeyId(),
                credential.profileBinding(), credential.status(), credential.content(), credential.attributes());
    }

    /* default */ static IssuerChainPath rootPath(PkiId authorityId, PkiId issuerId, PkiId credentialId) {
        return IssuerChainPath.create(authorityId, issuerId, List.of(credentialId));
    }

    /* default */ static IssuerChainPath childPath(PkiId authorityId, PkiId issuerId, PkiId credentialId,
            IssuerChainPath parentPath) {
        List<PkiId> credentials = new java.util.ArrayList<>();
        credentials.add(credentialId);
        credentials.addAll(parentPath.orderedCredentialIds());
        return IssuerChainPath.create(authorityId, issuerId, credentials);
    }
}
