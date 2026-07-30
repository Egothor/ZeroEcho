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

import java.util.List;
import java.util.Objects;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;

/**
 * Immutable gate-produced end-entity certificate construction authority.
 *
 * <p>
 * The constructor is package-private so only the core profile validator can
 * create an instance. The type carries no generic attributes, raw CSR extension
 * bytes, requester serial, or issuer-controlled material.
 * </p>
 */
@SuppressWarnings({ "PMD.DataClass", "PMD.ExcessiveParameterList" })
public final class ValidatedCertificateRequest {
    private final PkiId issuerCaId;
    private final CertificateProfileRef profileReference;
    private final SubjectRef subjectRef;
    private final List<SubjectRdn> subjectRdns;
    private final List<SubjectAlternativeName> subjectAlternativeNames;
    private final boolean subjectAlternativeNameCritical;
    private final EncodedObject exactPublicKey;
    private final Validity validity;
    private final Set<LeafKeyUsage> keyUsages;
    private final Set<ExtendedKeyUsageId> extendedKeyUsages;
    private final boolean keyUsageCritical;
    private final boolean extendedKeyUsageCritical;
    private final boolean basicConstraintsCritical;

    /* default */ ValidatedCertificateRequest(PkiId issuerCaId, CertificateProfileRef profileReference,
            SubjectRef subjectRef, List<SubjectRdn> subjectRdns, List<SubjectAlternativeName> subjectAlternativeNames,
            boolean subjectAlternativeNameCritical, EncodedObject exactPublicKey, Validity validity,
            Set<LeafKeyUsage> keyUsages, Set<ExtendedKeyUsageId> extendedKeyUsages, boolean keyUsageCritical,
            boolean extendedKeyUsageCritical, boolean basicConstraintsCritical) {
        this.issuerCaId = Objects.requireNonNull(issuerCaId, "issuerCaId");
        this.profileReference = Objects.requireNonNull(profileReference, "profileReference");
        this.subjectRef = Objects.requireNonNull(subjectRef, "subjectRef");
        this.subjectRdns = List.copyOf(subjectRdns);
        this.subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
        this.subjectAlternativeNameCritical = subjectAlternativeNameCritical;
        this.exactPublicKey = new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
        this.validity = Objects.requireNonNull(validity, "validity");
        this.keyUsages = Set.copyOf(keyUsages);
        this.extendedKeyUsages = Set.copyOf(extendedKeyUsages);
        this.keyUsageCritical = keyUsageCritical;
        this.extendedKeyUsageCritical = extendedKeyUsageCritical;
        this.basicConstraintsCritical = basicConstraintsCritical;
    }

    /** @return authoritative issuer CA identifier */
    public PkiId issuerCaId() {
        return issuerCaId;
    }

    /** @return exact selected active profile reference */
    public CertificateProfileRef profileReference() {
        return profileReference;
    }

    /** @return selected active profile identifier */
    public String profileId() {
        return profileReference.profileId();
    }

    /** @return canonical inventory subject reference */
    public SubjectRef subjectRef() {
        return subjectRef;
    }

    /** @return ordered immutable approved subject RDNs */
    public List<SubjectRdn> subjectRdns() {
        return subjectRdns;
    }

    /** @return ordered immutable approved SAN entries */
    public List<SubjectAlternativeName> subjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    /** @return profile-derived SAN criticality */
    public boolean subjectAlternativeNameCritical() {
        return subjectAlternativeNameCritical;
    }

    /** @return defensive copy of the exact proof-bound SPKI */
    public EncodedObject exactPublicKey() {
        return new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
    }

    /** @return approved issuer-time validity */
    public Validity validity() {
        return validity;
    }

    /** @return exact profile-derived key usages */
    public Set<LeafKeyUsage> keyUsages() {
        return keyUsages;
    }

    /** @return exact profile-derived extended key usages */
    public Set<ExtendedKeyUsageId> extendedKeyUsages() {
        return extendedKeyUsages;
    }

    /** @return key-usage criticality */
    public boolean keyUsageCritical() {
        return keyUsageCritical;
    }

    /** @return extended-key-usage criticality */
    public boolean extendedKeyUsageCritical() {
        return extendedKeyUsageCritical;
    }

    /** @return leaf BasicConstraints criticality */
    public boolean basicConstraintsCritical() {
        return basicConstraintsCritical;
    }
}
