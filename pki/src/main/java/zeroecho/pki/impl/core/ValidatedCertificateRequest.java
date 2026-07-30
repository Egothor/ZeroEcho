/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.CertificateProfileRef;
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
            SubjectRef subjectRef,
            List<SubjectRdn> subjectRdns, List<SubjectAlternativeName> subjectAlternativeNames,
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
