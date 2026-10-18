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
package zeroecho.pki.impl.core;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.issuance.IssuanceIntent;
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
    private final boolean sanCritical;
    private final EncodedObject exactPublicKey;
    private final Validity validity;
    private final Set<LeafKeyUsage> keyUsages;
    private final Set<ExtendedKeyUsageId> extendedKeyUsages;
    private final boolean keyUsageCritical;
    private final boolean extendedKeyUsageCritical;
    private final boolean basicConstraintsCritical;
    private final X509AlgorithmBindingPolicy algorithmBindingPolicy;
    private final FrozenIssuance frozenIssuance;
    private final AttributeSet executionEvidence;

    /**
     * Exact issuer generation, chain path, and optional caller idempotency binding.
     *
     * @param issuerId exact selected issuer-generation identifier
     * @param chainPathId exact selected issuer-chain-path identifier
     * @param chainPathCommitment lowercase 64-hex-character immutable path commitment
     * @param intent optional caller idempotency intent frozen for publication
     */
    public record FrozenIssuance(PkiId issuerId, PkiId chainPathId, String chainPathCommitment,
            java.util.Optional<IssuanceIntent> intent) {
        /** Validates one immutable issuance selection. */
        public FrozenIssuance {
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(chainPathId, "chainPathId");
            if (chainPathCommitment == null || !chainPathCommitment.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Chain-path commitment is invalid");
            }
            Objects.requireNonNull(intent, "intent");
        }
    }

    /* default */ ValidatedCertificateRequest(PkiId issuerCaId, CertificateProfileRef profileReference,
            SubjectRef subjectRef, List<SubjectRdn> subjectRdns, List<SubjectAlternativeName> subjectAlternativeNames,
            boolean sanCritical, EncodedObject exactPublicKey, Validity validity,
            Set<LeafKeyUsage> keyUsages, Set<ExtendedKeyUsageId> extendedKeyUsages, boolean keyUsageCritical,
            boolean extendedKeyUsageCritical, boolean basicConstraintsCritical) {
        this(issuerCaId, profileReference, subjectRef, subjectRdns, subjectAlternativeNames,
                sanCritical, exactPublicKey, validity, keyUsages, extendedKeyUsages,
                keyUsageCritical, extendedKeyUsageCritical, basicConstraintsCritical,
                X509AlgorithmBindingPolicy.standardOnly());
    }

    /* default */ ValidatedCertificateRequest(PkiId issuerCaId, CertificateProfileRef profileReference,
            SubjectRef subjectRef, List<SubjectRdn> subjectRdns, List<SubjectAlternativeName> subjectAlternativeNames,
            boolean sanCritical, EncodedObject exactPublicKey, Validity validity,
            Set<LeafKeyUsage> keyUsages, Set<ExtendedKeyUsageId> extendedKeyUsages, boolean keyUsageCritical,
            boolean extendedKeyUsageCritical, boolean basicConstraintsCritical,
            X509AlgorithmBindingPolicy algorithmBindingPolicy) {
        this.issuerCaId = Objects.requireNonNull(issuerCaId, "issuerCaId");
        this.profileReference = Objects.requireNonNull(profileReference, "profileReference");
        this.subjectRef = Objects.requireNonNull(subjectRef, "subjectRef");
        this.subjectRdns = List.copyOf(subjectRdns);
        this.subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
        this.sanCritical = sanCritical;
        this.exactPublicKey = new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
        this.validity = Objects.requireNonNull(validity, "validity");
        this.keyUsages = Set.copyOf(keyUsages);
        this.extendedKeyUsages = Set.copyOf(extendedKeyUsages);
        this.keyUsageCritical = keyUsageCritical;
        this.extendedKeyUsageCritical = extendedKeyUsageCritical;
        this.basicConstraintsCritical = basicConstraintsCritical;
        this.algorithmBindingPolicy = Objects.requireNonNull(algorithmBindingPolicy, "algorithmBindingPolicy");
        this.frozenIssuance = null;
        this.executionEvidence = SimpleAttributeSet.builder().build();
    }

    private ValidatedCertificateRequest(ValidatedCertificateRequest source, FrozenIssuance frozenIssuance) {
        this.issuerCaId = source.issuerCaId;
        this.profileReference = source.profileReference;
        this.subjectRef = source.subjectRef;
        this.subjectRdns = source.subjectRdns;
        this.subjectAlternativeNames = source.subjectAlternativeNames;
        this.sanCritical = source.sanCritical;
        this.exactPublicKey = source.exactPublicKey;
        this.validity = source.validity;
        this.keyUsages = source.keyUsages;
        this.extendedKeyUsages = source.extendedKeyUsages;
        this.keyUsageCritical = source.keyUsageCritical;
        this.extendedKeyUsageCritical = source.extendedKeyUsageCritical;
        this.basicConstraintsCritical = source.basicConstraintsCritical;
        this.algorithmBindingPolicy = source.algorithmBindingPolicy;
        this.frozenIssuance = Objects.requireNonNull(frozenIssuance, "frozenIssuance");
        this.executionEvidence = source.executionEvidence;
    }

    private ValidatedCertificateRequest(ValidatedCertificateRequest source, AttributeSet executionEvidence) {
        this.issuerCaId = source.issuerCaId;
        this.profileReference = source.profileReference;
        this.subjectRef = source.subjectRef;
        this.subjectRdns = source.subjectRdns;
        this.subjectAlternativeNames = source.subjectAlternativeNames;
        this.sanCritical = source.sanCritical;
        this.exactPublicKey = source.exactPublicKey;
        this.validity = source.validity;
        this.keyUsages = source.keyUsages;
        this.extendedKeyUsages = source.extendedKeyUsages;
        this.keyUsageCritical = source.keyUsageCritical;
        this.extendedKeyUsageCritical = source.extendedKeyUsageCritical;
        this.basicConstraintsCritical = source.basicConstraintsCritical;
        this.algorithmBindingPolicy = source.algorithmBindingPolicy;
        this.frozenIssuance = source.frozenIssuance;
        this.executionEvidence = Objects.requireNonNull(executionEvidence, "executionEvidence");
    }

    /* default */ ValidatedCertificateRequest withFrozenIssuance(PkiId issuerId, PkiId chainPathId,
            String chainPathCommitment, java.util.Optional<IssuanceIntent> intent) {
        return new ValidatedCertificateRequest(this,
                new FrozenIssuance(issuerId, chainPathId, chainPathCommitment, intent));
    }

    /**
     * Returns a copy carrying the server-derived issuance execution evidence to co-commit with the
     * published credential, so the deferred (asynchronously signed) publication path records the same
     * audit evidence the synchronous path merges into the credential attributes.
     *
     * @param executionEvidence non-null evidence attribute set, possibly empty
     * @return copy bound to the supplied evidence
     */
    /* default */ ValidatedCertificateRequest withExecutionEvidence(AttributeSet executionEvidence) {
        return new ValidatedCertificateRequest(this, executionEvidence);
    }

    /**
     * Returns the authoritative issuer CA identifier.
     *
     * @return exact logical authority identifier
     */
    public PkiId issuerCaId() {
        return issuerCaId;
    }

    /**
     * Returns the selected exact profile reference, active or frozen by issuance intent.
     *
     * @return exact immutable profile reference
     */
    public CertificateProfileRef profileReference() {
        return profileReference;
    }

    /**
     * Returns the selected logical profile identifier.
     *
     * @return nonblank profile identifier
     */
    public String profileId() {
        return profileReference.profileId();
    }

    /**
     * Returns the canonical inventory subject reference.
     *
     * @return exact subject reference
     */
    public SubjectRef subjectRef() {
        return subjectRef;
    }

    /**
     * Returns the approved subject name.
     *
     * @return ordered immutable subject RDNs
     */
    public List<SubjectRdn> subjectRdns() {
        return subjectRdns;
    }

    /**
     * Returns the approved subject alternative names.
     *
     * @return ordered immutable SAN entries
     */
    public List<SubjectAlternativeName> subjectAlternativeNames() {
        return subjectAlternativeNames;
    }

    /**
     * Returns the profile-derived SAN criticality.
     *
     * @return whether SAN is critical
     */
    public boolean subjectAlternativeNameCritical() {
        return sanCritical;
    }

    /**
     * Returns the exact proof-bound public key.
     *
     * @return defensive copy of the SPKI
     */
    public EncodedObject exactPublicKey() {
        return new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
    }

    /**
     * Returns the approved issuer-time validity.
     *
     * @return exact validity interval
     */
    public Validity validity() {
        return validity;
    }

    /**
     * Returns the profile-derived key usages.
     *
     * @return immutable key-usage set
     */
    public Set<LeafKeyUsage> keyUsages() {
        return keyUsages;
    }

    /**
     * Returns the profile-derived extended key usages.
     *
     * @return immutable extended-key-usage set
     */
    public Set<ExtendedKeyUsageId> extendedKeyUsages() {
        return extendedKeyUsages;
    }

    /**
     * Returns the KeyUsage extension criticality.
     *
     * @return whether KeyUsage is critical
     */
    public boolean keyUsageCritical() {
        return keyUsageCritical;
    }

    /**
     * Returns the ExtendedKeyUsage extension criticality.
     *
     * @return whether ExtendedKeyUsage is critical
     */
    public boolean extendedKeyUsageCritical() {
        return extendedKeyUsageCritical;
    }

    /**
     * Returns the leaf BasicConstraints criticality.
     *
     * @return whether BasicConstraints is critical
     */
    public boolean basicConstraintsCritical() {
        return basicConstraintsCritical;
    }

    /**
     * Returns the X.509 representation selection.
     *
     * @return exact immutable binding policy
     */
    public X509AlgorithmBindingPolicy algorithmBindingPolicy() {
        return algorithmBindingPolicy;
    }

    /**
     * Returns the service-frozen publication selection.
     *
     * @return frozen selection, when supplied
     */
    public java.util.Optional<FrozenIssuance> frozenIssuance() {
        return java.util.Optional.ofNullable(frozenIssuance);
    }

    /**
     * Returns evidence co-committed with the credential.
     *
     * @return server-derived evidence, possibly empty
     */
    public AttributeSet executionEvidence() {
        return executionEvidence;
    }
}
