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
package zeroecho.pki.api.hybrid.sdk;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Map;
import java.util.HexFormat;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.request.SubjectAlternativeName;

/**
 * Public immutable result of pure SDK issuance policy evaluation. Contains public
 * metadata only; construction grants neither proof verification nor authorization.
 * @param issuerCaId logical issuer
 * @param issuerId exact issuer generation
 * @param chainPathId selected chain path
 * @param chainPathCommitment exact selected path commitment
 * @param profile exact approved profile reference
 * @param subjectRef effective subject identity
 * @param subject approved ordered RDNs
 * @param subjectAlternativeNames approved ordered SANs
 * @param validity exact absolute encoded bounds
 * @param primarySubjectSpki client primary public key
 * @param alternativeSubjectSpki client alternative public key
 * @param issuerBinding exact immutable outgoing issuer binding
 * @param issuerPrimarySpki exact issuer primary subject SPKI
 * @param issuerAlternativeSpki exact issuer alternative subject SPKI when present
 * @param issuerCertificateSha512 SHA-512 of issuer certificate DER, lowercase hex
 * @param providerEvidence authority snapshot semantic fingerprint
 * @param disclosurePolicy canonical policy disclosure evidence
 * @param lifecycleTarget optional exact predecessor/operation/subject-key target
 */
public record SdkIssuancePreview(PkiId issuerCaId, PkiId issuerId, PkiId chainPathId,
        String chainPathCommitment, CertificateProfileRef profile, SubjectRef subjectRef,
        List<SubjectRdn> subject, List<SubjectAlternativeName> subjectAlternativeNames, Validity validity,
        EncodedObject primarySubjectSpki, EncodedObject alternativeSubjectSpki,
        IssuerCryptographicBinding issuerBinding, EncodedObject issuerPrimarySpki, Optional<EncodedObject> issuerAlternativeSpki,
        String issuerCertificateSha512,
        String providerEvidence, HybridSdkValue disclosurePolicy, Optional<SdkLifecycleTarget> lifecycleTarget) {
    /** Snapshots finite collections and rejects missing coordinates. */
    public SdkIssuancePreview {
        Objects.requireNonNull(issuerCaId); Objects.requireNonNull(issuerId); Objects.requireNonNull(chainPathId);
        Objects.requireNonNull(chainPathCommitment); Objects.requireNonNull(profile); Objects.requireNonNull(subjectRef);
        subject = List.copyOf(subject); subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
        Objects.requireNonNull(validity); Objects.requireNonNull(primarySubjectSpki); Objects.requireNonNull(alternativeSubjectSpki);
        Objects.requireNonNull(issuerBinding); Objects.requireNonNull(issuerPrimarySpki); Objects.requireNonNull(issuerAlternativeSpki); Objects.requireNonNull(issuerCertificateSha512);
        Objects.requireNonNull(providerEvidence); Objects.requireNonNull(disclosurePolicy);
        Objects.requireNonNull(lifecycleTarget, "lifecycleTarget");
        lifecycleTarget.ifPresent(target -> {
            if (!target.subjectPrimarySpkiSha512().equals("sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(primarySubjectSpki.bytes())))
                    || !target.subjectAlternativeSpkiSha512().equals("sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(alternativeSubjectSpki.bytes())))) {
                throw new IllegalArgumentException("Lifecycle target subject keys differ from preview");
            }
        });
    }

    /**
     * Preserves the issuance-only preview constructor without lifecycle evidence.
     * @param issuerCaId logical issuer @param issuerId generation @param chainPathId path
     * @param chainPathCommitment path commitment @param profile approved profile
     * @param subjectRef subject identity @param subject ordered RDNs @param subjectAlternativeNames ordered SANs
     * @param validity absolute bounds @param primarySubjectSpki primary subject SPKI @param alternativeSubjectSpki alternative subject SPKI
     * @param issuerBinding outgoing issuer authority @param issuerPrimarySpki issuer primary SPKI
     * @param issuerAlternativeSpki issuer alternative SPKI @param issuerCertificateSha512 issuer DER digest
     * @param providerEvidence provider authority fingerprint @param disclosurePolicy canonical disclosure policy
     */
    public SdkIssuancePreview(PkiId issuerCaId, PkiId issuerId, PkiId chainPathId,
            String chainPathCommitment, CertificateProfileRef profile, SubjectRef subjectRef,
            List<SubjectRdn> subject, List<SubjectAlternativeName> subjectAlternativeNames, Validity validity,
            EncodedObject primarySubjectSpki, EncodedObject alternativeSubjectSpki,
            IssuerCryptographicBinding issuerBinding, EncodedObject issuerPrimarySpki, Optional<EncodedObject> issuerAlternativeSpki,
            String issuerCertificateSha512, String providerEvidence, HybridSdkValue disclosurePolicy) {
        this(issuerCaId, issuerId, chainPathId, chainPathCommitment, profile, subjectRef, subject, subjectAlternativeNames,
                validity, primarySubjectSpki, alternativeSubjectSpki, issuerBinding, issuerPrimarySpki, issuerAlternativeSpki,
                issuerCertificateSha512, providerEvidence, disclosurePolicy, Optional.empty());
    }

    /** @return strict F7 field-17 object, empty only for ordinary issuance */
    public HybridSdkValue targetExtensionValue() {
        return lifecycleTarget.map(SdkLifecycleTarget::value).orElseGet(() -> HybridSdkValue.object(Map.of()));
    }
    /** @return canonical F7 effective subject, SAN and exact absolute validity value */
    public HybridSdkValue effectiveSubjectValue() {
        return HybridSdkValue.object(Map.of("subjectRef", HybridSdkValue.text(subjectRef.value()),
                "rdns", HybridSdkValue.list(subject.stream().map(rdn -> HybridSdkValue.object(Map.of(
                        "type", HybridSdkValue.text(rdn.type().name()), "value", HybridSdkValue.text(rdn.value())))).toList()),
                "sans", HybridSdkValue.list(subjectAlternativeNames.stream().map(SdkIssuancePreview::san).toList()),
                "notBefore", HybridSdkValue.text(validity.notBefore().toString()),
                "notAfter", HybridSdkValue.text(validity.notAfter().toString())));
    }
    /** @return SHA-512 commitment binding outgoing algorithms, provider authority and full chain path */
    public String bindingSetCommitment() {
        var value = HybridSdkValue.object(Map.of("issuerBinding", HybridSdkValue.text(issuerBinding.commitment()),
                "provider", HybridSdkValue.text(providerEvidence), "path", HybridSdkValue.text(chainPathCommitment)));
        return "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(value.encode()));
    }
    /** @return exact F8 issuer primary binding; never a client subject binding */
    public HybridSdkFrame primaryIssuerBindingFrame() {
        return keyFrame(8, issuerBinding.primary(), issuerPrimarySpki);
    }
    /** @return exact F9 issuer alternative binding when the selected CA has one */
    public Optional<HybridSdkFrame> alternativeIssuerBindingFrame() {
        return issuerBinding.alternative().map(key -> keyFrame(9, key, issuerAlternativeSpki.orElseThrow()));
    }
    private static HybridSdkFrame keyFrame(int kind, zeroecho.pki.api.ca.IssuerKeyBinding key, EncodedObject spki) {
        return new HybridSdkFrame(kind, Map.of(1, key.keyRef().value().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                2, key.publicKeyAlgorithm().canonicalForm().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                3, key.signatureAlgorithm().canonicalForm().getBytes(java.nio.charset.StandardCharsets.UTF_8),
                4, key.signatureAlgorithmIdentifier().bytes(), 5, HybridSdkFrame.hash(spki.bytes())));
    }
    private static HybridSdkValue san(SubjectAlternativeName name) {
        HybridSdkValue value = switch (name) {
            case SubjectAlternativeName.DnsName dns -> HybridSdkValue.text(dns.value());
            case SubjectAlternativeName.UriName uri -> HybridSdkValue.text(uri.value());
            case SubjectAlternativeName.Rfc822Name email -> HybridSdkValue.text(email.value());
            case SubjectAlternativeName.IpAddress ip -> HybridSdkValue.bytes(ip.bytes());
        };
        return HybridSdkValue.object(Map.of("type", HybridSdkValue.text(name.type().name()), "value", value));
    }
}
