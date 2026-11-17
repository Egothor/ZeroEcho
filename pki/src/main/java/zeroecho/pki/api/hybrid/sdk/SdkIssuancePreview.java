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
 *
 * <p>The constructor snapshots the two lists with {@link List#copyOf}, retaining
 * their immutable element references and the other supplied value objects. It
 * requires non-null coordinates and checks a present lifecycle target against both
 * client SPKI hashes. It does not validate digest spelling, parse certificates or
 * SPKIs, establish generation/path/profile relationships, or admit current policy.
 * Some malformed supplied coordinates therefore fail only when a typed value or
 * issuer-binding frame is requested.</p>
 *
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
 * @param enrollmentTarget optional trusted native enrollment target
 */
public record SdkIssuancePreview(PkiId issuerCaId, PkiId issuerId, PkiId chainPathId,
        String chainPathCommitment, CertificateProfileRef profile, SubjectRef subjectRef,
        List<SubjectRdn> subject, List<SubjectAlternativeName> subjectAlternativeNames, Validity validity,
        EncodedObject primarySubjectSpki, EncodedObject alternativeSubjectSpki,
        IssuerCryptographicBinding issuerBinding, EncodedObject issuerPrimarySpki, Optional<EncodedObject> issuerAlternativeSpki,
        String issuerCertificateSha512,
        String providerEvidence, HybridSdkValue disclosurePolicy, Optional<SdkLifecycleTarget> lifecycleTarget,
        Optional<SdkEnrollmentTarget> enrollmentTarget) {
    /**
     * Snapshots the subject collections and checks a present lifecycle subject-key target.
     *
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
     * @param enrollmentTarget optional trusted native enrollment target
     * @throws NullPointerException if a coordinate, optional container, list or list element is null
     * @throws IllegalArgumentException if a present lifecycle target differs from either subject SPKI hash
     */
    public SdkIssuancePreview {
        Objects.requireNonNull(issuerCaId); Objects.requireNonNull(issuerId); Objects.requireNonNull(chainPathId);
        Objects.requireNonNull(chainPathCommitment); Objects.requireNonNull(profile); Objects.requireNonNull(subjectRef);
        subject = List.copyOf(subject); subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
        Objects.requireNonNull(validity); Objects.requireNonNull(primarySubjectSpki); Objects.requireNonNull(alternativeSubjectSpki);
        Objects.requireNonNull(issuerBinding); Objects.requireNonNull(issuerPrimarySpki); Objects.requireNonNull(issuerAlternativeSpki); Objects.requireNonNull(issuerCertificateSha512);
        Objects.requireNonNull(providerEvidence); Objects.requireNonNull(disclosurePolicy);
        Objects.requireNonNull(enrollmentTarget, "enrollmentTarget");
        Objects.requireNonNull(lifecycleTarget, "lifecycleTarget");
        lifecycleTarget.ifPresent(target -> {
            if (!target.subjectPrimarySpkiSha512().equals("sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(primarySubjectSpki.bytes())))
                    || !target.subjectAlternativeSpkiSha512().equals("sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(alternativeSubjectSpki.bytes())))) {
                throw new IllegalArgumentException("Lifecycle target subject keys differ from preview");
            }
        });
    }

    /**
     * Creates a lifecycle preview with no native enrollment target.
     *
     * @param issuerCaId issuer CA
     * @param issuerId generation
     * @param chainPathId path
     * @param chainPathCommitment path commitment
     * @param profile approved profile
     * @param subjectRef subject
     * @param subject ordered RDNs
     * @param subjectAlternativeNames ordered SANs
     * @param validity absolute bounds
     * @param primarySubjectSpki primary SPKI
     * @param alternativeSubjectSpki alternative SPKI
     * @param issuerBinding outgoing binding
     * @param issuerPrimarySpki issuer primary SPKI
     * @param issuerAlternativeSpki issuer alternative SPKI
     * @param issuerCertificateSha512 certificate digest
     * @param providerEvidence authority fingerprint
     * @param disclosurePolicy disclosure policy
     * @param lifecycleTarget predecessor and operation evidence
     * @throws NullPointerException if a coordinate, optional container, list or list element is null
     * @throws IllegalArgumentException if a present lifecycle target differs from the subject keys
     */
    // Preserve the established public constructor signature.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    public SdkIssuancePreview(PkiId issuerCaId, PkiId issuerId, PkiId chainPathId,
            String chainPathCommitment, CertificateProfileRef profile, SubjectRef subjectRef,
            List<SubjectRdn> subject, List<SubjectAlternativeName> subjectAlternativeNames, Validity validity,
            EncodedObject primarySubjectSpki, EncodedObject alternativeSubjectSpki,
            IssuerCryptographicBinding issuerBinding, EncodedObject issuerPrimarySpki, Optional<EncodedObject> issuerAlternativeSpki,
            String issuerCertificateSha512, String providerEvidence, HybridSdkValue disclosurePolicy,
            Optional<SdkLifecycleTarget> lifecycleTarget) {
        this(issuerCaId, issuerId, chainPathId, chainPathCommitment, profile, subjectRef, subject, subjectAlternativeNames,
                validity, primarySubjectSpki, alternativeSubjectSpki, issuerBinding, issuerPrimarySpki, issuerAlternativeSpki,
                issuerCertificateSha512, providerEvidence, disclosurePolicy, lifecycleTarget, Optional.empty());
    }

    /**
     * Creates an ordinary issuance preview with neither lifecycle nor enrollment evidence.
     *
     * @param issuerCaId logical issuer
     * @param issuerId generation
     * @param chainPathId path
     * @param chainPathCommitment path commitment
     * @param profile approved profile
     * @param subjectRef subject identity
     * @param subject ordered RDNs
     * @param subjectAlternativeNames ordered SANs
     * @param validity absolute bounds
     * @param primarySubjectSpki primary subject SPKI
     * @param alternativeSubjectSpki alternative subject SPKI
     * @param issuerBinding outgoing issuer authority
     * @param issuerPrimarySpki issuer primary SPKI
     * @param issuerAlternativeSpki issuer alternative SPKI
     * @param issuerCertificateSha512 issuer DER digest
     * @param providerEvidence provider authority fingerprint
     * @param disclosurePolicy canonical disclosure policy
     * @throws NullPointerException if a coordinate, optional container, list or list element is null
     */
    // Preserve the established public constructor signature.
    @SuppressWarnings("PMD.ExcessiveParameterList")
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

    /**
     * Encodes the public extension selected for F7 field 17.
     *
     * <p>Without enrollment, the result is the lifecycle object or an empty object
     * for ordinary issuance. With enrollment, it is a version-one wrapper containing
     * lifecycle (possibly empty), enrollment and binding-set inputs. This method
     * serializes supplied coordinates without authorizing the native protocol.</p>
     *
     * @return immutable canonical typed extension object, never null
     * @throws IllegalArgumentException if supplied text or nested values exceed typed-value bounds
     */
    public HybridSdkValue targetExtensionValue() {
        HybridSdkValue lifecycle = lifecycleTarget.map(SdkLifecycleTarget::value)
                .orElseGet(() -> HybridSdkValue.object(Map.of()));
        return enrollmentTarget.map(target -> HybridSdkValue.object(Map.of(
                "version", HybridSdkValue.integer(1), "lifecycle", lifecycle, "enrollment", target.value(),
                "bindingSetInputs", bindingSetInputs())))
                .orElse(lifecycle);
    }
    /**
     * Encodes the effective subject, ordered RDNs/SANs and exact absolute validity for F7.
     *
     * <p>IP SANs retain their address bytes; the other supported SAN kinds use text.
     * No subject normalization, profile evaluation or validity adjustment occurs.</p>
     *
     * @return immutable canonical public subject and validity object
     * @throws IllegalArgumentException if supplied text, collections or encoding exceed typed-value bounds
     */
    public HybridSdkValue effectiveSubjectValue() {
        return HybridSdkValue.object(Map.of("subjectRef", HybridSdkValue.text(subjectRef.value()),
                "rdns", HybridSdkValue.list(subject.stream().map(rdn -> HybridSdkValue.object(Map.of(
                        "type", HybridSdkValue.text(rdn.type().name()), "value", HybridSdkValue.text(rdn.value())))).toList()),
                "sans", HybridSdkValue.list(subjectAlternativeNames.stream().map(SdkIssuancePreview::san).toList()),
                "notBefore", HybridSdkValue.text(validity.notBefore().toString()),
                "notAfter", HybridSdkValue.text(validity.notAfter().toString())));
    }
    /**
     * Commits the supplied issuer binding, provider fingerprint and selected path commitment.
     *
     * <p>The SHA-512 input is the canonical typed encoding of those three named
     * values. The method commits existing evidence rather than reading a provider or
     * validating every certificate in a chain.</p>
     *
     * @return sha512: followed by 128 lowercase hexadecimal digits
     * @throws IllegalArgumentException if a supplied value exceeds typed-value encoding bounds
     */
    public String bindingSetCommitment() {
        return "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(bindingSetInputs().encode()));
    }
    private HybridSdkValue bindingSetInputs() {
        return HybridSdkValue.object(Map.of("issuerBinding", HybridSdkValue.text(issuerBinding.commitment()),
                "provider", HybridSdkValue.text(providerEvidence), "path", HybridSdkValue.text(chainPathCommitment)));
    }
    /**
     * Encodes the outgoing issuer primary role as an F8 binding frame.
     *
     * <p>The SPKI hash describes the supplied issuer key, independently of the
     * requesting client's primary key. Encoding does not establish consistency
     * between that SPKI and the captured issuer role.</p>
     *
     * @return new immutable F8 public issuer-role frame
     * @throws IllegalArgumentException if encoded fields exceed frame bounds
     */
    public HybridSdkFrame primaryIssuerBindingFrame() {
        return keyFrame(8, issuerBinding.primary(), issuerPrimarySpki);
    }
    /**
     * Encodes the outgoing issuer alternative role as an F9 binding frame when present.
     *
     * @return immutable F9 frame, or empty when the captured binding has no alternative role
     * @throws java.util.NoSuchElementException if the binding has an alternative role but its SPKI is absent
     * @throws IllegalArgumentException if encoded fields exceed frame bounds
     */
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
