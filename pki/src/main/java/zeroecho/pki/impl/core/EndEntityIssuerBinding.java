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
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;

import java.util.HexFormat;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pkix.cmp.CrmfRequest;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;

/**
 * Validates the issued certificate and request against the frozen issuer signing binding.
 */
final class EndEntityIssuerBinding {
    private final PkiStore store;
    private final Optional<PublicKeyInfoSource> managedKeys;
    private final X509AuthoritySnapshot authority;
    private final X509ProfileBindingMatcher bindingMatcher;

    /* default */ EndEntityIssuerBinding(PkiStore store, Optional<PublicKeyInfoSource> managedKeys,
            X509AuthoritySnapshot authority, X509ProfileBindingMatcher bindingMatcher) {
        this.store = store;
        this.managedKeys = managedKeys;
        this.authority = authority;
        this.bindingMatcher = bindingMatcher;
    }

    // Untrusted parser/provider diagnostics must not escape this stable no-cause boundary.
    /* default */
    @SuppressWarnings("PMD.PreserveStackTrace")
    AlgorithmIdentifier select(byte[] issuerDer, Credential issuer, Instant now,
            AlgorithmIdentity signature, IssuerGeneration generation, IssuerCryptographicBinding issuerBinding,
            ValidatedCertificateRequest approved, Optional<X509EnrollmentPayload> csrDer,
            VerifiedIssuanceCandidate candidate) throws IOException {
        AlgorithmIdentifier signingBinding;
        try {
            new StreamingDerReader().validate(issuerDer, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(issuerDer);
            requireIssuerCertificate(certificate, issuer, now);
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
            AlgorithmIdentity issuerKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(
                    Pkix.subjectPublicKeyInfo(certificate)), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509SuiteCompatibility.requireCompatible(signature, issuerKey);
            if (managedKeys.isPresent()) { IssuerBindingResolver.resolve(store, generation, managedKeys.orElseThrow(), authority); }
            X509AlgorithmBindingPolicy policy = approved.algorithmBindingPolicy();
            signingBinding = bindingMatcher.select(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                    policy.certificateSignature());
            requireFrozenSignature(signingBinding, issuerBinding);
            if (csrDer.isPresent()) {
                X509EnrollmentPayload payload = csrDer.orElseThrow();
                AlgorithmIdentifier proofAlgorithm = payload.kind() == X509EnrollmentPayload.Kind.PKCS10
                        ? Pkix.parseCertificationRequest(payload.der()).signatureAlgorithm()
                        : CrmfRequest.parse(payload.der()).signatureAlgorithm();
                bindingMatcher.require(proofAlgorithm, X509AlgorithmBinding.Role.CSR_SIGNATURE,
                        policy.csrSignature());
            }
            bindingMatcher.require(Pkix.subjectPublicKeyAlgorithm(candidate.exactPublicKey().bytes()),
                    X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY, policy.subjectPublicKey());
        } catch (IllegalArgumentException | IOException invalid) {
            throw new PkiException("End-entity preparation rejected: code=ISSUANCE_BINDING_INVALID");
        }
        return signingBinding;
    }

    /* default */ static void requireIssuerCertificate(X509Certificate certificate, Credential issuer, Instant now) {
        boolean[] usages = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || usages == null || usages.length <= 5 || !usages[5]
                || !certificate.getNotBefore().toInstant().equals(issuer.validity().notBefore())
                || !certificate.getNotAfter().toInstant().equals(issuer.validity().notAfter())
                || now.isBefore(certificate.getNotBefore().toInstant()) || !now.isBefore(certificate.getNotAfter().toInstant())) {
            throw new PkiException("End-entity preparation rejected: code=ISSUER_CERTIFICATE_UNUSABLE");
        }
    }

    private static void requireFrozenSignature(AlgorithmIdentifier signingBinding,
            IssuerCryptographicBinding issuerBinding) {
        if (!signingBinding.equals(Pkix.parseAlgorithmIdentifier(issuerBinding.primary().signatureAlgorithmIdentifier().bytes()))) {
            throw new IllegalArgumentException("Frozen issuer signature binding differs");
        }
    }

    /* default */ static void requireSelectedIssuance(IssuanceIntent expected, IssuerGeneration generation, IssuerChainPath path) {
        if (!expected.expectedIssuerId().equals(generation.issuerId())
                || !expected.expectedChainPathId().equals(path.pathId())
                || !expected.expectedChainPathCommitment().equals(path.pathCommitment())) {
            throw new PkiException("Correlated issuance rejected: code=ISSUANCE_SELECTION_STALE");
        }
    }

    /* default */ static void requireConsistentIssuer(CaRecord ca, IssuerGeneration generation, IssuerChainPath path,
            Credential credential) {
        if (!generation.issuerId().equals(ca.currentIssuanceIssuerId())
                || !path.pathId().equals(ca.issuanceChainPathId())
                || !credential.credentialId().equals(generation.credentialId())
                || !path.orderedCredentialIds().getFirst().equals(credential.credentialId())
                || !ca.issuerKeyRef().equals(generation.signingKeyRef())
                || !credential.subjectRef().equals(ca.subjectRef())
                || !BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                || !(credential.profileBinding() instanceof CaProfileBinding profile)
                || !generation.profilePolicyCommitment().equals(HexFormat.of().formatHex(
                        profile.reference().canonicalSha256()))) {
            throw new PkiException("End-entity preparation rejected: code=ISSUER_BINDING_INCONSISTENT");
        }
    }


    /* default */ static String managedAttribute(Credential credential, String name) {
        List<AttributeValue> values = credential.attributes().getAll(new AttributeId(name));
        if (values.size() != 1 || !(values.getFirst() instanceof AttributeValue.StringValue value)) {
            throw new PkiException("OCSP_PREDECESSOR_PROVENANCE_INVALID");
        }
        return value.value();
    }
}
