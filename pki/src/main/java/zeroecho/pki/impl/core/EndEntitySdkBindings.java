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

import java.util.Arrays;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import java.io.IOException;
import java.security.cert.X509Certificate;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest;
import zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pkix.Pkix;
import java.nio.ByteBuffer;
import zeroecho.pki.api.confirmation.CredentialConfirmationPolicy;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget;
import zeroecho.pki.api.hybrid.sdk.SdkIssuanceApproval;
import zeroecho.pki.api.hybrid.sdk.SdkLifecycleTarget;
import zeroecho.pki.impl.framework.x509.bc.BcHybridSdkProofVerifier;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview;
import zeroecho.pki.api.issuance.EndEntityReissueRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.issuance.EndEntityReplacementRequest;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;

/**
 * Validates SDK proofs and their bindings to immutable issuance targets.
 */
final class EndEntitySdkBindings {
    private EndEntitySdkBindings() { }
    /* default */ static SdkIssuancePreview enrollmentPreview(
            SdkIssuancePreview preview,
            ParsedHybridSdkRequest parsed,
            Optional<SdkEnrollmentTarget> target) {
        target.ifPresent(value -> {
            String operation = preview.lifecycleTarget().map(lifecycle -> switch (lifecycle.operation()) {
                case "credential.renew" -> "RENEW";
                case "credential.replace" -> "REPLACE";
                default -> throw new PkiException("SDK_ENROLLMENT_OPERATION_UNSUPPORTED");
            }).orElse("ISSUE");
            if (!value.operation().equals(operation) || value.requestKind() != parsed.originalPayload().kind()) {
                throw new PkiException("SDK_ENROLLMENT_TARGET_MISMATCH");
            }
        });
        return new SdkIssuancePreview(preview.issuerCaId(), preview.issuerId(),
                preview.chainPathId(), preview.chainPathCommitment(), preview.profile(), preview.subjectRef(),
                preview.subject(), preview.subjectAlternativeNames(), preview.validity(), preview.primarySubjectSpki(),
                preview.alternativeSubjectSpki(), preview.issuerBinding(), preview.issuerPrimarySpki(), preview.issuerAlternativeSpki(),
                preview.issuerCertificateSha512(), preview.providerEvidence(), preview.disclosurePolicy(), preview.lifecycleTarget(), target);
    }

    /* default */ static HybridSdkValue confirmationPolicyValue(
            CredentialConfirmationPolicy policy) {
        return HybridSdkValue.object(Map.of(
                "disclosure", HybridSdkValue.text(policy.disclosurePolicy().name()),
                "window", HybridSdkValue.text(policy.confirmationWindow().toString()),
                "suite", HybridSdkValue.text(policy.proofSuite().suiteId()),
                "suiteCommitment", HybridSdkValue.text(policy.proofSuite().configurationCommitment()),
                "commitment", HybridSdkValue.text("sha256:" + policy.configurationCommitment())));
    }

    /* default */ static void verifySdkProof(ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval) {
        String proof = new BcHybridSdkProofVerifier().verify(parsed,
                approval.primaryFrame(), approval.primaryProof(), approval.alternativeProof(), approval.proofAcceptedAt());
        if (!MessageDigest.isEqual(proof.getBytes(StandardCharsets.US_ASCII),
                approval.expectedF3().getBytes(StandardCharsets.US_ASCII))) {
            throw new PkiException("SDK_PROOF_COMMITMENT_MISMATCH");
        }
    }

    /* default */ static void requireSdkTarget(SdkIssuancePreview preview,
            SdkIssuanceApproval approval,
            ParsedHybridSdkRequest parsed) {
        HybridSdkFrame target = approval.targetFrame();
        if (target.kind() != 7 || !MessageDigest.isEqual(
                HybridSdkFrame.hash(target.encode()), approval.primaryFrame().field(17))) {
            throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
        }
        Map<Integer, byte[]> fields = Map.ofEntries(
                Map.entry(1, utf8(preview.lifecycleTarget()
                        .map(SdkLifecycleTarget::operation).orElse("credential.issue"))),
                Map.entry(4, utf8(preview.issuerCaId().value())),
                Map.entry(5, utf8(preview.issuerId().value())),
                Map.entry(6, utf8(preview.chainPathId().value())),
                Map.entry(7, utf8("sha512:" + preview.issuerCertificateSha512())),
                Map.entry(8, preview.primaryIssuerBindingFrame().encode()),
                Map.entry(9, preview.alternativeIssuerBindingFrame().map(HybridSdkFrame::encode)
                        .orElseGet(() -> new byte[0])),
                Map.entry(10, utf8(preview.profile().profileId())),
                Map.entry(11, ByteBuffer.allocate(Long.BYTES).putLong(preview.profile().profileVersion()).array()),
                Map.entry(12, utf8("sha256:" + HexFormat.of().formatHex(preview.profile().canonicalSha256()))),
                Map.entry(13, utf8(preview.bindingSetCommitment())),
                Map.entry(15, preview.effectiveSubjectValue().encode()),
                Map.entry(16, preview.disclosurePolicy().encode()),
                Map.entry(17, preview.targetExtensionValue().encode()));
        preview.lifecycleTarget().ifPresent(lifecycle -> {
            Map<String, HybridSdkValue> arguments = HybridSdkValue.decode(target.field(2))
                    .objectFields();
            boolean replacement = "credential.replace".equals(lifecycle.operation());
            Set<String> names = replacement ? Set.of("existingCredentialId", "requestId", "profileId")
                    : Set.of("credentialId");
            if (!arguments.keySet().equals(names)
                    || !arguments.get(replacement ? "existingCredentialId" : "credentialId").textValue()
                            .equals(lifecycle.predecessorId().value())
                    || replacement && (!arguments.get("profileId").textValue().equals(preview.profile().profileId())
                            || !arguments.get("requestId").textValue().equals(parsed.primary().requestId().value()))) {
                throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
            }
        });
        for (Map.Entry<Integer, byte[]> field : fields.entrySet()) {
            if (!MessageDigest.isEqual(field.getValue(), target.field(field.getKey()))) {
                throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
            }
        }
    }

    /* default */ static AccessContext sdkLifecycleAccess(AccessContext access, Object request) {
        PkiId predecessor;
        if (request instanceof EndEntityRenewalRequest value) {
            predecessor = value.existingCredentialId();
        } else if (request instanceof EndEntityReissueRequest value) {
            predecessor = value.existingCredentialId();
        } else if (request instanceof EndEntityReplacementRequest value) {
            predecessor = value.existingCredentialId();
        } else {
            throw new UnsupportedOperationException("Unsupported SDK lifecycle operation");
        }
        return lifecycleAccess(access, predecessor);
    }

    /* default */ static AccessContext lifecycleAccess(AccessContext access, PkiId predecessor) {
        Objects.requireNonNull(access, "access");
        if (access.objectId().filter(value -> !value.equals(predecessor)).isPresent()
                || access.formatId().filter(value -> !value.equals(BcX509CredentialFramework.FORMAT_ID)).isPresent()) {
            throw new IllegalArgumentException("Lifecycle access coordinates conflict with predecessor");
        }
        return new AccessContext(access.principal(), access.purpose(), Optional.of(predecessor),
                Optional.of(BcX509CredentialFramework.FORMAT_ID));
    }

    /* default */ static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /* default */ static void validateCorrelatedSdkBinding(Object correlated,
            ParsedHybridSdkRequest parsed,
            SdkIssuanceApproval approval) {
        IssuanceIntent intent;
        PkiId ca;
        if (correlated instanceof CorrelatedEndEntityIssuanceRequest issue) {
            intent = issue.intent();
            ca = issue.request().issuerCaId();
            if (issue.request().payload().kind() != parsed.originalPayload().kind()
                    || !Arrays.equals(issue.request().payload().der(), parsed.originalPayload().der())) {
                throw new PkiException("SDK_REQUEST_MISMATCH");
            }
        } else if (correlated instanceof CorrelatedEndEntityRenewalRequest renew) {
            intent = renew.intent();
            ca = renew.issuerCaId();
        } else if (correlated instanceof CorrelatedEndEntityReplacementRequest replace) {
            intent = replace.intent();
            ca = replace.issuerCaId();
        } else {
            throw new UnsupportedOperationException("SDK correlated operation unavailable");
        }
        SdkIssuancePreview preview = approval.preview();
        if (!ca.equals(preview.issuerCaId()) || !intent.expectedProfile().equals(preview.profile())
                || !intent.expectedIssuerId().equals(preview.issuerId())
                || !intent.expectedChainPathId().equals(preview.chainPathId())
                || !intent.expectedChainPathCommitment().equals(preview.chainPathCommitment())) {
            throw new PkiException("SDK_FROZEN_TARGET_MISMATCH");
        }
    }

    /* default */ static SdkIssuancePreview sdkPreview(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed,
            Optional<SdkLifecycleTarget> lifecycleTarget, EndEntityIssuancePreparation validation) throws IOException {
        ValidatedCertificateRequest.FrozenIssuance frozen = approved.request().frozenIssuance().orElseThrow();
        X509Certificate certificate = Pkix.parseCertificate(approved.issuerDer());
        ActiveCertificateProfile profile = approved.profile();
        HybridSdkValue policy = HybridSdkValue.object(Map.of(
                "profile", HybridSdkValue.bytes(profile.reference().canonicalSha256()),
                "confirmation", profile.definition().confirmationPolicy().map(EndEntitySdkBindings::confirmationPolicyValue)
                        .orElseGet(() -> HybridSdkValue.object(Map.of()))));
        return new SdkIssuancePreview(approved.request().issuerCaId(), frozen.issuerId(),
                frozen.chainPathId(), frozen.chainPathCommitment(), approved.request().profileReference(),
                approved.request().subjectRef(), approved.request().subjectRdns(), approved.request().subjectAlternativeNames(),
                approved.request().validity(), approved.request().exactPublicKey(), parsed.alternativeSubjectPublicKeyInfo(),
                approved.issuerBinding(), new EncodedObject(Encoding.DER, Pkix.subjectPublicKeyInfo(certificate)),
                Optional.of(new EncodedObject(Encoding.DER,
                        AltSignatureExtensions.requiredValue(certificate, X509ExtensionOids.subjectAltPublicKeyInfo()))),
                HexFormat.of().formatHex(HybridSdkFrame.hash(approved.issuerDer())),
                validation.authority().semanticFingerprint(), policy, lifecycleTarget);
    }
}
