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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.sign.ContentVerifier;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.crypto.AltSigningCapability;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

/**
 * Builds and validates root certificate encodings against the captured algorithm authority.
 */
final class RootCertificateEncoding {
    private final PkiStore store;
    private final SigningProvider provider;
    private final AlgorithmIdentity signature;
    private final X509AuthoritySnapshot authority;
    private final X509AlgorithmBindingRegistry bindings;

    /* default */ RootCertificateEncoding(PkiStore store, SigningProvider provider, AlgorithmIdentity signature,
            X509AuthoritySnapshot authority, X509AlgorithmBindingRegistry bindings) {
        this.store = store;
        this.provider = provider;
        this.signature = signature;
        this.authority = authority;
        this.bindings = bindings;
    }
    /* default */ byte[] buildTbs(Optional<KeyRef> alternativeKey, HybridCertificateMode hybridMode,
            ValidatedCaCertificateRequest approved,
            AlgorithmIdentifier algorithm, X500Principal subject, byte[] spki, Validity validity,
            CancellationSignal cancellation) throws IOException {
        if (!(hybridMode instanceof HybridCertificateMode.AltSignature altSig)) {
            return Pkix.certificateBuilder()
                    .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                    .validity(validity.notBefore(), validity.notAfter())
                    .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                            approved.policy().basicConstraintsCritical())
                    .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                            approved.policy().keyUsageCritical())
                    .buildTbs(algorithm);
        }
        // Hybrid: AltSignature mode — build pre-TBS, sign with alt key, build final TBS.
        KeyRef altKeyRef = alternativeKey.orElseGet(() -> new KeyRef(altSig.altKeyRef()));
        byte[] altSpki = publicKeyInfo(altKeyRef, cancellation);
        AlgorithmIdentity altIdentity = authority.resolveIdentity(altSig.altSignatureAlgorithmId());
        if (altIdentity.kind() != AlgorithmIdentity.Kind.SIGNATURE) { throw reject("ALT_ALGORITHM_INVALID"); }
        X509SecurityFloor.requirePermitted(altIdentity);
        X509AlgorithmBinding altSigBinding = bindings.standard(altIdentity,
                X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE)
                .orElseThrow(() -> reject("ALT_ALGORITHM_BINDING_MISSING"));
        AlgorithmIdentifier altAlgId = toAltAlgorithmIdentifier(altSigBinding);
        byte[] preTbs = Pkix.certificateBuilder()
                .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                .validity(validity.notBefore(), validity.notAfter())
                .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                        approved.policy().basicConstraintsCritical())
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                        approved.policy().keyUsageCritical())
                .addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(altSpki))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgId))
                .buildAlternativeSignatureTbs(algorithm);
        if (preTbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("TBS_TOO_LARGE"); }
        if (!(provider instanceof AltSigningCapability altSigner)) { throw reject("ALT_SIGNING_CAPABILITY_UNAVAILABLE"); }
        cancellation.throwIfCancelled();
        byte[] altSignatureBytes;
        try {
            altSignatureBytes = altSigner.sign(altKeyRef, altSig.altSignatureAlgorithmId(), preTbs);
        } catch (GeneralSecurityException e) {
            throw new PkiException("Alt signature failed: code=ALT_SIGNING_FAILED", e);
        }
        if (altSignatureBytes == null || altSignatureBytes.length == 0
                || altSignatureBytes.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("ALT_SIGNATURE_INVALID"); }
        ContentVerifier verifier = Pkix.verifier(altSpki, altAlgId);
        try (OutputStream output = verifier.contentStream()) { output.write(preTbs); }
        if (!verifier.verify(altSignatureBytes)) { throw reject("ALT_SIGNATURE_INVALID"); }
        return Pkix.certificateBuilder()
                .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                .validity(validity.notBefore(), validity.notAfter())
                .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                        approved.policy().basicConstraintsCritical())
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                        approved.policy().keyUsageCritical())
                .addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(altSpki))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgId))
                .addExtension(AltSignatureExtensions.altSignatureValue(altSignatureBytes))
                .buildTbs(algorithm);
    }

    /* default */ byte[] publicKeyInfo(KeyRef keyRef, CancellationSignal cancellation) throws IOException {
        if (!(provider instanceof PublicKeyInfoSource source)
                || !provider.supportedAlgorithms().contains(signature.canonicalForm())) { throw reject("PUBLIC_KEY_SOURCE_UNAVAILABLE"); }
        cancellation.throwIfCancelled();
        EncodedObject exported = Objects.requireNonNull(source.resolvePublicKeyInfo(keyRef), "publicKeyInfo");
        cancellation.throwIfCancelled();
        if (exported.encoding() != Encoding.DER || exported.byteLength() < 1
                || exported.byteLength() > ManagedKeyProofCommand.MAX_SPKI_BYTES) { throw reject("PUBLIC_KEY_ENCODING_INVALID"); }
        byte[] spki = exported.bytes();
        new StreamingDerReader().validateSubjectPublicKeyInfo(spki, ManagedKeyProofCommand.MAX_SPKI_BYTES);
        return spki;
    }

    /* default */ AlgorithmIdentifier algorithm(ValidatedCaCertificateRequest request) {
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentifier subjectAlgorithm = Pkix.subjectPublicKeyAlgorithm(request.exactPublicKey().bytes());
        AlgorithmIdentity subjectKey = adapter.decode(subjectAlgorithm, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(signature, subjectKey);
        X509AlgorithmBindingPolicy policy = request.algorithmBindingPolicy();
        X509AlgorithmBinding signingBinding = binding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                policy.certificateSignature());
        X509ExecutionPlan<SigningProvider> plan = authority.plan(signature, subjectKey, Direction.SIGN, Optional.empty(),
                "explicit", signingBinding.bindingId(), SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        X509AlgorithmBinding subjectBinding = binding(subjectKey, X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY, policy.subjectPublicKey());
        AlgorithmIdentifier expected = BcX509AlgorithmAdapter.toLib(authority.bindings().resolve(subjectBinding.bindingId(),
                subjectKey, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        if (!subjectAlgorithm.equals(expected)) { throw reject("SUBJECT_BINDING_DIFFERS"); }
        return BcX509AlgorithmAdapter.toLib(plan.selection().binding());
    }

    /* default */ X509AlgorithmBinding binding(AlgorithmIdentity identity, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(identity, role).orElseThrow(() -> reject("BINDING_MISSING")));
        if (selected.role() != role || !selected.algorithmIdentity().equals(identity)
                || reference.isPresent() && selected.origin() == X509AlgorithmBinding.Origin.STANDARD) { throw reject("BINDING_DIFFERS"); }
        return selected;
    }

    /* default */ static AlgorithmIdentifier toAltAlgorithmIdentifier(X509AlgorithmBinding binding) {
        return switch (binding.parameterRule()) {
            case ABSENT -> AlgorithmIdentifier.absent(binding.oid());
            case DER_NULL -> AlgorithmIdentifier.derNull(binding.oid());
            case STRUCTURED_DER -> throw reject("ALT_ALGORITHM_PARAMETER_RULE_UNSUPPORTED");
        };
    }
    private static PkiException reject(String code) { return new PkiException("Root creation rejected: code=" + code); }

    /* default */ void requireHybridContinuity(PkiId caId, Credential selected, CaProfileBinding historical,
            ActiveCertificateProfile active, CancellationSignal cancellation) throws IOException {
        ImportedCertificateProfileVersion previous = store.getProfileVersion(
                historical.reference().profileId(), historical.reference().profileVersion())
                .orElseThrow(() -> reject("ROOT_PROFILE_MISSING"));
        if (!previous.reference().equals(historical.reference())) { throw reject("ROOT_PROFILE_BINDING_INVALID"); }
        HybridCertificateMode oldMode = previous.definition().hybridMode();
        HybridCertificateMode newMode = active.definition().hybridMode();
        if (!oldMode.getClass().equals(newMode.getClass())) { throw reject("HYBRID_MODE_CHANGE_UNSUPPORTED"); }
        if (newMode instanceof HybridCertificateMode.AltSignature) {
            byte[] encoded = CredentialContent.materializeForBc(store, selected.content());
            X509Certificate certificate = Pkix.parseCertificate(encoded);
            byte[] expected = AltSignatureExtensions.requiredValue(certificate,
                    AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
            // A creation profile's original key is not the authority after an explicit generation rotation.
            IssuerCryptographicBinding retained = store.getIssuerCryptographicBinding(IssuerGeneration.idFor(caId, selected.credentialId()))
                    .orElseThrow(() -> reject("ISSUER_BINDING_MISSING"));
            IssuerKeyBinding alternative = retained.alternative().orElseThrow(() -> reject("ALT_ROLE_CONTINUITY_INVALID"));
            byte[] configured = publicKeyInfo(alternative.keyRef(), cancellation);
            byte[] algorithm = alternative.signatureAlgorithmIdentifier().bytes();
            IssuerCryptographicBinding.HybridSignatureBaseline baseline = retained.certificateHybridBaseline();
            boolean signatureValid = baseline == IssuerCryptographicBinding.HybridSignatureBaseline.COR3_SIGNED_WRAPPER
                    ? Pkix.verifyAlternativeSignatureCor3(certificate, Pkix.publicKeyFromSubjectPublicKeyInfo(expected))
                    : baseline == IssuerCryptographicBinding.HybridSignatureBaseline.LEGACY_PRE_TBS
                            && Pkix.verifyAlternativeSignature(certificate, Pkix.publicKeyFromSubjectPublicKeyInfo(expected));
            if (!Arrays.equals(expected, configured)
                    || !alternative.subjectSpkiSha256().equals(SigningProvider.ContentCommitment.sha256(expected).sha256())
                    || !Arrays.equals(algorithm,
                            AltSignatureExtensions.requiredValue(certificate,
                                    AltSignatureExtensions.OID_ALT_SIGNATURE_ALGORITHM))
                    || !signatureValid) {
                throw reject("ALT_KEY_CONTINUITY_INVALID");
            }
        }
    }

    /* default */ static Validity wholeSecondValidity(Validity approved) {
        Instant start = approved.notBefore().truncatedTo(ChronoUnit.SECONDS);
        if (start.isBefore(approved.notBefore())) { start = start.plusSeconds(1); }
        Instant end = approved.notAfter().truncatedTo(ChronoUnit.SECONDS);
        if (!end.isAfter(start)) { throw reject("VALIDITY_NOT_REPRESENTABLE"); }
        return new Validity(start, end);
    }
}
