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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import java.security.cert.X509Certificate;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.store.PkiStore;

/** Deterministic generation-specific public evidence validation; never applies a realm fallback. */
public final class IssuerBindingResolver {
    private IssuerBindingResolver() { }

    /**
     * Validates a frozen generation against its exact credential and live managed public keys.
     * Historical public-only readers should read the binding directly rather than require live keys.
     * @param store authoritative immutable credential and binding store
     * @param generation already selected exact generation; never retargeted here
     * @param keys managed provider public-key source
     * @param authority immutable installed algorithm authority
     * @return exact validated persisted binding
     * @throws IllegalStateException for absent, incompatible or changed evidence
     */
    public static IssuerCryptographicBinding resolve(PkiStore store, IssuerGeneration generation,
            PublicKeyInfoSource keys, X509AuthoritySnapshot authority) {
        Objects.requireNonNull(store, "store"); Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(keys, "keys"); Objects.requireNonNull(authority, "authority");
        IssuerCryptographicBinding binding = store.getIssuerCryptographicBinding(generation.issuerId())
                .orElseThrow(() -> invalid("Missing explicit issuer binding; initialize a fresh empty PKI store"));
        var credential = store.getCredential(generation.credentialId()).orElseThrow(() -> invalid("Missing issuer credential"));
        if (!binding.issuerId().equals(generation.issuerId()) || !binding.authorityId().equals(generation.authorityId())
                || !binding.credentialId().equals(generation.credentialId())
                || !binding.primary().keyRef().equals(generation.signingKeyRef())
                || !binding.formatId().equals(credential.formatId().value())
                || !HexFormat.of().formatHex(binding.profile().canonicalSha256()).equals(generation.profilePolicyCommitment())) {
            throw invalid("Issuer binding identity differs");
        }
        byte[] certificate = CredentialContent.materializeForBc(store, credential.content());
        if (!digest(certificate).equals(binding.certificateSha256())) { throw invalid("Issuer credential digest differs"); }
        try {
            X509Certificate holder = zeroecho.pkix.Pkix.parseCertificate(certificate);
            validateKey(binding.primary(), zeroecho.pkix.Pkix.subjectPublicKeyInfo(holder), keys, authority);
            byte[] extension = holder.getExtensionValue("2.5.29.72");
            if (binding.alternative().isPresent()) {
                if (extension == null) { throw invalid("Alternative issuer subject key missing"); }
                validateKey(binding.alternative().orElseThrow(), org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets(), keys, authority);
            } else if (extension != null) { throw invalid("Unexpected alternative issuer subject key"); }
            return binding;
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalStateException("Issuer cryptographic evidence is invalid", failure);
        }
    }

    /** Explicit alternative outgoing signer selection; contains public identity only.
     * @param keyRef managed signing key @param signatureAlgorithm exact outgoing signature */
    public record AlternativeSelection(zeroecho.pki.api.KeyRef keyRef, zeroecho.core.spec.AlgorithmIdentity signatureAlgorithm) {
        /** Creates a complete explicit alternative signer selection. */
        public AlternativeSelection { Objects.requireNonNull(keyRef, "keyRef"); Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm"); }
    }

    /**
     * Constructs public authority from explicit outgoing selectors and the issued CA's own subject keys.
     * Incoming parent signatures never choose outgoing algorithms. No state is persisted here.
     * @param generation immutable generation @param certificateDer exact issued CA certificate
     * @param formatId credential format @param outgoingPrimarySignature explicit outgoing signature
     * @param alternative explicit optional alternative signer @param keys provider public key source
     * @param authority immutable algorithm authority @param baseline retained certificate encoding baseline
     * @param profile exact creation profile @param bindingSetCommitment captured active binding-set digest
     * @return complete explicit binding ready for paired publication
     */
    public static IssuerCryptographicBinding create(IssuerGeneration generation, byte[] certificateDer, String formatId,
            zeroecho.core.spec.AlgorithmIdentity outgoingPrimarySignature, java.util.Optional<AlternativeSelection> alternative,
            PublicKeyInfoSource keys, X509AuthoritySnapshot authority,
            IssuerCryptographicBinding.HybridSignatureBaseline baseline,
            zeroecho.pki.api.profile.CertificateProfileRef profile, String bindingSetCommitment) {
        try {
            var certificate = zeroecho.pkix.Pkix.parseCertificate(certificateDer);
            IssuerKeyBinding primary = createKey(generation.signingKeyRef(), outgoingPrimarySignature,
                    zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate), keys, authority);
            java.util.Optional<IssuerKeyBinding> alternate = java.util.Optional.empty();
            if (alternative.isPresent()) {
                var selected = alternative.orElseThrow();
                byte[] extension = certificate.getExtensionValue("2.5.29.72");
                if (extension == null) { throw invalid("Alternative CA subject key missing"); }
                alternate = java.util.Optional.of(createKey(selected.keyRef(), selected.signatureAlgorithm(),
                        org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets(), keys, authority));
            } else if (certificate.getExtensionValue("2.5.29.72") != null) {
                throw invalid("Alternative CA signer selection missing");
            }
            String certificateDigest = digest(certificateDer);
            var initial = new IssuerCryptographicBinding(1, generation.issuerId(), generation.authorityId(), generation.credentialId(),
                    formatId, primary, alternate, certificateDigest, profile, bindingSetCommitment, baseline,
                    "0".repeat(64));
            String evidence = digest(("zeroecho-issuer-creation-v1\n" + initial.commitment()).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return new IssuerCryptographicBinding(1, generation.issuerId(), generation.authorityId(), generation.credentialId(),
                    formatId, primary, alternate, certificateDigest, profile, bindingSetCommitment, baseline,
                    evidence);
        } catch (IOException failure) { throw new IllegalStateException("Issuer certificate evidence invalid", failure); }
    }

    /** Creates public key authority from explicit outgoing selection and matching managed subject key.
     * @param reference managed signing key @param signature exact outgoing signature
     * @param spki expected certificate subject key @param keys managed public source
     * @param authority immutable installed authority @return validated immutable key binding
     * @throws IOException for unencodable public evidence */
    public static IssuerKeyBinding createKey(zeroecho.pki.api.KeyRef reference, zeroecho.core.spec.AlgorithmIdentity signature,
            byte[] spki, PublicKeyInfoSource keys, X509AuthoritySnapshot authority) throws IOException {
        var adapter = new BcX509AlgorithmAdapter(authority.bindings());
        var identity = adapter.decode(zeroecho.pkix.Pkix.subjectPublicKeyAlgorithm(spki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        var algorithm = zeroecho.pkix.Pkix.encodeAlgorithmIdentifier(adapter.encode(signature, X509AlgorithmRole.SIGNATURE_ALGORITHM));
        var binding = new IssuerKeyBinding(reference, identity, signature,
                new zeroecho.pki.api.EncodedObject(Encoding.DER, algorithm), digest(spki));
        validateKey(binding, spki, keys, authority);
        return binding;
    }

    private static void validateKey(IssuerKeyBinding binding, byte[] subjectSpki, PublicKeyInfoSource keys,
            X509AuthoritySnapshot authority) throws IOException {
        var exported = Objects.requireNonNull(keys.resolvePublicKeyInfo(binding.keyRef()), "publicKeyInfo");
        if (exported.encoding() != Encoding.DER || exported.byteLength() > 32768
                || !digest(subjectSpki).equals(binding.subjectSpkiSha256())
                || !MessageDigest.isEqual(subjectSpki, exported.bytes())) { throw invalid("Issuer managed key evidence differs"); }
        validatePublicAlgorithms(binding, subjectSpki, new BcX509AlgorithmAdapter(authority.bindings()));
    }

    /**
     * Captures immutable configured public algorithm rules without retaining providers or defaults.
     * @param authority exact trusted public algorithm authority
     * @return public-only verifier suitable for store startup and historical validation
     */
    public static zeroecho.pki.spi.store.IssuerAlgorithmEvidenceVerifier publicEvidenceVerifier(X509AuthoritySnapshot authority) {
        return publicEvidenceVerifier(new BcX509AlgorithmAdapter(Objects.requireNonNull(authority, "authority").bindings()));
    }

    /** @return immutable built-in standard and ZeroEcho-private public algorithm validation rules */
    public static zeroecho.pki.spi.store.IssuerAlgorithmEvidenceVerifier defaultPublicEvidenceVerifier() {
        return PublicEvidenceDefaults.VERIFIER;
    }

    private static final class PublicEvidenceDefaults {
        private static final zeroecho.pki.spi.store.IssuerAlgorithmEvidenceVerifier VERIFIER = publicEvidenceVerifier(
                new BcX509AlgorithmAdapter(zeroecho.pki.impl.framework.x509.X509BindingCatalog.builtIn(java.util.stream.Stream.concat(
                        zeroecho.pki.impl.framework.x509.StandardX509Bindings.catalog().rules().stream(),
                        zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings.catalog().rules().stream()).toList())));
    }

    private static zeroecho.pki.spi.store.IssuerAlgorithmEvidenceVerifier publicEvidenceVerifier(BcX509AlgorithmAdapter adapter) {
        return (binding, publicKey) -> {
            if (publicKey.encoding() != Encoding.DER) { throw invalid("Issuer public key is not DER"); }
            try { validatePublicAlgorithms(binding, publicKey.bytes(), adapter); }
            catch (IOException failure) { throw new IllegalStateException("Issuer public algorithm evidence invalid", failure); }
        };
    }

    private static void validatePublicAlgorithms(IssuerKeyBinding binding, byte[] subjectSpki,
            BcX509AlgorithmAdapter adapter) throws IOException {
        if (!digest(subjectSpki).equals(binding.subjectSpkiSha256())) { throw invalid("Issuer public-key digest differs"); }
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(subjectSpki);
        if (!MessageDigest.isEqual(subjectSpki, info.getEncoded("DER"))) { throw invalid("Noncanonical subject public key"); }
        if (!binding.publicKeyAlgorithm().equals(adapter.decode(zeroecho.pkix.Pkix.subjectPublicKeyAlgorithm(subjectSpki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM))) {
            throw invalid("Issuer public-key algorithm differs");
        }
        AlgorithmIdentifier signature = AlgorithmIdentifier.getInstance(binding.signatureAlgorithmIdentifier().bytes());
        if (!MessageDigest.isEqual(signature.getEncoded("DER"), binding.signatureAlgorithmIdentifier().bytes())
                || !binding.signatureAlgorithm().equals(adapter.decode(zeroecho.pkix.Pkix.parseAlgorithmIdentifier(binding.signatureAlgorithmIdentifier().bytes()), X509AlgorithmRole.SIGNATURE_ALGORITHM))) {
            throw invalid("Issuer outgoing signature algorithm differs");
        }
        X509SuiteCompatibility.requireCompatible(binding.signatureAlgorithm(), binding.publicKeyAlgorithm());
    }
    /**
     * Publishes authority from evidence captured before signing, without consulting mutable providers or defaults.
     * @param generation exact generation @param certificateDer exact issued certificate
     * @param formatId credential format @param primary captured primary signer
     * @param alternative captured alternative signer @param baseline own certificate encoding baseline
     * @param profile frozen profile @param bindingSetCommitment frozen binding-set digest
     * @return immutable complete binding ready for atomic publication
     */
    public static IssuerCryptographicBinding createCaptured(IssuerGeneration generation, byte[] certificateDer, String formatId,
            IssuerKeyBinding primary, java.util.Optional<IssuerKeyBinding> alternative,
            IssuerCryptographicBinding.HybridSignatureBaseline baseline,
            zeroecho.pki.api.profile.CertificateProfileRef profile, String bindingSetCommitment) {
        var certificate = zeroecho.pkix.Pkix.parseCertificate(certificateDer);
        if (!primary.keyRef().equals(generation.signingKeyRef())
                || !digest(zeroecho.pkix.Pkix.subjectPublicKeyInfo(certificate)).equals(primary.subjectSpkiSha256())) {
            throw invalid("Captured primary issuer evidence differs");
        }
        byte[] extension = certificate.getExtensionValue("2.5.29.72");
        if (alternative.isPresent()) {
            if (extension == null || !digest(org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets())
                    .equals(alternative.orElseThrow().subjectSpkiSha256())) { throw invalid("Captured alternative issuer evidence differs"); }
        } else if (extension != null) { throw invalid("Uncaptured alternative issuer key"); }
        var initial = new IssuerCryptographicBinding(1, generation.issuerId(), generation.authorityId(), generation.credentialId(), formatId,
                primary, alternative, digest(certificateDer), profile, bindingSetCommitment, baseline,
                "0".repeat(64));
        String evidence = digest(("zeroecho-issuer-creation-v1\n" + initial.commitment()).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return new IssuerCryptographicBinding(1, initial.issuerId(), initial.authorityId(), initial.credentialId(), initial.formatId(),
                primary, alternative, initial.certificateSha256(), profile, bindingSetCommitment, baseline,
                evidence);
    }

    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static IllegalStateException invalid(String message) { return new IllegalStateException(message); }
}
