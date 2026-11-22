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

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.stream.Stream;
import zeroecho.pkix.PkixEncoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.framework.x509.StandardX509Bindings;
import zeroecho.pki.impl.framework.x509.X509BindingCatalog;
import zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings;
import zeroecho.pki.spi.store.IssuerAlgorithmEvidenceVerifier;
import zeroecho.pkix.Pkix;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Creates and validates public signing evidence for an explicitly selected issuer generation.
 *
 * <p>Outgoing signing algorithms come from captured selections, never from an incoming
 * parent signature or a realm default. Live validation checks managed public-key
 * availability; public-only verifiers can instead validate retained evidence without
 * access to private keys or signing providers. This utility does not publish store state.
 */
public final class IssuerBindingResolver {
    private IssuerBindingResolver() {
    }

    /**
     * Validates a frozen generation against its exact credential and live managed public keys.
     * Historical public-only readers should read the binding directly rather than require live keys.
     * @param store authoritative immutable credential and binding store
     * @param generation already selected exact generation; never retargeted here
     * @param keys managed provider public-key source
     * @param authority immutable installed algorithm authority
     * @return exact validated persisted binding
     * @throws NullPointerException if a required argument or resolved public-key value is null
     * @throws IllegalStateException for absent, incompatible or changed evidence
     */
    public static IssuerCryptographicBinding resolve(PkiStore store, IssuerGeneration generation,
            PublicKeyInfoSource keys, X509AuthoritySnapshot authority) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(generation, "generation");
        Objects.requireNonNull(keys, "keys");
        Objects.requireNonNull(authority, "authority");
        IssuerCryptographicBinding binding = store.getIssuerCryptographicBinding(generation.issuerId())
                .orElseThrow(() -> invalid("Missing explicit issuer binding; initialize a fresh empty PKI store"));
        Credential credential = store.getCredential(generation.credentialId())
                .orElseThrow(() -> invalid("Missing issuer credential"));
        if (!binding.issuerId().equals(generation.issuerId()) || !binding.authorityId().equals(generation.authorityId())
                || !binding.credentialId().equals(generation.credentialId())
                || !binding.primary().keyRef().equals(generation.signingKeyRef())
                || !binding.formatId().equals(credential.formatId().value())
                || !HexFormat.of().formatHex(binding.profile().canonicalSha256()).equals(generation.profilePolicyCommitment())) {
            throw invalid("Issuer binding identity differs");
        }
        byte[] certificate = CredentialContent.materializeForBc(store, credential.content());
        if (!digest(certificate).equals(binding.certificateSha256())) {
            throw invalid("Issuer credential digest differs");
        }
        try {
            X509Certificate holder = Pkix.parseCertificate(certificate);
            validateKey(binding.primary(), Pkix.subjectPublicKeyInfo(holder), keys, authority);
            byte[] extension = holder.getExtensionValue(X509ExtensionOids.subjectAltPublicKeyInfo());
            if (binding.alternative().isPresent()) {
                if (extension == null) {
                    throw invalid("Alternative issuer subject key missing");
                }
                validateKey(binding.alternative().orElseThrow(),
                        PkixEncoding.octetStringContents(extension), keys, authority);
            } else if (extension != null) {
                throw invalid("Unexpected alternative issuer subject key");
            }
            return binding;
        } catch (IOException | IllegalArgumentException failure) {
            throw new IllegalStateException("Issuer cryptographic evidence is invalid", failure);
        }
    }

    /**
     * Selects an existing managed key and exact outgoing algorithm for the alternative role.
     *
     * <p>The selection contains public identity coordinates only. It does not prove
     * key possession or grant permission to use the managed private key.
     *
     * @param keyRef existing managed signing key; must not be {@code null}
     * @param signatureAlgorithm exact outgoing signature identity; must not be {@code null}
     */
    public record AlternativeSelection(KeyRef keyRef, AlgorithmIdentity signatureAlgorithm) {
        /**
         * Requires both coordinates of the alternative signer selection.
         *
         * @throws NullPointerException if either coordinate is null
         * @param keyRef existing managed signing key; must not be {@code null}
         * @param signatureAlgorithm exact outgoing signature identity; must not be {@code null}
         */
        public AlternativeSelection {
            Objects.requireNonNull(keyRef, "keyRef");
            Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
        }
    }

    /**
     * Constructs a generation binding from explicit selectors and the issued CA's subject keys.
     *
     * <p>Each selected managed public key must match the certificate's corresponding
     * subject key and the installed algorithm rules. An alternative subject-key extension
     * and an alternative selection must either both be present or both be absent.
     * The incoming certificate signature does not select an outgoing signing algorithm.
     * This method constructs evidence only; the caller owns its atomic publication.
     *
     * @param generation immutable generation whose primary key is being bound
     * @param certificateDer exact issued CA certificate bytes, borrowed for this call
     * @param formatId credential format identifier
     * @param outgoingPrimarySignature explicitly selected outgoing primary signature
     * @param alternative explicit alternative signer, or an empty optional; must not be null
     * @param keys managed provider's public-key source
     * @param authority installed algorithm authority used to interpret the public evidence
     * @param baseline retained certificate-encoding baseline
     * @param profile exact creation profile reference
     * @param bindingSetCommitment captured active binding-set digest
     * @return a complete immutable binding ready for publication with its generation
     * @throws NullPointerException if a required coordinate or resolved public-key value is null
     * @throws IllegalArgumentException if certificate, algorithm or binding data is malformed
     * @throws IllegalStateException if public keys, role selections or algorithm evidence disagree,
     *         or the certificate evidence cannot be encoded
     */
    // Retain the established public binding-factory signature.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    public static IssuerCryptographicBinding create(IssuerGeneration generation, byte[] certificateDer, String formatId,
            AlgorithmIdentity outgoingPrimarySignature, Optional<AlternativeSelection> alternative,
            PublicKeyInfoSource keys, X509AuthoritySnapshot authority,
            IssuerCryptographicBinding.HybridSignatureBaseline baseline,
            CertificateProfileRef profile, String bindingSetCommitment) {
        try {
            X509Certificate certificate = Pkix.parseCertificate(certificateDer);
            IssuerKeyBinding primary = createKey(generation.signingKeyRef(), outgoingPrimarySignature,
                    Pkix.subjectPublicKeyInfo(certificate), keys, authority);
            Optional<IssuerKeyBinding> alternate = Optional.empty();
            if (alternative.isPresent()) {
                AlternativeSelection selected = alternative.orElseThrow();
                byte[] extension = certificate.getExtensionValue(X509ExtensionOids.subjectAltPublicKeyInfo());
                if (extension == null) {
                    throw invalid("Alternative CA subject key missing");
                }
                alternate = Optional.of(createKey(selected.keyRef(), selected.signatureAlgorithm(),
                        PkixEncoding.octetStringContents(extension), keys, authority));
            } else if (certificate.getExtensionValue(X509ExtensionOids.subjectAltPublicKeyInfo()) != null) {
                throw invalid("Alternative CA signer selection missing");
            }
            String certificateDigest = digest(certificateDer);
            IssuerCryptographicBinding initial = new IssuerCryptographicBinding(1, generation.issuerId(),
                    generation.authorityId(), generation.credentialId(),
                    formatId, primary, alternate, certificateDigest, profile, bindingSetCommitment, baseline,
                    "0".repeat(64));
            String evidence = digest(("zeroecho-issuer-creation-v1\n" + initial.commitment())
                    .getBytes(StandardCharsets.US_ASCII));
            return new IssuerCryptographicBinding(1, generation.issuerId(), generation.authorityId(), generation.credentialId(),
                    formatId, primary, alternate, certificateDigest, profile, bindingSetCommitment, baseline,
                    evidence);
        } catch (IOException failure) {
            throw new IllegalStateException("Issuer certificate evidence invalid", failure);
        }
    }

    /**
     * Binds an explicit outgoing signature algorithm to the matching managed subject key.
     *
     * <p>The expected SubjectPublicKeyInfo must be canonical DER and must equal the
     * public encoding resolved for the managed reference. Algorithm compatibility is
     * checked under the supplied authority; no private-key operation is performed.
     *
     * @param reference managed signing-key reference
     * @param signature exact outgoing signature identity
     * @param spki expected certificate SubjectPublicKeyInfo DER, borrowed for this call
     * @param keys managed provider's public-key source
     * @param authority installed public algorithm authority
     * @return a validated immutable public key binding
     * @throws IOException if public algorithm evidence cannot be encoded
     * @throws NullPointerException if a required coordinate or resolved public-key value is null
     * @throws IllegalArgumentException if public-key or algorithm encodings are malformed
     * @throws IllegalStateException if the managed key or its algorithm evidence does not match
     */
    public static IssuerKeyBinding createKey(KeyRef reference, AlgorithmIdentity signature,
            byte[] spki, PublicKeyInfoSource keys, X509AuthoritySnapshot authority) throws IOException {
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity identity = adapter.decode(Pkix.subjectPublicKeyAlgorithm(spki),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(adapter.encode(signature,
                X509AlgorithmRole.SIGNATURE_ALGORITHM));
        IssuerKeyBinding binding = new IssuerKeyBinding(reference, identity, signature,
                new EncodedObject(Encoding.DER, algorithm), digest(spki));
        validateKey(binding, spki, keys, authority);
        return binding;
    }

    private static void validateKey(IssuerKeyBinding binding, byte[] subjectSpki, PublicKeyInfoSource keys,
            X509AuthoritySnapshot authority) throws IOException {
        EncodedObject exported = Objects.requireNonNull(keys.resolvePublicKeyInfo(binding.keyRef()), "publicKeyInfo");
        if (exported.encoding() != Encoding.DER || exported.byteLength() > 32_768
                || !digest(subjectSpki).equals(binding.subjectSpkiSha256())
                || !MessageDigest.isEqual(subjectSpki, exported.bytes())) {
            throw invalid("Issuer managed key evidence differs");
        }
        validatePublicAlgorithms(binding, subjectSpki, new BcX509AlgorithmAdapter(authority.bindings()));
    }

    /**
     * Captures immutable configured public algorithm rules without retaining providers or defaults.
     * @param authority exact trusted public algorithm authority
     * @return public-only verifier suitable for store startup and historical validation
     * @throws NullPointerException if the authority is null
     */
    public static IssuerAlgorithmEvidenceVerifier publicEvidenceVerifier(X509AuthoritySnapshot authority) {
        return publicEvidenceVerifier(new BcX509AlgorithmAdapter(Objects.requireNonNull(authority, "authority").bindings()));
    }

    /**
     * Returns the shared public-evidence verifier for the built-in binding catalogs.
     *
     * <p>The verifier combines standard and ZeroEcho-private algorithm rules. It checks
     * public encodings and compatibility without resolving managed keys or consulting
     * a mutable realm default; it does not grant signing authority.
     *
     * @return the cached verifier using the immutable built-in algorithm bindings
     */
    public static IssuerAlgorithmEvidenceVerifier defaultPublicEvidenceVerifier() {
        return PublicEvidenceDefaults.VERIFIER;
    }

    /**
     * Retains the default public-evidence verifier without initializing it for callers that do not use it.
     *
     * <p>Class initialization publishes the shared verifier when the default
     * verification path is first selected.
     */
    private static final class PublicEvidenceDefaults {
        private static final IssuerAlgorithmEvidenceVerifier VERIFIER = publicEvidenceVerifier(
                new BcX509AlgorithmAdapter(X509BindingCatalog.builtIn(Stream.concat(
                        StandardX509Bindings.catalog().rules().stream(),
                        ZeroEchoPrivateX509Bindings.catalog().rules().stream()).toList())));
    }

    private static IssuerAlgorithmEvidenceVerifier publicEvidenceVerifier(BcX509AlgorithmAdapter adapter) {
        return (binding, publicKey) -> {
            if (publicKey.encoding() != Encoding.DER) {
                throw invalid("Issuer public key is not DER");
            }
            try {
                validatePublicAlgorithms(binding, publicKey.bytes(), adapter);
            } catch (IOException failure) {
                throw new IllegalStateException("Issuer public algorithm evidence invalid", failure);
            }
        };
    }

    private static void validatePublicAlgorithms(IssuerKeyBinding binding, byte[] subjectSpki,
            BcX509AlgorithmAdapter adapter) throws IOException {
        if (!digest(subjectSpki).equals(binding.subjectSpkiSha256())) {
            throw invalid("Issuer public-key digest differs");
        }
        if (!MessageDigest.isEqual(subjectSpki, PkixEncoding.canonicalDer(subjectSpki))) {
            throw invalid("Noncanonical subject public key");
        }
        if (!binding.publicKeyAlgorithm().equals(adapter.decode(Pkix.subjectPublicKeyAlgorithm(subjectSpki),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM))) {
            throw invalid("Issuer public-key algorithm differs");
        }
        if (!MessageDigest.isEqual(Pkix.encodeAlgorithmIdentifier(Pkix.parseAlgorithmIdentifier(binding.signatureAlgorithmIdentifier().bytes())), binding.signatureAlgorithmIdentifier().bytes())
                || !binding.signatureAlgorithm().equals(adapter.decode(Pkix.parseAlgorithmIdentifier(
                        binding.signatureAlgorithmIdentifier().bytes()), X509AlgorithmRole.SIGNATURE_ALGORITHM))) {
            throw invalid("Issuer outgoing signature algorithm differs");
        }
        X509SuiteCompatibility.requireCompatible(binding.signatureAlgorithm(), binding.publicKeyAlgorithm());
    }
    /**
     * Constructs a generation binding from signer evidence captured before issuance.
     *
     * <p>The captured primary reference must be the generation's signing key, and each
     * captured public-key digest must match the corresponding issued subject key.
     * No mutable provider or realm default is consulted. The caller remains responsible
     * for validating the captured evidence and atomically publishing the returned binding;
     * this method itself performs no store mutation or certificate-signature verification.
     *
     * @param generation exact immutable generation being published
     * @param certificateDer exact issued CA certificate bytes, borrowed for this call
     * @param formatId credential format identifier
     * @param primary captured primary signer binding
     * @param alternative captured alternative binding, or an empty optional; must not be null
     * @param baseline retained encoding baseline of the issued certificate
     * @param profile frozen creation profile reference
     * @param bindingSetCommitment frozen binding-set digest
     * @return a complete immutable binding ready for atomic publication
     * @throws NullPointerException if a required coordinate is null
     * @throws IllegalArgumentException if certificate or binding data is malformed
     * @throws IllegalStateException if a captured reference or subject-key digest disagrees
     */
    public static IssuerCryptographicBinding createCaptured(IssuerGeneration generation, byte[] certificateDer, String formatId,
            IssuerKeyBinding primary, Optional<IssuerKeyBinding> alternative,
            IssuerCryptographicBinding.HybridSignatureBaseline baseline,
            CertificateProfileRef profile, String bindingSetCommitment) {
        X509Certificate certificate = Pkix.parseCertificate(certificateDer);
        if (!primary.keyRef().equals(generation.signingKeyRef())
                || !digest(Pkix.subjectPublicKeyInfo(certificate)).equals(primary.subjectSpkiSha256())) {
            throw invalid("Captured primary issuer evidence differs");
        }
        byte[] extension = certificate.getExtensionValue(X509ExtensionOids.subjectAltPublicKeyInfo());
        if (alternative.isPresent()) {
            if (extension == null || !digest(PkixEncoding.octetStringContents(extension))
                    .equals(alternative.orElseThrow().subjectSpkiSha256())) {
                throw invalid("Captured alternative issuer evidence differs");
            }
        } else if (extension != null) {
            throw invalid("Uncaptured alternative issuer key");
        }
        IssuerCryptographicBinding initial = new IssuerCryptographicBinding(1, generation.issuerId(),
                generation.authorityId(), generation.credentialId(), formatId,
                primary, alternative, digest(certificateDer), profile, bindingSetCommitment, baseline,
                "0".repeat(64));
        String evidence = digest(("zeroecho-issuer-creation-v1\n" + initial.commitment()).getBytes(StandardCharsets.US_ASCII));
        return new IssuerCryptographicBinding(1, initial.issuerId(), initial.authorityId(), initial.credentialId(), initial.formatId(),
                primary, alternative, initial.certificateSha256(), profile, bindingSetCommitment, baseline,
                evidence);
    }

    private static String digest(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
    private static IllegalStateException invalid(String message) {
        return new IllegalStateException(message);
    }
}
