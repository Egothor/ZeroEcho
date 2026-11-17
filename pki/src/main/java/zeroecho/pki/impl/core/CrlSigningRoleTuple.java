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

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.sig.SignatureInteropProfile;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.context.SignatureContext;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pkix.Pkix;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Pure public CRL role evidence, compatibility hashes and finite signature bounds.
 */
public final class CrlSigningRoleTuple {
    private CrlSigningRoleTuple() { }

    /**
     * Hashes the actual signer tuple, excluding certificate identities and profile versions.
     * @param binding exact immutable outgoing signer binding
     * @param certificate bounded issuer certificate
     * @param nativeAlgorithm actual native CRL AlgorithmIdentifier DER
     * @param alternativeAlgorithm actual alternative AlgorithmIdentifier DER, empty for native-only issuers
     * @return canonical lowercase SHA-256 compatibility commitment
     * @throws IOException if public certificate evidence is malformed
     */
    public static String commitment(IssuerCryptographicBinding binding, X509Certificate certificate,
            byte[] nativeAlgorithm, byte[] alternativeAlgorithm) throws IOException {
        byte[] primary = Pkix.subjectPublicKeyInfo(certificate);
        requireDigest(binding.primary(), primary);
        byte[] alternative = binding.alternative().isPresent() ? alternativeSpki(certificate) : new byte[0];
        if (binding.alternative().isPresent()) { requireDigest(binding.alternative().orElseThrow(), alternative); }
        return hash("zeroecho-crl-role-tuple-v1", certificate.getSubjectX500Principal().getEncoded(),
                keyIdentifier(certificate), primary, nativeAlgorithm,
                binding.primary().publicKeyAlgorithm().canonicalForm().getBytes(StandardCharsets.UTF_8),
                binding.primary().signatureAlgorithm().canonicalForm().getBytes(StandardCharsets.UTF_8),
                alternative, alternativeAlgorithm,
                binding.alternative().map(key -> key.publicKeyAlgorithm().canonicalForm()).orElse("").getBytes(StandardCharsets.UTF_8),
                binding.alternative().map(key -> key.signatureAlgorithm().canonicalForm()).orElse("").getBytes(StandardCharsets.UTF_8),
                "ZEROECHO_CRL_ALT_BC186_V1".getBytes(StandardCharsets.US_ASCII));
    }

    private static void requireDigest(IssuerKeyBinding binding, byte[] spki) throws IOException {
        try {
            if (!binding.subjectSpkiSha256().equals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spki))))
                { throw new IOException("CRL subject public key differs from immutable binding"); }
        } catch (GeneralSecurityException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Derives the exact key identifier without interpreting a contributed public-key OID.
     * @param certificate bounded issuer certificate
     * @return supplied SKI or standard SHA-1 of subjectPublicKey BIT STRING contents
     * @throws IOException for malformed public evidence
     * @throws IllegalStateException if the key identifier cannot be derived with the required cryptographic engine
     */
    public static byte[] keyIdentifier(X509Certificate certificate) throws IOException {
        byte[] extension = certificate.getExtensionValue(X509ExtensionOids.subjectKeyIdentifier());
        if (extension != null) { return FullCrlTbsPreparation.decodeKeyIdentifier(extension); }
        try {
            byte[] publicBits = SubjectPublicKeyInfo.getInstance(
                    Pkix.subjectPublicKeyInfo(certificate)).getPublicKeyData().getBytes();
            return MessageDigest.getInstance("SHA-1").digest(publicBits);
        } catch (GeneralSecurityException impossible) { throw new IllegalStateException(impossible); }
    }

    /**
     * Returns the issuer's alternative SUBJECT SPKI, never its incoming signing key.
     * @param certificate bounded issuer certificate
     * @return exact alternative SPKI DER
     * @throws IOException if the extension is absent or malformed
     */
    public static byte[] alternativeSpki(X509Certificate certificate) throws IOException {
        return AltSignatureExtensions.requiredValue(certificate, AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
    }

    /**
     * Checks exact public-key and outgoing algorithm evidence without managed-key access.
     * @param binding frozen role descriptor
     * @param spki exact subject SPKI DER
     * @param authority configured public authority
     */
    public static void validate(IssuerKeyBinding binding, byte[] spki, X509AuthoritySnapshot authority) {
        IssuerBindingResolver.publicEvidenceVerifier(authority).verify(binding, new EncodedObject(Encoding.DER, spki));
    }

    /**
     * Computes a byte bound using a PUBLIC verification context, without signing probes.
     * @param binding frozen signing role
     * @param spki exact configured SPKI DER
     * @param authority configured public authority
     * @return maximum external signature bytes, at most the existing one-MiB cap
     * @throws GeneralSecurityException if a supported public context cannot be initialized
     * @throws IOException if configured public SPKI wrapping is invalid
     */
    public static int maximumSignatureBytes(IssuerKeyBinding binding, byte[] spki, X509AuthoritySnapshot authority)
            throws GeneralSecurityException, IOException {
        validate(binding, spki, authority);
        SignatureInteropProfile profile = SignatureInteropProfiles.resolve(binding.signatureAlgorithm().canonicalForm())
                .orElseThrow(() -> new GeneralSecurityException("CRL signature profile is unsupported"));
        byte[] nativeSpki = new BcX509PublicKeyAdapter(authority.bindings()).unwrap(spki);
        try (SignatureContext context = new ZeroEchoSession().createContext(profile.contextAlgorithmId(), KeyUsage.VERIFY,
                Pkix.publicKeyFromSubjectPublicKeyInfo(nativeSpki), profile.contextSpec())) {
            int bound = context.tagLength();
            if (profile.signatureRepresentation() == SignatureInteropProfile.SignatureRepresentation.ECDSA_DER_EXTERNAL_P1363_INTERNAL)
                { bound = Math.addExact(bound, 8); }
            return bound > 0 && bound <= 1_048_576 ? bound : 1_048_576;
        }
    }

    /**
     * Commits the selected implementation and exact public algorithm presentation.
     * @param plan already resolved role execution plan
     * @param bindingId actual role/profile-selected binding identifier
     * @param semanticCommitment actual selected binding semantic commitment
     * @return canonical SHA-256 plan commitment
     */
    public static String planCommitment(X509ExecutionPlan<?> plan, String bindingId, String semanticCommitment) {
        X509AlgorithmResolver.Selection selected = plan.selection();
        return hash("zeroecho-crl-plan-v1", selected.requested().canonicalForm().getBytes(StandardCharsets.UTF_8),
                selected.suite().signature().canonicalForm().getBytes(StandardCharsets.UTF_8),
                selected.suite().publicKey().canonicalForm().getBytes(StandardCharsets.UTF_8),
                selected.direction().name().getBytes(StandardCharsets.US_ASCII),
                selected.authorityFingerprint().getBytes(StandardCharsets.UTF_8),
                selected.provenance().getBytes(StandardCharsets.UTF_8),
                bindingId.getBytes(StandardCharsets.UTF_8), semanticCommitment.getBytes(StandardCharsets.UTF_8),
                selected.implementation().implementationId().getBytes(StandardCharsets.UTF_8),
                selected.implementation().domainFingerprint().getBytes(StandardCharsets.UTF_8),
                Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(selected.binding())));
    }

    /**
     * Hashes independently length-framed public values with a domain separator.
     * @param domain fixed semantic hash domain
     * @param values ordered bounded public values
     * @return lowercase SHA-256
     * @throws IllegalStateException if role encoding or cryptographic commitment calculation fails
     */
    public static String hash(String domain, byte[]... values) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeUTF(domain);
                for (byte[] value : values) { output.writeInt(value.length); output.write(value); }
            }
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(buffer.toByteArray()));
        } catch (IOException | GeneralSecurityException impossible) { throw new IllegalStateException(impossible); }
    }
}
