/*******************************************************************************
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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcEdDSAContentVerifierProviderBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.application.OcspResponseService;
import zeroecho.pki.application.PkiRepositoryContent;

/**
 * Transport-neutral signed-OCSP requester authentication and scoped query
 * authorization. Certificate trust proves eligibility only; an enabled persisted
 * principal and an explicit {@link Permission.Action#OCSP_STATUS_QUERY} grant are
 * independently required.
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CyclomaticComplexity",
        "PMD.AvoidInstantiatingObjectsInLoops", "PMD.FieldDeclarationsShouldBeAtStartOfClass",
        "PMD.ControlStatementBraces", "PMD.PreserveStackTrace", "PMD.AvoidLiteralsInIfCondition",
        "PMD.DataClass" })
public final class OcspRequesterService {
    private static final int MAXIMUM_CERTIFICATE_BYTES = 1_048_576;

    /** Exact bounded cryptographic fields retained from one canonical request. */
    public record SignedRequest(byte[] tbsRequest, byte[] requestorName, byte[] signatureAlgorithm,
            byte[] signature, List<byte[]> certificates) {
        /** Snapshots all security-sensitive input bytes. */
        public SignedRequest {
            tbsRequest = requireBytes(tbsRequest, "tbsRequest", 1_048_576);
            requestorName = requireBytes(requestorName, "requestorName", 65_536);
            signatureAlgorithm = requireBytes(signatureAlgorithm, "signatureAlgorithm", 4_096);
            signature = requireBytes(signature, "signature", 65_536);
            List<byte[]> exact = new ArrayList<>();
            for (byte[] certificate : Objects.requireNonNull(certificates, "certificates")) {
                exact.add(requireBytes(certificate, "certificate", MAXIMUM_CERTIFICATE_BYTES));
            }
            certificates = List.copyOf(exact);
        }
        @Override public byte[] tbsRequest() { return tbsRequest.clone(); }
        @Override public byte[] requestorName() { return requestorName.clone(); }
        @Override public byte[] signatureAlgorithm() { return signatureAlgorithm.clone(); }
        @Override public byte[] signature() { return signature.clone(); }
        @Override public List<byte[]> certificates() {
            return certificates.stream().map(byte[]::clone).toList();
        }
    }

    /** Safe successful authentication result. */
    public record Authorized(String principalId) {
        /** Validates the mapped principal identity. */
        public Authorized { Permission.requirePrincipal(principalId); }
    }

    /** Safe authentication or authorization rejection. */
    public static final class UnauthorizedException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String classification;
        /** Creates a redacted rejection. */
        public UnauthorizedException() { this("UNSPECIFIED"); }
        private UnauthorizedException(String classification) {
            super("OCSP requester is unauthorized");
            this.classification = classification;
        }
        /** @return safe non-secret internal rejection classification */
        public String classification() { return classification; }
    }

    /** Dependency corruption or recovery-required authorization authority. */
    public static final class UnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** Creates a redacted unavailable result. */
        public UnavailableException() { super("OCSP requester authority is unavailable"); }
    }

    private final ServerRealmContext realm;
    private final Clock clock;

    /** Creates one realm-bound requester authentication service. */
    public OcspRequesterService(ServerRealmContext realm, Clock clock) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Authenticates and authorizes every CertID in one signed request. Any failure
     * rejects the whole request without revealing the failed entry.
     */
    public Authorized authenticate(OcspResponderService.Responder responder, SignedRequest request,
            List<OcspResponseService.CertId> requests) {
        try {
            OcspResponderService.RequesterTrustPolicy policy = responder.requesterTrustPolicy().orElseThrow();
            List<X509Certificate> chain = certificates(request.certificates());
            X509Certificate signer = chain.getFirst();
            validateSigner(signer, request.requestorName());
            validateTrust(policy, chain);
            verifySignature(policy, signer, request);
            String principalId = mapPrincipal(policy, signer);
            SecurityPrincipal principal = realm.principal(principalId);
            if (!principal.enabled()) throw new UnauthorizedException("PRINCIPAL_DISABLED");
            validateRevocation(policy, signer);
            for (OcspResponseService.CertId certId : requests) {
                requireIssuer(responder, certId);
                if (!realm.authorizeOcspQuery(principalId, responder).allowed()) {
                    throw new UnauthorizedException("QUERY_DENIED");
                }
            }
            return new Authorized(principalId);
        } catch (UnauthorizedException rejection) {
            throw rejection;
        } catch (IllegalStateException unavailable) {
            throw new UnavailableException();
        } catch (RuntimeException | CertificateException | IOException failure) {
            throw new UnauthorizedException("VALIDATION_REJECTED");
        }
    }

    private void validateSigner(X509Certificate signer, byte[] requestorName) throws CertificateException {
        signer.checkValidity(Date.from(clock.instant()));
        requireCanonical(signer);
        if (signer.hasUnsupportedCriticalExtension()) throw new CertificateException("Unsupported critical extension");
        boolean[] usage = signer.getKeyUsage();
        if (usage != null && (usage.length == 0 || !usage[0])) throw new CertificateException("Signing usage denied");
        if (!Arrays.equals(requestorName, signer.getSubjectX500Principal().getEncoded())) {
            throw new UnauthorizedException("REQUESTOR_NAME");
        }
    }

    private void validateTrust(OcspResponderService.RequesterTrustPolicy policy, List<X509Certificate> chain)
            throws CertificateException, IOException {
        int matches = 0;
        String signerCommitment = digest(chain.getFirst().getEncoded());
        for (OcspResponderService.TrustSelector selector : policy.trustSelectors()) {
            if (selector.type() == OcspResponderService.TrustSelectorType.EXACT_REQUESTER_CERTIFICATE_COMMITMENTS) {
                if (selector.identities().contains(signerCommitment) && chain.size() == 1) matches++;
                continue;
            }
            for (String identity : selector.identities()) {
                X509Certificate anchor = selector.type() == OcspResponderService.TrustSelectorType.MANAGED_ISSUER_GENERATIONS
                        ? issuerCertificate(new PkiId(identity)) : credentialCertificate(new PkiId(identity));
                if (validPath(chain, anchor)) matches++;
            }
        }
        if (matches != 1) throw new UnauthorizedException("TRUST_PATH");
    }

    private boolean validPath(List<X509Certificate> chain, X509Certificate anchor) {
        try {
            Set<String> seen = new HashSet<>();
            for (X509Certificate certificate : chain) {
                certificate.checkValidity(Date.from(clock.instant()));
                requireCanonical(certificate);
                if (certificate.hasUnsupportedCriticalExtension()) return false;
                if (!seen.add(digest(certificate.getEncoded()))) return false;
            }
            anchor.checkValidity(Date.from(clock.instant()));
            requireCanonical(anchor);
            if (anchor.hasUnsupportedCriticalExtension()) return false;
            for (int index = 0; index + 1 < chain.size(); index++) {
                if (chain.get(index + 1).getBasicConstraints() < 0) return false;
                boolean[] usage = chain.get(index + 1).getKeyUsage();
                if (usage != null && (usage.length <= 5 || !usage[5])) return false;
                verifyIssuedBy(chain.get(index), chain.get(index + 1));
            }
            X509Certificate last = chain.getLast();
            if (Arrays.equals(last.getEncoded(), anchor.getEncoded())) return true;
            if (anchor.getBasicConstraints() < 0) return false;
            boolean[] anchorUsage = anchor.getKeyUsage();
            if (anchorUsage != null && (anchorUsage.length <= 5 || !anchorUsage[5])) return false;
            verifyIssuedBy(last, anchor);
            return true;
        } catch (CertificateException | RuntimeException failure) {
            return false;
        }
    }

    private static void verifyIssuedBy(X509Certificate certificate, X509Certificate issuer)
            throws CertificateException {
        if (!Arrays.equals(certificate.getIssuerX500Principal().getEncoded(),
                issuer.getSubjectX500Principal().getEncoded())) throw new CertificateException("Issuer mismatch");
        try { certificate.verify(issuer.getPublicKey()); }
        catch (java.security.GeneralSecurityException failure) { throw new CertificateException("Signature mismatch"); }
    }

    private void verifySignature(OcspResponderService.RequesterTrustPolicy policy, X509Certificate signer,
            SignedRequest request) throws IOException {
        AlgorithmIdentifier algorithm = AlgorithmIdentifier.getInstance(ASN1Primitive.fromByteArray(
                request.signatureAlgorithm()));
        X509AlgorithmBinding selected = null;
        for (OcspResponderService.RequestSignatureBinding reference : policy.signatureBindings()) {
            X509AlgorithmBinding binding = realm.session().algorithmBindings().require(reference.bindingId(),
                    reference.commitment());
            if (binding.role() == X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE
                    && binding.oid().equals(algorithm.getAlgorithm().getId()) && parametersMatch(binding, algorithm)) {
                if (selected != null) throw new UnauthorizedException("BINDING_AMBIGUOUS");
                selected = binding;
            }
        }
        if (selected == null || !supported(selected)) throw new UnauthorizedException("BINDING_REJECTED");
        try {
            ContentVerifier verifier = verifier(selected, signer).get(algorithm);
            verifier.getOutputStream().write(request.tbsRequest());
            verifier.getOutputStream().close();
            if (!verifier.verify(request.signature())) throw new UnauthorizedException("SIGNATURE_INVALID");
        } catch (org.bouncycastle.operator.OperatorCreationException | CertificateException failure) {
            throw new UnauthorizedException("SIGNATURE_PROVIDER");
        }
    }

    private static ContentVerifierProvider verifier(X509AlgorithmBinding binding, X509Certificate signer)
            throws CertificateException, IOException, org.bouncycastle.operator.OperatorCreationException {
        X509CertificateHolder holder = new X509CertificateHolder(signer.getEncoded());
        if (binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256)) {
            return new BcECContentVerifierProviderBuilder(DefaultDigestAlgorithmIdentifierFinder.INSTANCE)
                    .build(holder);
        }
        if (binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)) {
            return new BcEdDSAContentVerifierProviderBuilder().build(holder);
        }
        return new BcRSAContentVerifierProviderBuilder(DefaultDigestAlgorithmIdentifierFinder.INSTANCE)
                .build(holder);
    }

    private static boolean supported(X509AlgorithmBinding binding) {
        return binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PSS_SHA256);
    }

    private static boolean parametersMatch(X509AlgorithmBinding binding, AlgorithmIdentifier algorithm) {
        return switch (binding.parameterRule()) {
            case ABSENT -> algorithm.getParameters() == null;
            case DER_NULL -> DERNull.INSTANCE.equals(algorithm.getParameters());
            case STRUCTURED_DER -> strictPss(binding, algorithm);
        };
    }

    private static boolean strictPss(X509AlgorithmBinding binding, AlgorithmIdentifier algorithm) {
        if (!binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PSS_SHA256)
                || !PKCSObjectIdentifiers.id_RSASSA_PSS.equals(algorithm.getAlgorithm())
                || algorithm.getParameters() == null) return false;
        try {
            RSASSAPSSparams parameters = RSASSAPSSparams.getInstance(algorithm.getParameters());
            AlgorithmIdentifier hash = parameters.getHashAlgorithm();
            AlgorithmIdentifier mask = parameters.getMaskGenAlgorithm();
            AlgorithmIdentifier maskHash = AlgorithmIdentifier.getInstance(mask.getParameters());
            return NISTObjectIdentifiers.id_sha256.equals(hash.getAlgorithm())
                    && DERNull.INSTANCE.equals(hash.getParameters())
                    && PKCSObjectIdentifiers.id_mgf1.equals(mask.getAlgorithm())
                    && NISTObjectIdentifiers.id_sha256.equals(maskHash.getAlgorithm())
                    && DERNull.INSTANCE.equals(maskHash.getParameters())
                    && BigInteger.valueOf(32).equals(parameters.getSaltLength())
                    && BigInteger.ONE.equals(parameters.getTrailerField());
        } catch (RuntimeException failure) { return false; }
    }

    private String mapPrincipal(OcspResponderService.RequesterTrustPolicy policy, X509Certificate signer)
            throws CertificateException {
        String certificate = digest(signer.getEncoded());
        String spki = digest(signer.getPublicKey().getEncoded());
        MessageDigest issuerSerial = sha256();
        issuerSerial.update(signer.getIssuerX500Principal().getEncoded());
        issuerSerial.update((byte) 0);
        issuerSerial.update(positiveSerial(signer).toByteArray());
        String exactIssuerSerial = HexFormat.of().formatHex(issuerSerial.digest());
        List<OcspResponderService.PrincipalMapping> matches = policy.principalMappings().stream()
                .filter(mapping -> switch (mapping.type()) {
                    case SHA256_CERTIFICATE_COMMITMENT -> mapping.commitment().equals(certificate);
                    case SHA256_SPKI_COMMITMENT -> mapping.commitment().equals(spki);
                    case ISSUER_AND_SERIAL_COMMITMENT -> mapping.commitment().equals(exactIssuerSerial);
                }).toList();
        if (matches.size() != 1) throw new UnauthorizedException("PRINCIPAL_MAPPING");
        return matches.getFirst().principalId();
    }

    private void validateRevocation(OcspResponderService.RequesterTrustPolicy policy, X509Certificate signer)
            throws CertificateException {
        Optional<Credential> managed = managedCredential(policy, signer);
        if (policy.revocationPolicy() == OcspResponderService.RequesterRevocationPolicy.LOCAL_AUTHORITATIVE_REQUIRED
                && managed.isEmpty()) throw new UnauthorizedException("LOCAL_SIGNER_REQUIRED");
        if (policy.revocationPolicy() != OcspResponderService.RequesterRevocationPolicy.VALIDITY_AND_TRUST_ONLY
                && managed.isPresent()) {
            RevocationState state = realm.session().revocations().get(managed.orElseThrow().credentialId())
                    .map(record -> record.transition().state()).orElse(RevocationState.CLEAR);
            if (state != RevocationState.CLEAR) throw new UnauthorizedException("SIGNER_REVOKED");
        }
    }

    private Optional<Credential> managedCredential(OcspResponderService.RequesterTrustPolicy policy,
            X509Certificate signer) throws CertificateException {
        BigInteger serial = positiveSerial(signer);
        String commitment = digest(signer.getEncoded());
        List<Credential> matches = new ArrayList<>();
        for (OcspResponderService.TrustSelector selector : policy.trustSelectors()) {
            if (selector.type() != OcspResponderService.TrustSelectorType.MANAGED_ISSUER_GENERATIONS) continue;
            for (String identity : selector.identities()) {
                realm.session().repository().credential(new PkiId(identity), serial)
                        .filter(credential -> credentialCommitment(credential).equals(commitment)).ifPresent(matches::add);
            }
        }
        if (matches.size() > 1) throw new UnauthorizedException("MANAGED_SIGNER_AMBIGUOUS");
        return matches.stream().findFirst();
    }

    private void requireIssuer(OcspResponderService.Responder responder, OcspResponseService.CertId certId) {
        X509Certificate issuer = issuerCertificate(responder.issuerId());
        try {
            byte[] name = MessageDigest.getInstance(certId.hash() == OcspResponseService.CertIdHash.SHA1
                    ? "SHA-1" : "SHA-256").digest(issuer.getSubjectX500Principal().getEncoded());
            X509CertificateHolder holder = new X509CertificateHolder(issuer.getEncoded());
            byte[] key = MessageDigest.getInstance(certId.hash() == OcspResponseService.CertIdHash.SHA1
                    ? "SHA-1" : "SHA-256").digest(holder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());
            if (!MessageDigest.isEqual(name, certId.issuerNameHash())
                    || !MessageDigest.isEqual(key, certId.issuerKeyHash())) {
                throw new UnauthorizedException("ISSUER_SCOPE");
            }
        } catch (CertificateException | IOException | NoSuchAlgorithmException failure) {
            throw new UnavailableException();
        }
    }

    private X509Certificate issuerCertificate(PkiId issuerId) {
        PkiId credentialId = realm.session().repository().issuer(issuerId).orElseThrow().credentialId();
        return credentialCertificate(credentialId);
    }

    private X509Certificate credentialCertificate(PkiId credentialId) {
        try (PkiRepositoryContent content = realm.session().repository().openCredential(credentialId);
                InputStream input = content.openStream()) {
            byte[] encoded = input.readNBytes(MAXIMUM_CERTIFICATE_BYTES + 1);
            if (encoded.length > MAXIMUM_CERTIFICATE_BYTES || input.read() != -1) throw new IllegalStateException();
            return parseCertificate(encoded);
        } catch (IOException | CertificateException failure) { throw new IllegalStateException(); }
    }

    private String credentialCommitment(Credential credential) {
        try {
            return digest(credentialCertificate(credential.credentialId()).getEncoded());
        } catch (CertificateException failure) {
            throw new IllegalStateException("Managed requester certificate is unavailable");
        }
    }

    private static List<X509Certificate> certificates(List<byte[]> encoded) throws CertificateException {
        if (encoded.isEmpty()) throw new CertificateException("Signer certificate is required");
        List<X509Certificate> result = new ArrayList<>(encoded.size());
        for (byte[] certificate : encoded) result.add(parseCertificate(certificate));
        return List.copyOf(result);
    }

    private static X509Certificate parseCertificate(byte[] encoded) throws CertificateException {
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(input);
        if (input.available() != 0 || !Arrays.equals(encoded, certificate.getEncoded())) {
            throw new CertificateException("Certificate is not canonical");
        }
        return certificate;
    }

    private static void requireCanonical(X509Certificate certificate) throws CertificateException {
        parseCertificate(certificate.getEncoded());
    }

    private static BigInteger positiveSerial(X509Certificate certificate) {
        if (certificate.getSerialNumber().signum() <= 0) throw new UnauthorizedException("SERIAL_INVALID");
        return certificate.getSerialNumber();
    }

    private static String digest(byte[] value) { return HexFormat.of().formatHex(sha256().digest(value)); }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable"); }
    }
    private static byte[] requireBytes(byte[] value, String field, int maximum) {
        Objects.requireNonNull(value, field);
        if (value.length == 0 || value.length > maximum) throw new IllegalArgumentException(field + " is invalid");
        return value.clone();
    }
}
