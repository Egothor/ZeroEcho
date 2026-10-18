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
package zeroecho.pki.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.sign.ContentVerifier;

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
    private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final String OID_MGF1 = "1.2.840.113549.1.1.8";
    private static final String OID_RSA_PSS = "1.2.840.113549.1.1.10";
    private static final byte[] DER_NULL = { 0x05, 0x00 };
    /** Canonical DER of the approved RSASSA-PSS parameters (SHA-256, MGF1-SHA-256, salt 32). */
    private static final byte[] PSS_SHA256_PARAMETERS = pssSha256Parameters();

    /**
     * Exact bounded cryptographic fields retained from one canonical request.
     *
     * @param tbsRequest canonical to-be-signed request DER
     * @param requestorName canonical requestor-name DER
     * @param signatureAlgorithm canonical signature algorithm identifier DER
     * @param signature request signature bytes
     * @param certificates bounded requester certificate chain
     */
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
        /** Returns a defensive copy of canonical to-be-signed request DER.
         * @return copied DER bytes */
        @Override public byte[] tbsRequest() { return tbsRequest.clone(); }
        /** Returns a defensive copy of canonical requestor-name DER.
         * @return copied DER bytes */
        @Override public byte[] requestorName() { return requestorName.clone(); }
        /** Returns a defensive copy of the signature algorithm identifier DER.
         * @return copied DER bytes */
        @Override public byte[] signatureAlgorithm() { return signatureAlgorithm.clone(); }
        /** Returns a defensive copy of the request signature.
         * @return copied signature bytes */
        @Override public byte[] signature() { return signature.clone(); }
        /** Returns immutable defensive copies of the requester certificates.
         * @return immutable list of copied certificate encodings */
        @Override public List<byte[]> certificates() {
            return certificates.stream().map(byte[]::clone).toList();
        }
    }

    /**
     * Safe successful authentication result.
     *
     * @param principalId authenticated enabled principal identifier
     */
    public record Authorized(String principalId) {
        /** Validates the mapped principal identity. */
        public Authorized { Permission.requirePrincipal(principalId); }
    }

    /** Safe authentication or authorization rejection. */
    public static final class UnauthorizedException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        /** Safe non-secret rejection classification. */
        private final String classification;
        /** Creates a redacted rejection. */
        public UnauthorizedException() { this("UNSPECIFIED"); }
        private UnauthorizedException(String classification) {
            super("OCSP requester is unauthorized");
            this.classification = classification;
        }
        /**
         * Returns the rejection classification.
         *
         * @return safe non-secret internal rejection classification
         */
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

    /**
     * Creates one realm-bound requester authentication service.
     *
     * @param realm owning realm context
     * @param clock authoritative server clock
     */
    public OcspRequesterService(ServerRealmContext realm, Clock clock) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Authenticates and authorizes every CertID in one signed request. Any failure
     * rejects the whole request without revealing the failed entry.
     *
     * @param responder exact responder configuration
     * @param request canonical signed request fields
     * @param requests certificate identifiers authorized as one unit
     * @return authenticated enabled requester principal
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
            SignedRequest request) {
        AlgorithmIdentifier algorithm = Pkix.parseAlgorithmIdentifier(request.signatureAlgorithm());
        X509AlgorithmBinding selected = null;
        for (OcspResponderService.RequestSignatureBinding reference : policy.signatureBindings()) {
            X509AlgorithmBinding binding = realm.session().algorithmBindings().require(reference.bindingId(),
                    reference.commitment());
            if (binding.role() == X509AlgorithmBinding.Role.OCSP_REQUEST_SIGNATURE
                    && binding.oid().equals(algorithm.oid()) && parametersMatch(binding, algorithm)) {
                if (selected != null) throw new UnauthorizedException("BINDING_AMBIGUOUS");
                selected = binding;
            }
        }
        if (selected == null || !supported(selected)) throw new UnauthorizedException("BINDING_REJECTED");
        ContentVerifier verifier;
        try {
            verifier = Pkix.verifier(signer.getPublicKey(), algorithm);
            try (OutputStream stream = verifier.contentStream()) {
                stream.write(request.tbsRequest());
            }
        } catch (IOException | RuntimeException failure) {
            throw new UnauthorizedException("SIGNATURE_PROVIDER");
        }
        if (!verifier.verify(request.signature())) throw new UnauthorizedException("SIGNATURE_INVALID");
    }

    private static boolean supported(X509AlgorithmBinding binding) {
        return binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256)
                || binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PSS_SHA256);
    }

    private static boolean parametersMatch(X509AlgorithmBinding binding, AlgorithmIdentifier algorithm) {
        return switch (binding.parameterRule()) {
            case ABSENT -> algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.ABSENT;
            case DER_NULL -> algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.DER_NULL;
            case STRUCTURED_DER -> strictPss(binding, algorithm);
        };
    }

    private static boolean strictPss(X509AlgorithmBinding binding, AlgorithmIdentifier algorithm) {
        return binding.algorithmIdentity().equals(BootstrapAlgorithmIdentities.RSA_PSS_SHA256)
                && OID_RSA_PSS.equals(algorithm.oid())
                && algorithm.parameterForm() == AlgorithmIdentifier.ParameterForm.EXACT_DER
                && Arrays.equals(algorithm.parameters(), PSS_SHA256_PARAMETERS);
    }

    private static byte[] pssSha256Parameters() {
        byte[] sha256 = derSequence(derOid(OID_SHA256), DER_NULL);
        byte[] mgf1 = derSequence(derOid(OID_MGF1), sha256);
        return derSequence(derExplicit(0, sha256), derExplicit(1, mgf1), derExplicit(2, derInteger(32)));
    }

    private static byte[] derOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(Integer.parseInt(parts[0]) * 40 + Integer.parseInt(parts[1]));
        for (int index = 2; index < parts.length; index++) {
            writeBase128(body, Long.parseLong(parts[index]));
        }
        return derTag(0x06, body.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        byte[] buffer = new byte[10];
        int index = buffer.length;
        buffer[--index] = (byte) (value & 0x7f);
        long remaining = value >>> 7;
        while (remaining > 0) {
            buffer[--index] = (byte) ((remaining & 0x7f) | 0x80);
            remaining >>>= 7;
        }
        out.write(buffer, index, buffer.length - index);
    }

    private static byte[] derInteger(int value) {
        return derTag(0x02, new byte[] { (byte) value });
    }

    private static byte[] derExplicit(int tagNumber, byte[] content) {
        return derTag(0xA0 | tagNumber, content);
    }

    private static byte[] derSequence(byte[]... elements) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        for (byte[] element : elements) {
            content.writeBytes(element);
        }
        return derTag(0x30, content.toByteArray());
    }

    private static byte[] derTag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (content.length < 128) {
            out.write(content.length);
        } else {
            byte[] buffer = new byte[4];
            int index = buffer.length;
            int length = content.length;
            while (length > 0) {
                buffer[--index] = (byte) (length & 0xff);
                length >>>= 8;
            }
            out.write(0x80 | (buffer.length - index));
            out.write(buffer, index, buffer.length - index);
        }
        out.writeBytes(content);
        return out.toByteArray();
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
            byte[] publicKeyBits = Pkix.subjectPublicKeyBytes(Pkix.subjectPublicKeyInfo(issuer));
            byte[] key = MessageDigest.getInstance(certId.hash() == OcspResponseService.CertIdHash.SHA1
                    ? "SHA-1" : "SHA-256").digest(publicKeyBits);
            if (!MessageDigest.isEqual(name, certId.issuerNameHash())
                    || !MessageDigest.isEqual(key, certId.issuerKeyHash())) {
                throw new UnauthorizedException("ISSUER_SCOPE");
            }
        } catch (NoSuchAlgorithmException failure) {
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
