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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline;
import zeroecho.pki.application.SdkOcspProjection;
import zeroecho.pkix.Pkix;

/** Stateless, bounded SDK OCSP assurance verifier; bundle material never establishes trust. */
public final class SdkOcspEvidenceVerifier {
    private SdkOcspEvidenceVerifier() { }

    /**
     * Verifies native delegation/signature, both certificate/evidence roles and every duplicated field.
     * No status lookup, network access, provider key access or trust discovery occurs.
     * Runtime is linear in the bounded request/status/chain sizes.
     * @param evidence untrusted complete bundle
     * @param trusted independent policy-authorized coordinates, certificates, nonce and evaluation time
     * @return exact verified native projection; GOOD is not a certificate-path validity assertion
     * @throws IllegalArgumentException for invalid trust inputs, evidence, time, role or signature
     */
    public static SdkOcspProjection.Projection verify(SdkOcspEvidence evidence, TrustedContext trusted) {
        Objects.requireNonNull(evidence, "evidence"); Objects.requireNonNull(trusted, "trusted");
        try {
            HybridSdkFrame frame = evidence.primaryFrame();
            equal(frame.field(2), text(trusted.realmId())); equal(frame.field(3), text(trusted.canonicalOrigin()));
            equal(frame.field(4), trusted.clientNonce()); equal(frame.field(5), HybridSdkFrame.hash(trusted.originalRequestDer()));
            equal(frame.field(6), HybridSdkFrame.hash(evidence.primaryResponseDer()));
            equal(frame.field(9), text(trusted.authorityId().value())); equal(frame.field(10), text(trusted.issuerId().value()));
            equal(frame.field(11), text(trusted.chainPathId().value())); equal(frame.field(12), text(trusted.chainPathCommitment()));
            equal(frame.field(13), text(trusted.issuerBindingCommitment())); equal(frame.field(14), trusted.responderRoles().encode());
            var chain = evidence.responderChain(); var expected = new java.util.ArrayList<byte[]>();
            expected.add(trusted.responderCertificateDer()); expected.addAll(trusted.issuerPath());
            if (chain.size() != expected.size()) throw invalid();
            for (int index = 0; index < chain.size(); index++) equal(chain.get(index), expected.get(index));
            equal(frame.field(7), HybridSdkFrame.hash(chain.getFirst()));
            equal(frame.field(8), HybridSdkFrame.hash(HybridSdkValue.list(chain.stream().map(HybridSdkValue::bytes).toList()).encode()));
            var certificates = validatedResponder(trusted);
            var responder = certificates.getFirst(); var issuer = certificates.get(1);
            var roles = trusted.responderRoles().objectFields(); var primaryRole = roles.get("primary").objectFields(); var alternativeRole = roles.get("alternative").objectFields();
            byte[] primarySpki = valueBytes(primaryRole.get("spki")), alternativeSpki = valueBytes(alternativeRole.get("spki"));
            equal(primarySpki, responder.getPublicKey().getEncoded()); equal(alternativeSpki, alternativeKey(responder).getEncoded());
            PublicKey primary = suiteKey(primarySpki, false), alternative = suiteKey(alternativeSpki, true);
            var projection = SdkOcspProjection.parse(trusted.originalRequestDer(), evidence.primaryResponseDer());
            equal(projection.algorithmIdentifier(), HybridSdkFrame.primaryAlgorithm());
            equal(frame.field(15), time(projection.producedAt())); equal(frame.field(16), time(projection.thisUpdate())); equal(frame.field(17), time(projection.nextUpdate()));
            equal(frame.field(20), projection.nonce().encode()); equal(frame.field(21), projection.statuses().encode());
            var nativeResponse = Pkix.parseOcspResponse(evidence.primaryResponseDer());
            var embedded = nativeResponse.certificates(); if (embedded.size() != chain.size()) throw invalid();
            for (int index = 0; index < embedded.size(); index++) equal(embedded.get(index).getEncoded(), chain.get(index));
            if (!nativeResponse.verifySignature(primary)) throw invalid();
            if (nativeResponse.responderId() instanceof zeroecho.pkix.ocsp.ResponderId.ByName name) {
                if (!name.name().equals(responder.getSubjectX500Principal())) throw invalid();
            } else if (nativeResponse.responderId() instanceof zeroecho.pkix.ocsp.ResponderId.ByKey key) {
                equal(key.keyHash(), Pkix.subjectKeyIdentifier(primary));
            } else throw invalid();
            for (var id : Pkix.parseOcspRequest(trusted.originalRequestDer()).requestedCertificates()) {
                var expectedId = Pkix.computeCertId(issuer, id.serialNumber(), id.hashAlgorithm().oid());
                if (!id.hashAlgorithm().oid().equals(expectedId.hashAlgorithm().oid())
                        || !Arrays.equals(id.issuerNameHash(), expectedId.issuerNameHash())
                        || !Arrays.equals(id.issuerKeyHash(), expectedId.issuerKeyHash()) || !id.serialNumber().equals(expectedId.serialNumber())) throw invalid();
            }
            Instant now = trusted.evaluationTime(), issued = instant(frame.field(18)), expires = instant(frame.field(19));
            if (projection.producedAt().isBefore(now.minusSeconds(300)) || projection.producedAt().isAfter(now.plusSeconds(60))
                    || projection.thisUpdate().isAfter(now.plusSeconds(60)) || issued.isAfter(now.plusSeconds(60))
                    || !now.isBefore(expires) || expires.isAfter(responder.getNotAfter().toInstant()) || !now.isBefore(projection.nextUpdate())) throw invalid();
            HybridSdkFrame.requirePrimaryProofSyntax(evidence.primarySignature());
            if (!verifySignature("SHA384withECDSA", primary, frame.encode(), evidence.primarySignature(), false)
                    || !verifySignature("ML-DSA-87", alternative, evidence.alternativeFrame().encode(), evidence.alternativeSignature(), true)) throw invalid();
            return projection;
        } catch (GeneralSecurityException | java.io.IOException malformed) { throw invalid(); }
    }
    /**
     * Checks independently authorized delegation, path, both certificate signatures and fixed responder roles.
     * This pure pre-sign check discovers no trust, performs no signing and grants no additional authority.
     * @param trusted bounded independent policy/store evidence and trusted evaluation time
     * @throws IllegalArgumentException if delegation, certificate validity, path or role evidence fails
     */
    public static void validateResponder(TrustedContext trusted) {
        Objects.requireNonNull(trusted, "trusted");
        try { validatedResponder(trusted); }
        catch (GeneralSecurityException | java.io.IOException invalid) { throw invalid(); }
    }
    /**
     * Validates policy-authorized responder material independently of any HTTP listener coordinates.
     * Registration uses this origin-free pure check; no identity, trust or signing authority is created.
     * Inputs are public, borrowed and bounded identically to TrustedContext's certificate material.
     * @param issuerPath independently trusted ordered issuer-to-anchor DER path
     * @param baselines explicit persisted baseline per issuer-path certificate
     * @param responderDer independently authorized directly delegated responder DER
     * @param roles independently authorized closed responder-role object
     * @param now trusted evaluation time
     * @throws IllegalArgumentException for invalid bounds, delegation, validity, path or role evidence
     */
    public static void validateResponder(List<byte[]> issuerPath, List<HybridSignatureBaseline> baselines,
            byte[] responderDer, HybridSdkValue roles, Instant now) {
        try { validatedResponder(issuerPath, baselines, responderDer, roles, now); }
        catch (GeneralSecurityException | java.io.IOException invalid) { throw invalid(); }
    }
    private static List<X509Certificate> validatedResponder(TrustedContext trusted) throws GeneralSecurityException, java.io.IOException {
        return validatedResponder(trusted.issuerPath(), trusted.issuerCertificateBaselines(), trusted.responderCertificateDer(), trusted.responderRoles(), trusted.evaluationTime());
    }
    private static List<X509Certificate> validatedResponder(List<byte[]> issuerPath, List<HybridSignatureBaseline> baselines,
            byte[] responderDer, HybridSdkValue responderRoles, Instant now) throws GeneralSecurityException, java.io.IOException {
        Objects.requireNonNull(issuerPath, "issuerPath"); Objects.requireNonNull(baselines, "baselines"); Objects.requireNonNull(now, "now");
        if (issuerPath.isEmpty() || issuerPath.size() > 31 || baselines.size() != issuerPath.size()) throw invalid();
        baselines = List.copyOf(baselines);
        var chain = new java.util.ArrayList<byte[]>(); chain.add(SdkOcspEvidence.bounded(responderDer, 262144));
        for (var der : issuerPath) chain.add(SdkOcspEvidence.bounded(der, 262144));
        SdkOcspEvidence.copyChain(chain);
        var authorizedRoles = Objects.requireNonNull(responderRoles, "responderRoles").objectFields();
        if (!authorizedRoles.keySet().equals(java.util.Set.of("primary", "alternative"))) throw invalid();
        HybridSdkFrame.requireOcspRole(authorizedRoles.get("primary"), HybridSdkFrame.primaryAlgorithm());
        HybridSdkFrame.requireOcspRole(authorizedRoles.get("alternative"), HybridSdkFrame.alternativeAlgorithm());
    var certificates = new java.util.ArrayList<X509Certificate>();
    for (byte[] der : chain) {
        var certificate = Pkix.parseCertificate(der); equal(der, certificate.getEncoded()); certificates.add(certificate);
        certificate.checkValidity(java.util.Date.from(now));
        if (certificate.hasUnsupportedCriticalExtension()) throw invalid();
    }
    var responder = certificates.getFirst(); var issuer = certificates.get(1);
    boolean[] usage = responder.getKeyUsage();
    if (responder.getBasicConstraints() >= 0 || usage == null || usage.length == 0 || !usage[0]
            || responder.getExtendedKeyUsage() == null || !responder.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.9")) throw invalid();
    verifyCertificate(responder, issuer, HybridSignatureBaseline.COR3_SIGNED_WRAPPER);
    for (int index = 1; index < certificates.size(); index++) {
        var certificate = certificates.get(index); boolean[] caUsage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || caUsage != null && (caUsage.length <= 5 || !caUsage[5])) throw invalid();
        if (certificate.getBasicConstraints() < index - 1) throw invalid();
        if (index < certificates.size() - 1) verifyCertificate(certificate, certificates.get(index + 1), baselines.get(index - 1));
    }
        var roles = responderRoles.objectFields();
        byte[] primary = valueBytes(roles.get("primary").objectFields().get("spki"));
        byte[] alternative = valueBytes(roles.get("alternative").objectFields().get("spki"));
        equal(primary, responder.getPublicKey().getEncoded()); equal(alternative, alternativeKey(responder).getEncoded());
        suiteKey(primary, false); suiteKey(alternative, true);
        return certificates;
    }
    private static void verifyCertificate(X509Certificate certificate, X509Certificate issuer, HybridSignatureBaseline baseline) throws GeneralSecurityException, java.io.IOException {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) || baseline == HybridSignatureBaseline.NONE) throw invalid();
        certificate.verify(issuer.getPublicKey()); var alternative = alternativeKey(issuer);
        boolean valid = switch (baseline) {
            case COR3_SIGNED_WRAPPER -> Pkix.verifyAlternativeSignatureCor3(certificate, alternative);
            case LEGACY_PRE_TBS -> Pkix.verifyAlternativeSignature(certificate, alternative);
            case NONE -> false;
        };
        if (!valid) throw invalid();
    }
    private static PublicKey alternativeKey(X509Certificate certificate) throws java.io.IOException, GeneralSecurityException {
        byte[] extension = certificate.getExtensionValue("2.5.29.72"); if (extension == null) throw invalid();
        return key(ASN1OctetString.getInstance(extension).getOctets());
    }
    private static PublicKey key(byte[] der) throws java.io.IOException, GeneralSecurityException {
        var info = SubjectPublicKeyInfo.getInstance(der); equal(der, info.getEncoded("DER"));
        zeroecho.sdk.util.BouncyCastleActivator.init(); return new JcaPEMKeyConverter().setProvider("BC").getPublicKey(info);
    }
    private static PublicKey suiteKey(byte[] der, boolean alternative) throws java.io.IOException, GeneralSecurityException {
        var info = SubjectPublicKeyInfo.getInstance(der); PublicKey key = key(der);
        if (info.getPublicKeyData().getPadBits() != 0) throw invalid();
        if (alternative) {
            if (!info.getAlgorithm().getAlgorithm().getId().equals("2.16.840.1.101.3.4.3.19") || info.getAlgorithm().getParameters() != null
                    || info.getPublicKeyData().getBytes().length != 2592) throw invalid();
        } else if (!info.getAlgorithm().getAlgorithm().getId().equals("1.2.840.10045.2.1")
                || !org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(info.getAlgorithm().getParameters()).getId().equals("1.3.132.0.34")
                || info.getPublicKeyData().getBytes().length != 97 || info.getPublicKeyData().getBytes()[0] != 4) throw invalid();
        return key;
    }
    private static boolean verifySignature(String algorithm, PublicKey key, byte[] message, byte[] signature, boolean alternative) throws GeneralSecurityException {
        Signature verifier = alternative ? Signature.getInstance(algorithm, "BC") : Signature.getInstance(algorithm);
        if (alternative) verifier.setParameter(new org.bouncycastle.jcajce.spec.ContextParameterSpec(new byte[0]));
        verifier.initVerify(key); verifier.update(message); return verifier.verify(signature);
    }
    private static byte[] valueBytes(HybridSdkValue value) { byte[] encoded = value.encode(); if (encoded[0] != 4) throw invalid(); return Arrays.copyOfRange(encoded, 5, encoded.length); }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] time(Instant value) { return ByteBuffer.allocate(8).putLong(value.getEpochSecond()).array(); }
    private static Instant instant(byte[] value) { return Instant.ofEpochSecond(ByteBuffer.wrap(value).getLong()); }
    private static void equal(byte[] left, byte[] right) { if (!java.security.MessageDigest.isEqual(left, right)) throw invalid(); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK OCSP evidence invalid"); }

    /**
     * Independent relying-party trust and request inputs; never populate these from the bundle.
     * Path order is selected issuer first, explicit trusted anchor last. Baselines are independently
     * authorized per path certificate; the new responder always uses COR3. Public role identities
     * come from trusted policy/catalog selection, not bundle claims. Arrays are defensively owned.
     * @param realmId expected realm
     * @param canonicalOrigin configured expected HTTPS origin with explicit port
     * @param authorityId expected logical CA
     * @param issuerId expected immutable issuer generation
     * @param chainPathId expected immutable path
     * @param chainPathCommitment expected full path commitment
     * @param issuerBindingCommitment expected raw lowercase SHA256 binding commitment
     * @param originalRequestDer exact locally sent native request
     * @param clientNonce locally generated 32-byte SDK nonce
     * @param issuerPath independently trusted ordered DER path, at most 31 certificates
     * @param issuerCertificateBaselines explicit baseline per path certificate
     * @param responderCertificateDer independently policy-authorized delegated responder certificate
     * @param responderRoles independently catalog-authorized closed F4 tag-14 role object
     * @param evaluationTime trusted local evaluation time
     */
    public record TrustedContext(String realmId, String canonicalOrigin, PkiId authorityId, PkiId issuerId, PkiId chainPathId,
            String chainPathCommitment, String issuerBindingCommitment, byte[] originalRequestDer, byte[] clientNonce,
            List<byte[]> issuerPath, List<HybridSignatureBaseline> issuerCertificateBaselines, byte[] responderCertificateDer,
            HybridSdkValue responderRoles, Instant evaluationTime) {
        /** Validates bounded independent trust inputs without discovering new trust. */
        public TrustedContext {
            HybridSdkValue.requireIdentifier(realmId); HybridSdkFrame.requireOrigin(canonicalOrigin);
            Objects.requireNonNull(authorityId, "authorityId"); Objects.requireNonNull(issuerId, "issuerId"); Objects.requireNonNull(chainPathId, "chainPathId");
            HybridSdkValue.requireIdentifier(authorityId.value()); HybridSdkValue.requireIdentifier(issuerId.value()); HybridSdkValue.requireIdentifier(chainPathId.value());
            if (chainPathCommitment == null || !chainPathCommitment.matches("(?:sha256:)?[0-9a-f]{64}")
                    || issuerBindingCommitment == null || !issuerBindingCommitment.matches("[0-9a-f]{64}")) throw invalid();
            originalRequestDer = SdkOcspEvidence.bounded(originalRequestDer, 1048576);
            clientNonce = SdkOcspEvidence.bounded(clientNonce, 32); if (clientNonce.length != 32) throw invalid();
            Objects.requireNonNull(issuerPath, "issuerPath"); if (issuerPath.isEmpty() || issuerPath.size() > 31) throw invalid();
            issuerPath = issuerPath.stream().map(bytes -> SdkOcspEvidence.bounded(bytes, 262144)).toList();
            issuerCertificateBaselines = List.copyOf(issuerCertificateBaselines);
            if (issuerCertificateBaselines.size() != issuerPath.size()) throw invalid();
            responderCertificateDer = SdkOcspEvidence.bounded(responderCertificateDer, 262144);
            var roles = Objects.requireNonNull(responderRoles, "responderRoles").objectFields();
            if (!roles.keySet().equals(java.util.Set.of("primary", "alternative"))) throw invalid();
            HybridSdkFrame.requireOcspRole(roles.get("primary"), HybridSdkFrame.primaryAlgorithm());
            HybridSdkFrame.requireOcspRole(roles.get("alternative"), HybridSdkFrame.alternativeAlgorithm());
            Objects.requireNonNull(evaluationTime, "evaluationTime");
        }
        /** @return independent original request bytes */
        @Override public byte[] originalRequestDer() { return originalRequestDer.clone(); }
        /** @return independent locally supplied nonce bytes */
        @Override public byte[] clientNonce() { return clientNonce.clone(); }
        /** @return independent trusted issuer path and DER bytes */
        @Override public List<byte[]> issuerPath() { return issuerPath.stream().map(byte[]::clone).toList(); }
        /** @return independent policy-authorized responder DER bytes */
        @Override public byte[] responderCertificateDer() { return responderCertificateDer.clone(); }
    }
}
