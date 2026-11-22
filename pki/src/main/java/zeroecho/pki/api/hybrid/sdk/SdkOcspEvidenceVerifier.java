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

import java.util.ArrayList;
import java.util.Map;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.OcspResponse;


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
import zeroecho.pkix.PkixEncoding;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.IssuerCryptographicBinding.HybridSignatureBaseline;
import zeroecho.pki.application.SdkOcspProjection;
import zeroecho.pkix.Pkix;

/**
 * Stateless verifier for the separate SDK F4/F5 OCSP evidence profile.
 *
 * <p>This profile is not standard AltSignature OCSP. Bundle material never creates
 * trust: callers supply independently authorized responder roles, issuer path,
 * original request, SDK nonce and evaluation time. The bounded checks here are not
 * a general PKIX trust discovery or revocation service.</p>
 */
public final class SdkOcspEvidenceVerifier {
    private static final int LIMIT_4 = 4;
    private static final int LIMIT_32 = 32;

    private static final String VALUE_ALTERNATIVE = "alternative";

    private static final String VALUE_PRIMARY = "primary";

    private SdkOcspEvidenceVerifier() { }

    /**
     * Verifies native delegation/signature, both certificate/evidence roles and every duplicated field.
     * No status lookup, network access, provider key access or trust discovery occurs.
     * Runtime is linear in the bounded request/status/chain sizes.
     *
     * <p>The verifier matches the exact retained native response and embedded chain,
     * verifies its primary responder signature, recomputes requested issuer CertIDs,
     * and verifies the independent F4 primary and F5 alternative signatures. The
     * native nonce is derived from the original request/response; the 32-byte SDK
     * nonce is separately matched to the caller's trusted challenge.</p>
     *
     * <p>All temporal decisions use {@code trusted.evaluationTime()}, not an implicit
     * current clock. Production time may be at most 300 seconds old or 60 seconds
     * ahead; status/evidence issue times may be at most 60 seconds ahead. Evidence
     * expiry and nextUpdate must exceed that evaluation time, and evidence expiry
     * must not exceed responder validity. A later relying-party decision must use
     * its own actual evaluation time. GOOD does not establish certificate-path
     * validity, application authorization or future freshness.</p>
     *
     * @param evidence untrusted complete bundle
     * @param trusted independent policy-authorized coordinates, certificates, nonce and evaluation time
     * @return exact verified native projection; GOOD is not a certificate-path validity assertion
     * @throws NullPointerException if evidence or trusted context is null
     * @throws IllegalArgumentException for invalid trust inputs, evidence, time, role or signature
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static SdkOcspProjection.Projection verify(SdkOcspEvidence evidence, TrustedContext trusted) {
        Objects.requireNonNull(evidence, "evidence"); Objects.requireNonNull(trusted, "trusted");
        try {
            HybridSdkFrame frame = evidence.primaryFrame();
            List<byte[]> chain = requireFrameCoordinates(evidence, trusted);
            List<X509Certificate> certificates = validatedResponder(trusted);
            X509Certificate responder = certificates.getFirst(); X509Certificate issuer = certificates.get(1);
            Map<String,HybridSdkValue> roles = trusted.responderRoles().objectFields(); Map<String,HybridSdkValue> primaryRole = roles.get(VALUE_PRIMARY).objectFields(); Map<String,HybridSdkValue> alternativeRole = roles.get(VALUE_ALTERNATIVE).objectFields();
            byte[] primarySpki = valueBytes(primaryRole.get("spki"));
            byte[] alternativeSpki = valueBytes(alternativeRole.get("spki"));
            equal(primarySpki, responder.getPublicKey().getEncoded()); equal(alternativeSpki, Certificates.alternativeKey(responder).getEncoded());
            PublicKey primary = Certificates.suiteKey(primarySpki, false);
            PublicKey alternative = Certificates.suiteKey(alternativeSpki, true);
            SdkOcspProjection.Projection projection = SdkOcspProjection.parse(trusted.originalRequestDer(), evidence.primaryResponseDer());
            equal(projection.algorithmIdentifier(), HybridSdkFrame.primaryAlgorithm());
            equal(frame.field(15), time(projection.producedAt())); equal(frame.field(16), time(projection.thisUpdate())); equal(frame.field(17), time(projection.nextUpdate()));
            equal(frame.field(20), projection.nonce().encode()); equal(frame.field(21), projection.statuses().encode());
            requireNativeResponse(evidence, trusted, chain, responder, issuer, primary);
            requireEvidenceTime(frame, projection, trusted.evaluationTime(), responder);
            HybridSdkFrame.requirePrimaryProofSyntax(evidence.primarySignature());
            if (!verifySignature("SHA384withECDSA", primary, frame.encode(), evidence.primarySignature(), false)
                    || !verifySignature("ML-DSA-87", alternative, evidence.alternativeFrame().encode(), evidence.alternativeSignature(), true)) { throw invalid(); }
            return projection;
        } catch (GeneralSecurityException | java.io.IOException malformed) { throw invalid(); }
    }
    /**
     * Checks independently authorized delegation, path, both certificate signatures and fixed responder roles.
     * This pure pre-sign check discovers no trust, performs no signing and grants no additional authority.
     *
     * <p>Checks certificate validity at the supplied evaluation time, critical
     * extensions, CA/key-usage constraints, direct OCSP delegation and fixed primary
     * P-384/alternative ML-DSA-87 responder roles. Chain edges use the explicitly
     * authorized hybrid baselines; the supplied terminal anchor is not authenticated
     * by its self-signature. No certificate revocation lookup or general policy
     * path-building occurs.</p>
     *
     * @param trusted bounded independent policy/store evidence and trusted evaluation time
     * @throws NullPointerException if the trusted context is null
     * @throws IllegalArgumentException if delegation, certificate validity, path or role evidence fails
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static void validateResponder(TrustedContext trusted) {
        Objects.requireNonNull(trusted, "trusted");
        try { validatedResponder(trusted); }
        catch (GeneralSecurityException | java.io.IOException invalid) { throw invalid(); }
    }
    /**
     * Validates policy-authorized responder material independently of any HTTP listener coordinates.
     * Registration uses this origin-free pure check; no identity, trust or signing authority is created.
     * Inputs are public and borrowed during the call; bounded local copies of certificate
     * arrays and the baseline list are used for validation. Caller-owned resources
     * are not closed, and the method does not retain a new context.
     * @param issuerPath independently trusted ordered issuer-to-anchor DER path
     * @param baselines explicit persisted baseline per issuer-path certificate
     * @param responderDer independently authorized directly delegated responder DER
     * @param roles independently authorized closed responder-role object
     * @param now trusted evaluation time
     * @throws NullPointerException if a required value, baseline or certificate element is null
     * @throws IllegalArgumentException for invalid bounds, delegation, validity, path or role evidence
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static void validateResponder(List<byte[]> issuerPath, List<HybridSignatureBaseline> baselines,
            byte[] responderDer, HybridSdkValue roles, Instant now) {
        try { validatedResponder(issuerPath, baselines, responderDer, roles, now); }
        catch (GeneralSecurityException | java.io.IOException invalid) { throw invalid(); }
    }
    private static List<byte[]> requireFrameCoordinates(SdkOcspEvidence evidence, TrustedContext trusted) {
            HybridSdkFrame frame = evidence.primaryFrame();
            equal(frame.field(2), text(trusted.realmId())); equal(frame.field(3), text(trusted.canonicalOrigin()));
            equal(frame.field(LIMIT_4), trusted.clientNonce()); equal(frame.field(5), HybridSdkFrame.hash(trusted.originalRequestDer()));
            equal(frame.field(6), HybridSdkFrame.hash(evidence.primaryResponseDer()));
            equal(frame.field(9), text(trusted.authorityId().value())); equal(frame.field(10), text(trusted.issuerId().value()));
            equal(frame.field(11), text(trusted.chainPathId().value())); equal(frame.field(12), text(trusted.chainPathCommitment()));
            equal(frame.field(13), text(trusted.issuerBindingCommitment())); equal(frame.field(14), trusted.responderRoles().encode());
            List<byte[]> chain = evidence.responderChain(); List<byte[]> expected = new ArrayList<>();
            expected.add(trusted.responderCertificateDer()); expected.addAll(trusted.issuerPath());
            if (chain.size() != expected.size()) { throw invalid(); }
            for (int index = 0; index < chain.size(); index++) { equal(chain.get(index), expected.get(index)); }
            equal(frame.field(7), HybridSdkFrame.hash(chain.getFirst()));
            equal(frame.field(8), HybridSdkFrame.hash(HybridSdkValue.list(chain.stream().map(HybridSdkValue::bytes).toList()).encode()));
        return chain;
    }

    private static void requireNativeResponse(SdkOcspEvidence evidence, TrustedContext trusted,
            List<byte[]> chain, X509Certificate responder, X509Certificate issuer, PublicKey primary)
            throws GeneralSecurityException, java.io.IOException {
            OcspResponse nativeResponse = Pkix.parseOcspResponse(evidence.primaryResponseDer());
            List<X509Certificate> embedded = nativeResponse.certificates(); if (embedded.size() != chain.size()) { throw invalid(); }
            for (int index = 0; index < embedded.size(); index++) { equal(embedded.get(index).getEncoded(), chain.get(index)); }
            if (!nativeResponse.verifySignature(primary)) { throw invalid(); }
            if (nativeResponse.responderId() instanceof zeroecho.pkix.ocsp.ResponderId.ByName name) {
                if (!name.name().equals(responder.getSubjectX500Principal())) { throw invalid(); }
            } else if (nativeResponse.responderId() instanceof zeroecho.pkix.ocsp.ResponderId.ByKey key) {
                equal(key.keyHash(), Pkix.subjectKeyIdentifier(primary));
            } else { throw invalid(); }
            for (CertId id : Pkix.parseOcspRequest(trusted.originalRequestDer()).requestedCertificates()) {
                CertId expectedId = Pkix.computeCertId(issuer, id.serialNumber(), id.hashAlgorithm().oid());
                if (!id.hashAlgorithm().oid().equals(expectedId.hashAlgorithm().oid())
                        || !Arrays.equals(id.issuerNameHash(), expectedId.issuerNameHash())
                        || !Arrays.equals(id.issuerKeyHash(), expectedId.issuerKeyHash()) || !id.serialNumber().equals(expectedId.serialNumber())) { throw invalid(); }
            }
    }

    private static void requireEvidenceTime(HybridSdkFrame frame, SdkOcspProjection.Projection projection,
            Instant now, X509Certificate responder) {
            Instant issued = instant(frame.field(18));
            Instant expires = instant(frame.field(19));
            if (projection.producedAt().isBefore(now.minusSeconds(300)) || projection.producedAt().isAfter(now.plusSeconds(60))
                    || projection.thisUpdate().isAfter(now.plusSeconds(60)) || issued.isAfter(now.plusSeconds(60))
                    || !now.isBefore(expires) || expires.isAfter(responder.getNotAfter().toInstant()) || !now.isBefore(projection.nextUpdate())) { throw invalid(); }
    }

    private static List<X509Certificate> validatedResponder(TrustedContext trusted) throws GeneralSecurityException, java.io.IOException {
        return validatedResponder(trusted.issuerPath(), trusted.issuerCertificateBaselines(), trusted.responderCertificateDer(), trusted.responderRoles(), trusted.evaluationTime());
    }
    private static List<X509Certificate> validatedResponder(List<byte[]> issuerPath, List<HybridSignatureBaseline> baselines,
            byte[] responderDer, HybridSdkValue responderRoles, Instant now) throws GeneralSecurityException, java.io.IOException {
        Objects.requireNonNull(issuerPath, "issuerPath"); Objects.requireNonNull(baselines, "baselines"); Objects.requireNonNull(now, "now");
        if (issuerPath.isEmpty() || issuerPath.size() > 31 || baselines.size() != issuerPath.size()) { throw invalid(); }
        List<HybridSignatureBaseline> baselineSnapshot = List.copyOf(baselines);
        List<byte[]> chain = new ArrayList<>(); chain.add(SdkOcspEvidence.bounded(responderDer, 262_144));
        for (byte[] der : issuerPath) { chain.add(SdkOcspEvidence.bounded(der, 262_144)); }
        SdkOcspEvidence.copyChain(chain);
        Map<String,HybridSdkValue> authorizedRoles = Objects.requireNonNull(responderRoles, "responderRoles").objectFields();
        if (!authorizedRoles.keySet().equals(java.util.Set.of(VALUE_PRIMARY, VALUE_ALTERNATIVE))) { throw invalid(); }
        HybridSdkFrame.requireOcspRole(authorizedRoles.get(VALUE_PRIMARY), HybridSdkFrame.primaryAlgorithm());
        HybridSdkFrame.requireOcspRole(authorizedRoles.get(VALUE_ALTERNATIVE), HybridSdkFrame.alternativeAlgorithm());
        List<X509Certificate> certificates = Certificates.validatedChain(chain, baselineSnapshot, now);
        X509Certificate responder = certificates.getFirst();
        Map<String,HybridSdkValue> roles = responderRoles.objectFields();
        byte[] primary = valueBytes(roles.get(VALUE_PRIMARY).objectFields().get("spki"));
        byte[] alternative = valueBytes(roles.get(VALUE_ALTERNATIVE).objectFields().get("spki"));
        equal(primary, responder.getPublicKey().getEncoded()); equal(alternative, Certificates.alternativeKey(responder).getEncoded());
        Certificates.suiteKey(primary, false); Certificates.suiteKey(alternative, true);
        return certificates;
    }






    private static PublicKey key(byte[] der) throws java.io.IOException, GeneralSecurityException {
        equal(der, PkixEncoding.canonicalDer(der));
        zeroecho.sdk.util.BouncyCastleActivator.init(); return Pkix.publicKeyFromSubjectPublicKeyInfo(der);
    }

    private static boolean verifySignature(String algorithm, PublicKey key, byte[] message, byte[] signature, boolean alternative) throws GeneralSecurityException {
        if (alternative) { return PkixEncoding.verifyEmptyContextMldsa87(key, message, signature); }
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(key); verifier.update(message); return verifier.verify(signature);
    }
    private static byte[] valueBytes(HybridSdkValue value) { byte[] encoded = value.encode(); if (encoded[0] != LIMIT_4) { throw invalid(); } return Arrays.copyOfRange(encoded, 5, encoded.length); }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] time(Instant value) { return ByteBuffer.allocate(8).putLong(value.getEpochSecond()).array(); }
    private static Instant instant(byte[] value) { return Instant.ofEpochSecond(ByteBuffer.wrap(value).getLong()); }
    private static void equal(byte[] left, byte[] right) { if (!java.security.MessageDigest.isEqual(left, right)) { throw invalid(); } }

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
    // An immutable input contract carries independently authorized values, without active behavior.
    @SuppressWarnings("PMD.DataClass")
    public record TrustedContext(String realmId, String canonicalOrigin, PkiId authorityId, PkiId issuerId, PkiId chainPathId,
            String chainPathCommitment, String issuerBindingCommitment, byte[] originalRequestDer, byte[] clientNonce,
            List<byte[]> issuerPath, List<HybridSignatureBaseline> issuerCertificateBaselines, byte[] responderCertificateDer,
            HybridSdkValue responderRoles, Instant evaluationTime) {
        /**
         * Copies request, nonce and certificate arrays and checks the public context shape.
         *
         * <p>The issuer-path list and baseline list become unmodifiable; certificate
         * arrays are copied individually. The constructor validates neither certificate
         * signatures nor time validity, and does not prove that the nonce was random
         * or newly generated. The combined chain encoding bound is enforced when the
         * responder is validated, rather than by these per-certificate checks.</p>
         *
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
         * @throws NullPointerException if required coordinates, arrays, lists or list elements are null
         * @throws IllegalArgumentException if identifier/origin/digest syntax, nonce length, request
         *     or certificate bounds, path/baseline counts or the closed responder-role shape is invalid
         */
        public TrustedContext {
            HybridSdkValue.requireIdentifier(realmId); HybridSdkFrame.requireOrigin(canonicalOrigin);
            Objects.requireNonNull(authorityId, "authorityId"); Objects.requireNonNull(issuerId, "issuerId"); Objects.requireNonNull(chainPathId, "chainPathId");
            HybridSdkValue.requireIdentifier(authorityId.value()); HybridSdkValue.requireIdentifier(issuerId.value()); HybridSdkValue.requireIdentifier(chainPathId.value());
            if (chainPathCommitment == null || !chainPathCommitment.matches("(?:sha256:)?[0-9a-f]{64}")
                    || issuerBindingCommitment == null || !issuerBindingCommitment.matches("[0-9a-f]{64}")) { throw invalid(); }
            originalRequestDer = SdkOcspEvidence.bounded(originalRequestDer, 1_048_576);
            clientNonce = SdkOcspEvidence.bounded(clientNonce, LIMIT_32); if (clientNonce.length != LIMIT_32) { throw invalid(); }
            Objects.requireNonNull(issuerPath, "issuerPath"); if (issuerPath.isEmpty() || issuerPath.size() > 31) { throw invalid(); }
            issuerPath = issuerPath.stream().map(bytes -> SdkOcspEvidence.bounded(bytes, 262_144)).toList();
            issuerCertificateBaselines = List.copyOf(issuerCertificateBaselines);
            if (issuerCertificateBaselines.size() != issuerPath.size()) { throw invalid(); }
            responderCertificateDer = SdkOcspEvidence.bounded(responderCertificateDer, 262_144);
            Map<String,HybridSdkValue> roles = Objects.requireNonNull(responderRoles, "responderRoles").objectFields();
            if (!roles.keySet().equals(java.util.Set.of(VALUE_PRIMARY, VALUE_ALTERNATIVE))) { throw invalid(); }
            HybridSdkFrame.requireOcspRole(roles.get(VALUE_PRIMARY), HybridSdkFrame.primaryAlgorithm());
            HybridSdkFrame.requireOcspRole(roles.get(VALUE_ALTERNATIVE), HybridSdkFrame.alternativeAlgorithm());
            Objects.requireNonNull(evaluationTime, "evaluationTime");
        }
        /**
         * Returns a new copy of the exact caller-supplied original request.
         *
         * @return independently owned original-request DER bytes
         */
        @Override public byte[] originalRequestDer() { return originalRequestDer.clone(); }
        /**
         * Returns a new copy of the caller-supplied SDK nonce.
         *
         * @return independently owned 32-byte SDK nonce
         */
        @Override public byte[] clientNonce() { return clientNonce.clone(); }
        /**
         * Returns an unmodifiable issuer-path list containing fresh copies of its certificates.
         *
         * @return independent issuer-to-anchor certificate arrays in retained order
         */
        @Override public List<byte[]> issuerPath() { return issuerPath.stream().map(byte[]::clone).toList(); }
        /**
         * Returns a new copy of the policy-authorized responder certificate.
         *
         * @return independently owned responder DER bytes
         */
        @Override public byte[] responderCertificateDer() { return responderCertificateDer.clone(); }
    }
    /** Performs the supplied certificate-path and fixed-suite responder checks. */
    private static final class Certificates {
    private static List<X509Certificate> validatedChain(List<byte[]> chain,
            List<HybridSignatureBaseline> baselineSnapshot, Instant now)
            throws GeneralSecurityException, java.io.IOException {
    List<X509Certificate> certificates = new ArrayList<>();
    for (byte[] der : chain) {
        X509Certificate certificate = Pkix.parseCertificate(der); equal(der, certificate.getEncoded()); certificates.add(certificate);
        certificate.checkValidity(java.util.Date.from(now));
        if (certificate.hasUnsupportedCriticalExtension()) { throw invalid(); }
    }
    X509Certificate responder = certificates.getFirst();
    requireResponderDelegation(responder, certificates.get(1));
    for (int index = 1; index < certificates.size(); index++) {
        X509Certificate certificate = certificates.get(index); boolean[] caUsage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || caUsage != null && (caUsage.length <= 5 || !caUsage[5])) { throw invalid(); }
        if (certificate.getBasicConstraints() < index - 1) { throw invalid(); }
        if (index < certificates.size() - 1) { verifyCertificate(certificate, certificates.get(index + 1), baselineSnapshot.get(index - 1)); }
    }
        return certificates;
    }
    private static void requireResponderDelegation(X509Certificate responder, X509Certificate issuer) throws GeneralSecurityException, java.io.IOException {
    boolean[] usage = responder.getKeyUsage();
    if (responder.getBasicConstraints() >= 0 || usage == null || usage.length == 0 || !usage[0]
            || responder.getExtendedKeyUsage() == null || !responder.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.9")) { throw invalid(); }
    verifyCertificate(responder, issuer, HybridSignatureBaseline.COR3_SIGNED_WRAPPER);
    }
    private static void verifyCertificate(X509Certificate certificate, X509Certificate issuer, HybridSignatureBaseline baseline) throws GeneralSecurityException, java.io.IOException {
        if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal()) || baseline == HybridSignatureBaseline.NONE) { throw invalid(); }
        certificate.verify(issuer.getPublicKey()); PublicKey alternative = alternativeKey(issuer);
        boolean valid = switch (baseline) {
            case COR3_SIGNED_WRAPPER -> Pkix.verifyAlternativeSignatureCor3(certificate, alternative);
            case LEGACY_PRE_TBS -> Pkix.verifyAlternativeSignature(certificate, alternative);
            case NONE -> false;
        };
        if (!valid) { throw invalid(); }
    }
    private static PublicKey alternativeKey(X509Certificate certificate) throws java.io.IOException, GeneralSecurityException {
        byte[] extension = certificate.getExtensionValue(zeroecho.pki.impl.hybrid.AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO); if (extension == null) { throw invalid(); }
        return key(PkixEncoding.octetStringContents(extension));
    }
    private static PublicKey suiteKey(byte[] der, boolean alternative) throws java.io.IOException, GeneralSecurityException {
        PublicKey key = key(der);
        PkixEncoding.requireCanonicalSubjectPublicKeyInfo(der);
        AlgorithmIdentifier algorithm = Pkix.subjectPublicKeyAlgorithm(der);
        byte[] bits = Pkix.subjectPublicKeyBytes(der);
        if (alternative) {
            if (!"2.16.840.1.101.3.4.3.19".equals(algorithm.oid())
                    || algorithm.parameterForm() != AlgorithmIdentifier.ParameterForm.ABSENT
                    || bits.length != 2_592) { throw invalid(); }
        } else {
            PkixEncoding.requireP384SubjectPublicKeyInfo(der);
        }
        return key;
    }
    }
}
