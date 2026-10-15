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
package zeroecho.pki.impl.core;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import zeroecho.pkix.Pkix;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.LeafCertificatePolicy;
import zeroecho.pki.api.profile.SubjectAlternativeNamePolicy;
import zeroecho.pki.api.profile.SubjectAlternativeNameRule;
import zeroecho.pki.api.profile.SubjectAlternativeNameType;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;

/**
 * Authoritative deny-by-default end-entity profile validation boundary.
 */
// The aggregate complexity is the explicit closed profile-validation grammar.
@SuppressWarnings("PMD.CyclomaticComplexity")
final class CertificateProfileValidator {

    private static final String EC_FAMILY = "ec";
    private static final int MAXIMUM_SPKI_BYTES = 1024 * 1024;

    private CertificateProfileValidator() {
    }

    /* package */ static ValidatedCertificateRequest validate(VerifiedIssuanceCandidate candidate,
            CertificateProfile profile, CertificateProfileRef profileReference, Credential issuerCredential,
            Instant evaluationTime, X509AuthoritySnapshot authority) {
        requireCanonicalRequestAttributes(candidate.request());
        return validatePolicy(candidate, profile, profileReference, issuerCredential, evaluationTime, authority, false);
    }

    /**
     * Validates a request reconstructed from an already-issued certificate for
     * renewal or reissue. Applies the identical deny-by-default subject, SAN,
     * key, and validity policy, but does not require the CSR transport attribute,
     * because a reconstruction carries no fresh PKCS#10 request.
     */
    /* package */ static ValidatedCertificateRequest validateReconstructed(VerifiedIssuanceCandidate candidate,
            CertificateProfile profile, CertificateProfileRef profileReference, Credential issuerCredential,
            Instant evaluationTime, X509AuthoritySnapshot authority) {
        return validatePolicy(candidate, profile, profileReference, issuerCredential, evaluationTime, authority, true);
    }

    private static ValidatedCertificateRequest validatePolicy(VerifiedIssuanceCandidate candidate,
            CertificateProfile profile, CertificateProfileRef profileReference, Credential issuerCredential,
            Instant evaluationTime, X509AuthoritySnapshot authority, boolean reconstructed) {
        ParsedCertificationRequest request = candidate.request();
        LeafCertificatePolicy policy = profile.leafPolicy();
        List<SubjectRdn> approvedSubject = validateSubject(request, profile, reconstructed);
        List<SubjectAlternativeName> approvedSans = validateSans(request, policy, approvedSubject.isEmpty());
        requireSubjectKeyAllowed(candidate.exactPublicKey(), policy.allowedSubjectKeyAlgorithmIds(), authority);
        Validity validity = approvedValidity(candidate, request, profile, issuerCredential, evaluationTime);
        boolean sanCritical = approvedSubject.isEmpty()
                || policy.subjectAlternativeNamePolicy().criticalWithNonemptySubject();
        SubjectRef approvedSubjectRef = new SubjectRef(approvedSubject.isEmpty() ? "x509:empty-subject"
                : BcX509ProfileSupport.subjectRefString(approvedSubject));
        return new ValidatedCertificateRequest(candidate.issuerCaId(), profileReference, approvedSubjectRef,
                approvedSubject, approvedSans, sanCritical, candidate.exactPublicKey(), validity, policy.keyUsages(),
                policy.extendedKeyUsages(), policy.keyUsageCritical(), policy.extendedKeyUsageCritical(),
                policy.basicConstraintsCritical(), profile.algorithmBindingPolicy());
    }

    private static void requireCanonicalRequestAttributes(ParsedCertificationRequest request) {
        try {
            zeroecho.pki.impl.framework.x509.bc.BcX509RequestPayloads.extract(request);
        } catch (IllegalArgumentException invalid) {
            throw reject("REQUEST_ATTRIBUTE_UNSUPPORTED"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private static List<SubjectRdn> validateSubject(ParsedCertificationRequest request, CertificateProfile profile,
            boolean reconstructed) {
        Map<SubjectRdnType, SubjectRdnRule> rules = new EnumMap<>(SubjectRdnType.class);
        for (SubjectRdnRule rule : profile.subjectPolicy().rules()) {
            rules.put(rule.type(), rule);
        }
        Map<SubjectRdnType, Integer> counts = new EnumMap<>(SubjectRdnType.class);
        List<SubjectRdn> approved = new ArrayList<>(request.subjectRdns().size() + rules.size());
        for (SubjectRdn rdn : request.subjectRdns()) {
            SubjectRdnRule rule = rules.get(rdn.type());
            String canonical = canonicalSubjectValue(rdn, rule, reconstructed);
            int count = Math.addExact(counts.getOrDefault(rdn.type(), 0), 1);
            if (count > rule.maximumOccurrences()) {
                throw reject("SUBJECT_RDN_CARDINALITY");
            }
            counts.put(rdn.type(), count);
            approved.add(new SubjectRdn(rdn.type(), canonical));
        }
        for (SubjectRdnRule rule : profile.subjectPolicy().rules()) {
            if (rule.fixedValue().isPresent() && !reconstructed) {
                approved.add(new SubjectRdn(rule.type(), rule.fixedValue().orElseThrow()));
                counts.put(rule.type(), 1);
            }
            int count = counts.getOrDefault(rule.type(), 0);
            if (count < rule.minimumOccurrences() || count > rule.maximumOccurrences()) {
                throw reject("SUBJECT_RDN_REQUIRED");
            }
        }
        if (approved.isEmpty() && !profile.subjectPolicy().allowEmpty()) {
            throw reject("SUBJECT_EMPTY");
        }
        if (approved.size() > zeroecho.pki.api.profile.SubjectPolicy.HARD_MAXIMUM_RDN_COUNT) {
            throw reject("SUBJECT_TOO_MANY_RDNS");
        }
        return List.copyOf(approved);
    }

    private static String canonicalSubjectValue(SubjectRdn rdn, SubjectRdnRule rule, boolean reconstructed) {
        if (rule == null || !rule.requesterSupplied() && !(reconstructed && rule.fixedValue().isPresent())) {
            throw reject("SUBJECT_RDN_FORBIDDEN");
        }
        String canonical = SubjectRdnRule.canonicalValue(rdn.type(), rdn.value());
        if (reconstructed && rule.fixedValue().isPresent() && !rule.fixedValue().orElseThrow().equals(canonical)) {
            throw reject("SUBJECT_FIXED_RDN_MISMATCH");
        }
        if (canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > rule.maximumUtf8Bytes()) {
            throw reject("SUBJECT_RDN_TOO_LARGE");
        }
        return canonical;
    }

    // The branches preserve the closed SAN type-specific profile grammar.
    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.NPathComplexity" })
    private static List<SubjectAlternativeName> validateSans(ParsedCertificationRequest request,
            LeafCertificatePolicy policy, boolean emptySubject) {
        SubjectAlternativeNamePolicy sanPolicy = policy.subjectAlternativeNamePolicy();
        List<SubjectAlternativeName> sans = request.subjectAlternativeNames();
        if (sans.size() < sanPolicy.minimumTotal() || sans.size() > sanPolicy.maximumTotal()) {
            throw reject("SAN_COUNT_INVALID");
        }
        Map<SubjectAlternativeNameType, SubjectAlternativeNameRule> rules = new EnumMap<>(
                SubjectAlternativeNameType.class);
        for (SubjectAlternativeNameRule rule : sanPolicy.rules()) {
            rules.put(rule.type(), rule);
        }
        Map<SubjectAlternativeNameType, Integer> counts = new EnumMap<>(SubjectAlternativeNameType.class);
        Set<SubjectAlternativeName> unique = new HashSet<>();
        boolean serviceIdentity = false;
        boolean emailIdentity = false;
        for (SubjectAlternativeName san : sans) {
            if (!unique.add(san)) {
                throw reject("SAN_DUPLICATE");
            }
            SubjectAlternativeNameRule rule = rules.get(san.type());
            if (rule == null) {
                throw reject("SAN_TYPE_FORBIDDEN");
            }
            int count = Math.addExact(counts.getOrDefault(san.type(), 0), 1);
            if (count > rule.maximum()) {
                throw reject("SAN_TYPE_CARDINALITY");
            }
            counts.put(san.type(), count);
            if (san instanceof SubjectAlternativeName.DnsName dns && dns.value().startsWith("*.")
                    && !sanPolicy.allowDnsWildcard()) {
                throw reject("SAN_WILDCARD_FORBIDDEN");
            }
            if (san instanceof SubjectAlternativeName.IpAddress ip
                    && (ip.bytes().length == 4 && !rule.allowIpv4() || ip.bytes().length == 16 && !rule.allowIpv6())) {
                throw reject("SAN_IP_FAMILY_FORBIDDEN");
            }
            if (san instanceof SubjectAlternativeName.UriName uri) {
                String scheme = java.net.URI.create(uri.value()).getScheme();
                if (!sanPolicy.allowedUriSchemes().contains(scheme)) {
                    throw reject("SAN_URI_SCHEME_FORBIDDEN");
                }
            }
            serviceIdentity |= san.type() == SubjectAlternativeNameType.DNS_NAME
                    || san.type() == SubjectAlternativeNameType.IP_ADDRESS
                    || san.type() == SubjectAlternativeNameType.URI;
            emailIdentity |= san.type() == SubjectAlternativeNameType.RFC822_NAME;
        }
        for (SubjectAlternativeNameRule rule : sanPolicy.rules()) {
            int count = counts.getOrDefault(rule.type(), 0);
            if (count < rule.minimum() || count > rule.maximum()) {
                throw reject("SAN_TYPE_REQUIRED");
            }
        }
        if (emptySubject && sans.isEmpty() || sanPolicy.requireServiceIdentity() && !serviceIdentity
                || sanPolicy.requireEmailIdentity() && !emailIdentity) {
            throw reject("SAN_IDENTITY_REQUIRED");
        }
        return List.copyOf(sans);
    }

    // The public exception deliberately redacts ASN.1 parser details.
    @SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.AvoidRethrowingException" })
    /* package */ static void requireSubjectKeyAllowed(zeroecho.pki.api.EncodedObject exactPublicKey,
            Set<String> allowedAlgorithms, X509AuthoritySnapshot authority) {
        if (exactPublicKey.encoding() != Encoding.DER) {
            throw reject("SUBJECT_KEY_UNSUPPORTED");
        }
        byte[] encoded = exactPublicKey.bytes();
        try {
            new StreamingDerReader().validateSubjectPublicKeyInfo(encoded, MAXIMUM_SPKI_BYTES);
            zeroecho.pkix.AlgorithmIdentifier spkiAlgorithm = Pkix.subjectPublicKeyAlgorithm(encoded);
            AlgorithmIdentity identity;
            try {
                identity = new BcX509AlgorithmAdapter(authority.bindings()).decode(spkiAlgorithm,
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            } catch (IllegalArgumentException invalidBinding) {
                boolean knownOid = authority.bindings().rules().stream()
                        .filter(rule -> rule.role() == X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM)
                        .anyMatch(rule -> rule.oid().equals(spkiAlgorithm.oid()));
                throw reject(knownOid ? "SUBJECT_KEY_PARAMETERS_UNSUPPORTED" : "SUBJECT_KEY_ALGORITHM_UNKNOWN");
            }
            SubjectKeyAlgorithm algorithm = subjectKeyAlgorithm(identity);
            if (!allowedAlgorithms.contains(algorithm.profileId())) {
                throw reject("SUBJECT_KEY_ALGORITHM_FORBIDDEN");
            }
            byte[] nativeEncoded = new zeroecho.pki.impl.framework.x509.bc.BcX509PublicKeyAdapter(
                    authority.bindings()).unwrap(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm.jcaName());
            PublicKey reconstructed = keyFactory.generatePublic(new X509EncodedKeySpec(nativeEncoded));
            byte[] canonical = reconstructed.getEncoded();
            try {
                if (canonical == null || !MessageDigest.isEqual(nativeEncoded, canonical)) {
                    throw reject("SUBJECT_KEY_NOT_CANONICAL");
                }
            } finally {
                java.util.Arrays.fill(nativeEncoded, (byte) 0);
                if (canonical != null) {
                    java.util.Arrays.fill(canonical, (byte) 0);
                }
            }
        } catch (PkiException exception) {
            throw exception;
        } catch (GeneralSecurityException | IllegalArgumentException | IOException exception) {
            throw reject("SUBJECT_KEY_UNSUPPORTED");
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private static SubjectKeyAlgorithm subjectKeyAlgorithm(AlgorithmIdentity identity) {
        if (identity.equals(BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY)) {
            return new SubjectKeyAlgorithm("RSA", "RSA");
        }
        if (EC_FAMILY.equals(identity.family().name())) {
            return new SubjectKeyAlgorithm("ECDSA", "EC");
        }
        if (identity.equals(BootstrapAlgorithmIdentities.ED25519_PUBLIC_KEY)) {
            return new SubjectKeyAlgorithm("Ed25519", "Ed25519");
        }
        if (identity.equals(BootstrapAlgorithmIdentities.ED448_PUBLIC_KEY)) {
            return new SubjectKeyAlgorithm("Ed448", "Ed448");
        }
        if (identity.equals(BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY)) {
            return new SubjectKeyAlgorithm("SPHINCS+", "SPHINCS+");
        }
        if (identity.family().name().startsWith("ml-dsa-")) {
            return new SubjectKeyAlgorithm("ML-DSA", "ML-DSA");
        }
        if (identity.family().name().startsWith("slh-dsa-")) {
            return new SubjectKeyAlgorithm("SLH-DSA", "SLH-DSA");
        }
        throw reject("SUBJECT_KEY_ALGORITHM_UNKNOWN");
    }

    // The public exception deliberately redacts temporal arithmetic details.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static Validity approvedValidity(VerifiedIssuanceCandidate candidate, ParsedCertificationRequest request,
            CertificateProfile profile, Credential issuerCredential, Instant evaluationTime) {
        Optional<Validity> supplied = candidate.validityOverride().isPresent() ? candidate.validityOverride()
                : request.requestedValidity();
        Duration duration = supplied.map(value -> Duration.between(value.notBefore(), value.notAfter()))
                .orElse(profile.maximumValidity());
        if (duration.isZero() || duration.isNegative() || duration.compareTo(profile.maximumValidity()) > 0) {
            throw reject("VALIDITY_EXCEEDS_PROFILE");
        }
        Instant notAfter;
        try {
            notAfter = evaluationTime.plus(duration);
        } catch (DateTimeException | ArithmeticException exception) {
            throw reject("VALIDITY_INVALID");
        }
        if (notAfter.isAfter(issuerCredential.validity().notAfter())) {
            throw reject("VALIDITY_EXCEEDS_ISSUER");
        }
        try {
            // X.509 Time represents whole seconds. Preserve the largest interval
            // inside the already-approved bounds, without extending either end.
            Instant notBefore = evaluationTime.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
            if (!notBefore.equals(evaluationTime)) {
                notBefore = notBefore.plusSeconds(1);
            }
            Instant encodedNotAfter = notAfter.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
            if (!encodedNotAfter.isAfter(notBefore)) {
                throw reject("VALIDITY_INVALID");
            }
            return new Validity(notBefore, encodedNotAfter);
        } catch (DateTimeException | ArithmeticException exception) {
            throw reject("VALIDITY_INVALID");
        }
    }

    private static PkiException reject(String code) {
        return new ProfileValidationRejection(code);
    }

    private record SubjectKeyAlgorithm(String profileId, String jcaName) {
    }
}
