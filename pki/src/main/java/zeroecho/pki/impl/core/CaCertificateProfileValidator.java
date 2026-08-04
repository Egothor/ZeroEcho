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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.SubjectRdnRule;
import zeroecho.pki.api.profile.SubjectRdnType;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;

/**
 * Authoritative active-profile gate for root and intermediate certificate
 * requests.
 */
// The closed gate deliberately keeps cohesive profile inputs together and
// redacts attacker-controlled parser failures rather than retaining their causes.
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ExcessiveParameterList", "PMD.PreserveStackTrace",
        "PMD.AvoidRethrowingException" })
final class CaCertificateProfileValidator {
    private static final int MAXIMUM_SUBJECT_DER_BYTES = 16 * 1024;
    private static final int SINGLE_VALUE = 1;

    private CaCertificateProfileValidator() {
    }

    /* package */ static ValidatedCaCertificateRequest validate(ValidatedCaCertificateRequest.Operation operation,
            ActiveCertificateProfile activeProfile, CertificateProfileKind expectedKind, FormatId formatId,
            PkiId issuerCaId, PkiId subjectCaId, SubjectRef requestedSubject, EncodedObject exactPublicKey,
            Optional<Validity> requestedValidity, Instant evaluationTime, Optional<Instant> issuerNotAfter,
            BigInteger serial, zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority) {
        CertificateProfileDefinition definition = activeProfile.definition();
        requireProfileShape(definition, expectedKind, formatId);
        List<SubjectRdn> approvedSubject = validateSubject(requestedSubject, definition);
        return validateApprovedSubject(operation, activeProfile, expectedKind, formatId, issuerCaId, subjectCaId,
                approvedSubject, exactPublicKey, requestedValidity, evaluationTime, issuerNotAfter, serial, authority);
    }

    /*
     * Package-private continuation used only after validateSubject has approved the
     * requester input. It preserves profile-fixed RDNs without treating them as a
     * second requester submission.
     */
    /* package */ static ValidatedCaCertificateRequest validateApprovedSubject(
            ValidatedCaCertificateRequest.Operation operation, ActiveCertificateProfile activeProfile,
            CertificateProfileKind expectedKind, FormatId formatId, PkiId issuerCaId, PkiId subjectCaId,
            List<SubjectRdn> approvedSubject, EncodedObject exactPublicKey, Optional<Validity> requestedValidity,
            Instant evaluationTime, Optional<Instant> issuerNotAfter, BigInteger serial,
            zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority) {
        CertificateProfileDefinition definition = activeProfile.definition();
        requireProfileShape(definition, expectedKind, formatId);
        List<SubjectRdn> subjectSnapshot = requireApprovedSubject(approvedSubject);
        CertificateProfileValidator.requireSubjectKeyAllowed(exactPublicKey,
                definition.caPolicy().allowedSubjectKeyAlgorithmIds(), authority);
        Validity validity = approvedValidity(requestedValidity, definition, evaluationTime, issuerNotAfter,
                operation == ValidatedCaCertificateRequest.Operation.IMPORT_ROOT);
        SubjectRef canonicalSubject = new SubjectRef(BcX509ProfileSupport.subject(subjectSnapshot).toString());
        return new ValidatedCaCertificateRequest(operation, formatId, issuerCaId, subjectCaId,
                activeProfile.reference(), expectedKind, canonicalSubject, subjectSnapshot, exactPublicKey, validity,
                serial, definition.caPolicy(), definition.algorithmBindingPolicy());
    }

    /* package */ static void requireProfileShape(ActiveCertificateProfile activeProfile,
            CertificateProfileKind expectedKind, FormatId formatId) {
        requireProfileShape(activeProfile.definition(), expectedKind, formatId);
    }

    private static void requireProfileShape(CertificateProfileDefinition definition,
            CertificateProfileKind expectedKind, FormatId formatId) {
        if (definition.certificateType() != expectedKind) {
            throw reject("CA_PROFILE_KIND_MISMATCH");
        }
        if (!definition.formatId().equals(formatId)) {
            throw reject("CA_PROFILE_FORMAT_MISMATCH");
        }
    }

    /* package */ static List<SubjectRdn> validateSubject(SubjectRef requestedSubject,
            CertificateProfileDefinition definition) {
        List<SubjectRdn> requested = parseSubject(requestedSubject);
        Map<SubjectRdnType, SubjectRdnRule> rules = new EnumMap<>(SubjectRdnType.class);
        for (SubjectRdnRule rule : definition.subjectPolicy().rules()) {
            rules.put(rule.type(), rule);
        }
        Map<SubjectRdnType, Integer> counts = new EnumMap<>(SubjectRdnType.class);
        List<SubjectRdn> approved = new ArrayList<>(requested.size() + rules.size());
        for (SubjectRdn rdn : requested) {
            SubjectRdnRule rule = rules.get(rdn.type());
            if (rule == null || !rule.requesterSupplied()) {
                throw reject("CA_SUBJECT_RDN_FORBIDDEN");
            }
            String canonical = SubjectRdnRule.canonicalValue(rdn.type(), rdn.value());
            if (canonical.getBytes(StandardCharsets.UTF_8).length > rule.maximumUtf8Bytes()) {
                throw reject("CA_SUBJECT_RDN_TOO_LARGE");
            }
            int count = Math.addExact(counts.getOrDefault(rdn.type(), 0), 1);
            if (count > rule.maximumOccurrences()) {
                throw reject("CA_SUBJECT_RDN_CARDINALITY");
            }
            counts.put(rdn.type(), count);
            approved.add(new SubjectRdn(rdn.type(), canonical));
        }
        for (SubjectRdnRule rule : definition.subjectPolicy().rules()) {
            if (rule.fixedValue().isPresent()) {
                approved.add(new SubjectRdn(rule.type(), rule.fixedValue().orElseThrow()));
                counts.put(rule.type(), 1);
            }
            int count = counts.getOrDefault(rule.type(), 0);
            if (count < rule.minimumOccurrences() || count > rule.maximumOccurrences()) {
                throw reject("CA_SUBJECT_RDN_REQUIRED");
            }
        }
        if (approved.isEmpty() || approved.size() > zeroecho.pki.api.profile.SubjectPolicy.HARD_MAXIMUM_RDN_COUNT) {
            throw reject("CA_SUBJECT_INVALID");
        }
        try {
            if (BcX509ProfileSupport.subject(approved).getEncoded().length > MAXIMUM_SUBJECT_DER_BYTES) {
                throw reject("CA_SUBJECT_TOO_LARGE");
            }
        } catch (java.io.IOException exception) {
            throw reject("CA_SUBJECT_INVALID");
        }
        return List.copyOf(approved);
    }

    /*
     * Validates a previously approved canonical subject without reclassifying
     * profile-fixed RDNs as requester input.
     */
    /* package */ static List<SubjectRdn> validateTrustedSubject(SubjectRef trustedSubject,
            CertificateProfileDefinition definition) {
        List<SubjectRdn> existing = parseSubject(trustedSubject);
        Map<SubjectRdnType, SubjectRdnRule> rules = new EnumMap<>(SubjectRdnType.class);
        for (SubjectRdnRule rule : definition.subjectPolicy().rules()) {
            rules.put(rule.type(), rule);
        }
        Map<SubjectRdnType, Integer> counts = new EnumMap<>(SubjectRdnType.class);
        List<SubjectRdn> requesterValues = new ArrayList<>(existing.size());
        for (SubjectRdn rdn : existing) {
            SubjectRdnRule rule = rules.get(rdn.type());
            if (rule == null) {
                throw reject("CA_SUBJECT_RDN_FORBIDDEN");
            }
            String canonical = SubjectRdnRule.canonicalValue(rdn.type(), rdn.value());
            if (!canonical.equals(rdn.value())
                    || canonical.getBytes(StandardCharsets.UTF_8).length > rule.maximumUtf8Bytes()) {
                throw reject("CA_SUBJECT_RDN_INVALID");
            }
            int count = Math.addExact(counts.getOrDefault(rdn.type(), 0), 1);
            if (count > rule.maximumOccurrences()) {
                throw reject("CA_SUBJECT_RDN_CARDINALITY");
            }
            counts.put(rdn.type(), count);
            if (rule.requesterSupplied()) {
                requesterValues.add(rdn);
            } else if (rule.fixedValue().isEmpty() || !rule.fixedValue().orElseThrow().equals(rdn.value())) {
                throw reject("CA_SUBJECT_FIXED_VALUE_MISMATCH");
            }
        }
        List<SubjectRdn> expected = new ArrayList<>(existing.size());
        expected.addAll(requesterValues);
        for (SubjectRdnRule rule : definition.subjectPolicy().rules()) {
            int count = counts.getOrDefault(rule.type(), 0);
            if (count < rule.minimumOccurrences() || count > rule.maximumOccurrences()) {
                throw reject("CA_SUBJECT_RDN_REQUIRED");
            }
            rule.fixedValue().ifPresent(value -> expected.add(new SubjectRdn(rule.type(), value)));
        }
        if (!existing.equals(expected)) {
            throw reject("CA_SUBJECT_ORDER_INVALID");
        }
        return requireApprovedSubject(expected);
    }

    private static List<SubjectRdn> requireApprovedSubject(List<SubjectRdn> approvedSubject) {
        List<SubjectRdn> snapshot = List.copyOf(approvedSubject);
        if (snapshot.isEmpty() || snapshot.size() > zeroecho.pki.api.profile.SubjectPolicy.HARD_MAXIMUM_RDN_COUNT) {
            throw reject("CA_SUBJECT_INVALID");
        }
        try {
            if (BcX509ProfileSupport.subject(snapshot).getEncoded().length > MAXIMUM_SUBJECT_DER_BYTES) {
                throw reject("CA_SUBJECT_TOO_LARGE");
            }
        } catch (java.io.IOException exception) {
            throw reject("CA_SUBJECT_INVALID");
        }
        return snapshot;
    }

    private static List<SubjectRdn> parseSubject(SubjectRef subjectRef) {
        try {
            X500Name name = new X500Name(subjectRef.value());
            List<SubjectRdn> result = new ArrayList<>();
            for (RDN rdn : name.getRDNs()) {
                AttributeTypeAndValue[] values = rdn.getTypesAndValues();
                if (values.length != SINGLE_VALUE) {
                    throw reject("CA_SUBJECT_MULTIVALUED_RDN");
                }
                result.add(new SubjectRdn(SubjectRdnType.fromOid(values[0].getType().getId()),
                        values[0].getValue().toString()));
            }
            return List.copyOf(result);
        } catch (PkiException exception) {
            throw exception;
        } catch (IllegalArgumentException exception) {
            throw reject("CA_SUBJECT_INVALID");
        }
    }

    private static Validity approvedValidity(Optional<Validity> requested, CertificateProfileDefinition definition,
            Instant evaluationTime, Optional<Instant> issuerNotAfter, boolean imported) {
        try {
            Instant ceiling = evaluationTime.plus(definition.maximumValidity());
            if (issuerNotAfter.isPresent() && issuerNotAfter.orElseThrow().isBefore(ceiling)) {
                ceiling = issuerNotAfter.orElseThrow();
            }
            Validity validity = requested.isPresent() ? requested.orElseThrow() : new Validity(evaluationTime, ceiling);
            boolean invalidStart = imported ? validity.notBefore().isAfter(evaluationTime)
                    : !validity.notBefore().equals(evaluationTime);
            if (invalidStart || !validity.notAfter().isAfter(evaluationTime)
                    || java.time.Duration.between(validity.notBefore(), validity.notAfter())
                            .compareTo(definition.maximumValidity()) > 0
                    || !imported && validity.notAfter().isAfter(ceiling)
                    || !validity.notAfter().isAfter(validity.notBefore())) {
                throw reject("CA_VALIDITY_REJECTED");
            }
            return validity;
        } catch (DateTimeException | ArithmeticException exception) {
            throw reject("CA_VALIDITY_REJECTED");
        }
    }

    private static PkiException reject(String code) {
        return new PkiException("CA certificate profile rejected: code=" + code);
    }
}
