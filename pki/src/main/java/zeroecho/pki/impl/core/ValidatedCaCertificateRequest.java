/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.profile.CaCertificatePolicy;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.SubjectRdn;

/**
 * Immutable gate-produced CA certificate request accepted by the issuer
 * backend.
 *
 * <p>
 * The request contains only values approved against one exact active profile
 * version. It carries no generic attributes, raw profile document, or caller
 * selected extension material.
 * </p>
 */
@SuppressWarnings("PMD.DataClass")
public final class ValidatedCaCertificateRequest {
    /** Closed CA certificate operations authorized by this gate. */
    public enum Operation {
        /** Creates a self-signed root credential. */
        CREATE_ROOT,
        /** Imports an existing root credential after full profile validation. */
        IMPORT_ROOT,
        /** Creates an intermediate CA's initial credential. */
        CREATE_INTERMEDIATE,
        /** Issues an additional intermediate CA credential. */
        ISSUE_INTERMEDIATE
    }

    private final Operation operation;
    private final FormatId formatId;
    private final PkiId issuerCaId;
    private final PkiId subjectCaId;
    private final CertificateProfileRef profileReference;
    private final CertificateProfileKind certificateType;
    private final SubjectRef subjectRef;
    private final List<SubjectRdn> subjectRdns;
    private final EncodedObject exactPublicKey;
    private final Validity validity;
    private final BigInteger serial;
    private final CaCertificatePolicy policy;

    // The constructor is the single cohesive gate output boundary.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    /* package */ ValidatedCaCertificateRequest(Operation operation, FormatId formatId, PkiId issuerCaId,
            PkiId subjectCaId, CertificateProfileRef profileReference, CertificateProfileKind certificateType,
            SubjectRef subjectRef, List<SubjectRdn> subjectRdns, EncodedObject exactPublicKey, Validity validity,
            BigInteger serial, CaCertificatePolicy policy) {
        this.operation = Objects.requireNonNull(operation, "operation");
        this.formatId = Objects.requireNonNull(formatId, "formatId");
        this.issuerCaId = Objects.requireNonNull(issuerCaId, "issuerCaId");
        this.subjectCaId = Objects.requireNonNull(subjectCaId, "subjectCaId");
        this.profileReference = Objects.requireNonNull(profileReference, "profileReference");
        this.certificateType = Objects.requireNonNull(certificateType, "certificateType");
        this.subjectRef = Objects.requireNonNull(subjectRef, "subjectRef");
        this.subjectRdns = List.copyOf(Objects.requireNonNull(subjectRdns, "subjectRdns"));
        EncodedObject publicKey = Objects.requireNonNull(exactPublicKey, "exactPublicKey");
        this.exactPublicKey = new EncodedObject(publicKey.encoding(), publicKey.bytes());
        this.validity = Objects.requireNonNull(validity, "validity");
        this.serial = Objects.requireNonNull(serial, "serial");
        this.policy = Objects.requireNonNull(policy, "policy");
        if (serial.signum() <= 0 || serial.toByteArray().length > 20) {
            throw new IllegalArgumentException("serial must be positive and at most 20 bytes");
        }
    }

    /** Returns the authorized operation. */
    public Operation operation() {
        return operation;
    }

    /** Returns the credential format. */
    public FormatId formatId() {
        return formatId;
    }

    /** Returns the issuing CA identifier. */
    public PkiId issuerCaId() {
        return issuerCaId;
    }

    /** Returns the subject CA identifier. */
    public PkiId subjectCaId() {
        return subjectCaId;
    }

    /** Returns the exact active profile reference. */
    public CertificateProfileRef profileReference() {
        return profileReference;
    }

    /** Returns the required certificate kind. */
    public CertificateProfileKind certificateType() {
        return certificateType;
    }

    /** Returns the canonical subject reference. */
    public SubjectRef subjectRef() {
        return subjectRef;
    }

    /** Returns the ordered canonical subject components. */
    public List<SubjectRdn> subjectRdns() {
        return subjectRdns;
    }

    /** Returns a defensive copy of the proof-bound public key. */
    public EncodedObject exactPublicKey() {
        return new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
    }

    /** Returns the approved exact validity. */
    public Validity validity() {
        return validity;
    }

    /** Returns the issuer-controlled serial. */
    public BigInteger serial() {
        return serial;
    }

    /** Returns the exact profile-derived CA policy. */
    public CaCertificatePolicy policy() {
        return policy;
    }
}
