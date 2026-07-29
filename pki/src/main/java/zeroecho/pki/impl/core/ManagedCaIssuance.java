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

import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;

/**
 * Immutable opaque authority for an intermediate CA issuance operation.
 *
 * <p>
 * Instances are constructed only inside the core CA proof gate after a successful
 * managed-key possession challenge. The class has no public constructor or
 * factory, so callers outside the core implementation cannot convert raw
 * attributes or public-key bytes into issuance authority.
 * </p>
 *
 * <p>
 * All mutable values are defensively snapshotted. Accessors return defensive
 * copies where necessary, allowing a backend to consume the object concurrently
 * without observing caller mutation.
 * </p>
 */
@SuppressWarnings("PMD.DataClass")
public final class ManagedCaIssuance {

    /**
     * Supported proof-bound CA issuance operations.
     */
    public enum Operation {
        /** Creates the initial credential for a newly defined intermediate CA. */
        CREATE_INTERMEDIATE,
        /** Issues an additional credential for an existing intermediate CA. */
        ISSUE_INTERMEDIATE
    }

    private final Operation operation;
    private final FormatId formatId;
    private final PkiId issuerCaId;
    private final PkiId subjectCaId;
    private final String profileId;
    private final Optional<Validity> requestedValidity;
    private final AttributeSet attributes;
    private final SubjectRef subjectRef;
    private final KeyRef subjectKeyRef;
    private final EncodedObject exactPublicKey;

    /* default */ ManagedCaIssuance(CaProofGate.ManagedKeyProof proof, Operation operation, PkiId issuerCaId,
            PkiId subjectCaId, String profileId, Optional<Validity> requestedValidity, AttributeSet attributes,
            SubjectRef subjectRef) {
        CaProofGate.ManagedKeyProof managedKeyProof = Objects.requireNonNull(proof, "proof");
        this.operation = Objects.requireNonNull(operation, "operation");
        this.formatId = managedKeyProof.formatId();
        this.issuerCaId = Objects.requireNonNull(issuerCaId, "issuerCaId");
        this.subjectCaId = Objects.requireNonNull(subjectCaId, "subjectCaId");
        this.profileId = Objects.requireNonNull(profileId, "profileId");
        this.requestedValidity = Objects.requireNonNull(requestedValidity, "requestedValidity");
        this.attributes = VerifiedIssuanceCandidate.snapshotAttributes(Objects.requireNonNull(attributes,
                "attributes"));
        this.subjectRef = Objects.requireNonNull(subjectRef, "subjectRef");
        this.subjectKeyRef = managedKeyProof.keyRef();
        EncodedObject publicKey = managedKeyProof.exactPublicKey();
        this.exactPublicKey = new EncodedObject(publicKey.encoding(), publicKey.bytes());
    }

    /**
     * Returns the authorized operation.
     *
     * @return authorized operation, never {@code null}
     */
    public Operation operation() {
        return operation;
    }

    /**
     * Returns the credential format.
     *
     * @return format identifier, never {@code null}
     */
    public FormatId formatId() {
        return formatId;
    }

    /**
     * Returns the issuing CA identifier.
     *
     * @return issuing CA identifier, never {@code null}
     */
    public PkiId issuerCaId() {
        return issuerCaId;
    }

    /**
     * Returns the subject CA identifier.
     *
     * @return subject CA identifier, never {@code null}
     */
    public PkiId subjectCaId() {
        return subjectCaId;
    }

    /**
     * Returns the validated profile identifier.
     *
     * @return profile identifier, never blank
     */
    public String profileId() {
        return profileId;
    }

    /**
     * Returns the optional validated validity request.
     *
     * @return optional validity, never {@code null}
     */
    public Optional<Validity> requestedValidity() {
        return requestedValidity;
    }

    /**
     * Returns a defensive snapshot of authoritative CA attributes.
     *
     * @return immutable attribute snapshot, never {@code null}
     */
    public AttributeSet attributes() {
        return VerifiedIssuanceCandidate.snapshotAttributes(attributes);
    }

    /**
     * Returns the subject bound to the possession proof.
     *
     * @return exact subject, never {@code null}
     */
    public SubjectRef subjectRef() {
        return subjectRef;
    }

    /**
     * Returns the managed key reference that completed the challenge.
     *
     * @return proven managed key reference, never {@code null}
     */
    public KeyRef subjectKeyRef() {
        return subjectKeyRef;
    }

    /**
     * Returns a defensive copy of the exact public key bound to the proof.
     *
     * @return DER-encoded public key, never {@code null}
     */
    public EncodedObject exactPublicKey() {
        return new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
    }
}
