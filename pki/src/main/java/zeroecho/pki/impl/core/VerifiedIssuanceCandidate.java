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
import java.util.ArrayList;
import java.util.List;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;

/**
 * Immutable internal authority for a request that passed the issuance PoP gate.
 *
 * <p>
 * Mutable byte-array components are copied on construction and whenever a
 * request snapshot is exposed. This prevents caller mutation of an earlier
 * diagnostic parse result from changing the privileged backend command.
 * </p>
 */
@SuppressWarnings("PMD.DataClass")
public final class VerifiedIssuanceCandidate {

    private final ParsedCertificationRequest request;
    private final PkiId fingerprint;
    private final EncodedObject exactPublicKey;
    private final ProofOfPossessionStatus proofKind;
    private final PkiId issuerCaId;
    private final String profileId;
    private final Optional<Validity> validityOverride;

    /* default */ VerifiedIssuanceCandidate(ParsedCertificationRequest request, PkiId fingerprint,
            EncodedObject exactPublicKey, ProofOfPossessionStatus proofKind, IssueEndEntityCommand command) {
        this.request = snapshot(Objects.requireNonNull(request, "request"));
        this.fingerprint = Objects.requireNonNull(fingerprint, "fingerprint");
        this.exactPublicKey = copy(Objects.requireNonNull(exactPublicKey, "exactPublicKey"));
        this.proofKind = Objects.requireNonNull(proofKind, "proofKind");
        IssueEndEntityCommand checkedCommand = Objects.requireNonNull(command, "command");
        this.issuerCaId = checkedCommand.issuerCaId();
        this.profileId = checkedCommand.profileId();
        this.validityOverride = checkedCommand.validityOverride();
    }

    /**
     * Returns an immutable snapshot of the cryptographically verified request.
     *
     * @return verified request snapshot, never {@code null}
     */
    public ParsedCertificationRequest request() {
        return snapshot(request);
    }

    /**
     * Returns the identity bound to the verified request.
     *
     * @return verified request identity, never {@code null}
     */
    public PkiId fingerprint() {
        return fingerprint;
    }

    /**
     * Returns a defensive copy of the exact verified subject public key.
     *
     * @return DER-encoded verified subject public key, never {@code null}
     */
    public EncodedObject exactPublicKey() {
        return copy(exactPublicKey);
    }

    /**
     * Returns the proof result that authorized construction.
     *
     * @return {@link ProofOfPossessionStatus#VERIFIED}
     */
    public ProofOfPossessionStatus proofKind() {
        return proofKind;
    }

    /**
     * Returns the store-authoritative issuing CA identifier.
     *
     * @return issuing CA identifier, never {@code null}
     */
    public PkiId issuerCaId() {
        return issuerCaId;
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
     * Returns the optional validated validity override.
     *
     * @return optional validity override, never {@code null}
     */
    public Optional<Validity> validityOverride() {
        return validityOverride;
    }

    /* default */ static ParsedCertificationRequest snapshot(ParsedCertificationRequest source) {
        Objects.requireNonNull(source, "source");
        return new ParsedCertificationRequest(source.requestId(), source.formatId(), source.subjectRef(),
                copy(source.publicKeyInfo()), source.requestedValidity(), source.requestedProfileId(),
                source.subjectRdns(), source.subjectAlternativeNames(), source.subjectAlternativeNamePresent(),
                snapshotCsrAttribute(source.attributes()));
    }

    private static EncodedObject copy(EncodedObject source) {
        return new EncodedObject(source.encoding(), source.bytes().clone());
    }

    private static AttributeSet snapshotCsrAttribute(AttributeSet source) {
        AttributeValue value = source.get(BcX509Attributes.CSR_DER)
                .orElseThrow(() -> new IllegalArgumentException("Missing canonical CSR attribute"));
        if (!(value instanceof AttributeValue.BytesValue bytesValue)) {
            throw new IllegalArgumentException("Canonical CSR attribute has the wrong type");
        }
        return new SimpleAttributeSet(List.of(new SimpleAttributeSet.Entry(BcX509Attributes.CSR_DER,
                List.of(new AttributeValue.BytesValue(bytesValue.value())))));
    }

    /* default */ static AttributeSet snapshotAttributes(AttributeSet source) {
        List<SimpleAttributeSet.Entry> entries = new ArrayList<>();
        for (AttributeId id : source.ids()) {
            List<AttributeValue> values = source.getAll(id).stream().map(VerifiedIssuanceCandidate::copyValue).toList();
            entries.add(new SimpleAttributeSet.Entry(id, values));
        }
        return new SimpleAttributeSet(entries);
    }

    private static AttributeValue copyValue(AttributeValue value) {
        if (value instanceof AttributeValue.BytesValue bytesValue) {
            return new AttributeValue.BytesValue(bytesValue.value());
        }
        return value;
    }
}
