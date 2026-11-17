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
package zeroecho.pki.server.http;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiSigningOperation;

/**
 * Decodes the supported semantic-signing operations from HTTP request fields.
 */
final class HttpSigningOperations {
    private static final String TEXT_FORMATID = "formatId";
    private static final String TEXT_PROFILEID = "profileId";
    private static final String TEXT_ISSUERCAID = "issuerCaId";
    private static final String TEXT_REQUESTID = "requestId";
    private static final String TEXT_CREDENTIALID = "credentialId";
    private static final String TEXT_CAID = "caId";
    private static final String TEXT_EXPECTEDHEAD = "expectedHead";
    private static final String TEXT_TYPE = "type";
    private HttpSigningOperations() { }
    /* default */ static PkiSigningOperation decode(String id, HttpOperationCodec.Fields fields) {
        return switch (id) {
            case PkiSigningOperation.CreateAuthority.NAME -> {
                fields.allowed(Set.of(TEXT_FORMATID, "subjectRef", TEXT_PROFILEID, "keyRef", "signatureAlgorithmId"));
                yield new PkiSigningOperation.CreateAuthority(new FormatId(fields.text(TEXT_FORMATID)),
                        new SubjectRef(fields.text("subjectRef")), fields.text(TEXT_PROFILEID),
                        new KeyRef(fields.text("keyRef")),fields.optionalText("signatureAlgorithmId"));
            }
            case PkiSigningOperation.IssueOcspResponderCertificate.NAME -> {
                zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest input = zeroecho.pki.server.OcspProvisioningProjection.decode(fields.values());
                fields.consumeAll();
                yield new PkiSigningOperation.IssueOcspResponderCertificate(input);
            }
            case PkiSigningOperation.IssueCredential.NAME -> {
                fields.exact(TEXT_ISSUERCAID, TEXT_REQUESTID, TEXT_PROFILEID);
                yield new PkiSigningOperation.IssueCredential(fields.pkiId(TEXT_ISSUERCAID), fields.pkiId(TEXT_REQUESTID),
                        fields.text(TEXT_PROFILEID));
            }
            case PkiSigningOperation.RenewCredential.NAME -> {
                fields.exact(TEXT_CREDENTIALID);
                yield new PkiSigningOperation.RenewCredential(fields.pkiId(TEXT_CREDENTIALID));
            }
            case PkiSigningOperation.ReplaceCredential.NAME -> {
                fields.exact("existingCredentialId", TEXT_REQUESTID, TEXT_PROFILEID);
                yield new PkiSigningOperation.ReplaceCredential(fields.pkiId("existingCredentialId"),
                        fields.pkiId(TEXT_REQUESTID), fields.text(TEXT_PROFILEID));
            }
            case PkiSigningOperation.ReissueCredential.NAME -> {
                fields.exact(TEXT_CREDENTIALID);
                yield new PkiSigningOperation.ReissueCredential(fields.pkiId(TEXT_CREDENTIALID));
            }
            case PkiSigningOperation.RolloverCaCertificate.NAME -> {
                fields.allowed(Set.of(TEXT_CAID, TEXT_ISSUERCAID, TEXT_EXPECTEDHEAD));
                yield new PkiSigningOperation.RolloverCaCertificate(fields.pkiId(TEXT_CAID),
                        fields.optionalText(TEXT_ISSUERCAID).map(PkiId::new),fields.head());
            }
            case PkiSigningOperation.RotateCaKey.NAME -> {
                fields.allowed(Set.of(TEXT_CAID, "newKeyRef", TEXT_ISSUERCAID, "newAlternativeKeyRef", "primarySignatureAlgorithmId", "alternativeSignatureAlgorithmId", TEXT_EXPECTEDHEAD));
                yield new PkiSigningOperation.RotateCaKey(fields.pkiId(TEXT_CAID),
                        fields.selection(),fields.optionalText(TEXT_ISSUERCAID).map(PkiId::new),fields.head());
            }
            case PkiSigningOperation.GenerateStatus.NAME -> {
                fields.exact(TEXT_ISSUERCAID, TEXT_TYPE, TEXT_FORMATID);
                yield new PkiSigningOperation.GenerateStatus(fields.pkiId(TEXT_ISSUERCAID),
                        StatusObjectType.valueOf(fields.text(TEXT_TYPE)), new FormatId(fields.text(TEXT_FORMATID)));
            }
            case PkiSigningOperation.CreateIntermediate.NAME -> {
                fields.allowed(Set.of(TEXT_FORMATID, TEXT_ISSUERCAID, "subjectRef", TEXT_PROFILEID, "keyRef", "signatureAlgorithmId"));
                yield new PkiSigningOperation.CreateIntermediate(new FormatId(fields.text(TEXT_FORMATID)),
                        fields.pkiId(TEXT_ISSUERCAID), new SubjectRef(fields.text("subjectRef")),
                        fields.text(TEXT_PROFILEID), fields.optionalText("keyRef").map(KeyRef::new),fields.optionalText("signatureAlgorithmId"));
            }
            case PkiSigningOperation.IssueIntermediateCertificate.NAME -> {
                fields.allowed(Set.of(TEXT_FORMATID, TEXT_ISSUERCAID, "subjectCaId", TEXT_PROFILEID, "notBefore", "notAfter", TEXT_EXPECTEDHEAD));
                yield new PkiSigningOperation.IssueIntermediateCertificate(new FormatId(fields.text(TEXT_FORMATID)),
                        fields.pkiId(TEXT_ISSUERCAID), fields.pkiId("subjectCaId"), fields.text(TEXT_PROFILEID),
                        requestedValidity(fields),fields.head());
            }
            default -> throw new IllegalArgumentException("Signing operation is unsupported");
        };
    }
    private static Optional<zeroecho.pki.api.Validity> requestedValidity(HttpOperationCodec.Fields fields) {
        boolean hasBefore = fields.contains("notBefore");
        boolean hasAfter = fields.contains("notAfter");
        if (hasBefore != hasAfter) {
            throw new IllegalArgumentException("notBefore and notAfter must be supplied together");
        }
        if (!hasBefore) {
            return Optional.empty();
        }
        return Optional.of(new zeroecho.pki.api.Validity(instant(fields.text("notBefore")),
                instant(fields.text("notAfter"))));
    }
    /* default */ static Instant instant(String value) {
        Instant parsed = Instant.parse(value);
        if (!parsed.toString().equals(value) || parsed.getEpochSecond() < 0L
                || parsed.getEpochSecond() > 253_402_300_799L) {
            throw new IllegalArgumentException("Instant is not canonical or supported");
        }
        return parsed;
    }
}
