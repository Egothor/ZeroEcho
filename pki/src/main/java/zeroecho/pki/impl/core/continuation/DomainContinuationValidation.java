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
package zeroecho.pki.impl.core.continuation;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.credential.CredentialLineage;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Central fail-closed validation for recovered durable domain continuations. */
public final class DomainContinuationValidation { // NOPMD CyclomaticComplexity - One persisted command grammar validates correlated domain continuations; individual methods remain checked.
    private static final int MAXIMUM_TOTAL_BYTES = 2 * 1_048_576;
    private static final String CREATE_ROOT = "CREATE_ROOT";
    private static final String ROLLOVER_ROOT = "ROLLOVER_ROOT";

    private DomainContinuationValidation() { }

    /**
     * Validates one decoded continuation against its authoritative metadata key.
     *
     * @param expectedOperationId operation identity encoded by the metadata key
     * @param record decoded record
     * @param encodedBytes total persisted record size
     * @return the exact validated record
     */
    public static DomainContinuationStore.Record validate(PkiId expectedOperationId,
            DomainContinuationStore.Record record, int encodedBytes) {
        Objects.requireNonNull(expectedOperationId, "expectedOperationId");
        Objects.requireNonNull(record, "record");
        if (!expectedOperationId.equals(record.operationId())
                || encodedBytes <= 0 || encodedBytes > MAXIMUM_TOTAL_BYTES
                || !MessageDigest.isEqual(record.commandCommitment().getBytes(StandardCharsets.US_ASCII),
                        DomainContinuationTemplate.commitment(record.command()).getBytes(StandardCharsets.US_ASCII))) {
            throw new IllegalStateException("Domain continuation identity or commitment is invalid");
        }
        DomainCommandEncoding.Decoded command = validateCanonical(record.kind(), record.command());
        if (record.kind() == DomainContinuationStore.Kind.KEY_PROOF) { validateProofRecord(record, command); }
        if (FullCrlSigningCommand.supports(command.operation())) {
            if (record.state() == DomainContinuationStore.State.SIGNING
                    || record.state() == DomainContinuationStore.State.PUBLISHING) {
                FullCrlSigningCommand.requireTbs(command, record.signingContent().orElseThrow());
            } else if (record.state() == DomainContinuationStore.State.COMPLETED) {
                FullCrlSigningCommand.resultId(record.result().orElseThrow());
            }
        }
        if (IntermediateSigningCommand.supports(command.operation())
                && (record.state() == DomainContinuationStore.State.SIGNING
                        || record.state() == DomainContinuationStore.State.PUBLISHING)) {
            IntermediateSigningCommand.requireCandidate(command, record.signingContent().orElseThrow());
        }
        return record;
    }

    /**
     * Validates an internal preparation template with the same canonical schema
     * rules used for durable continuations. This validates representation and
     * structure; domain preparation remains responsible for PKI policy checks.
     *
     * @param template immutable domain command template
     * @return validated decoded canonical command
     */
    public static DomainCommandEncoding.Decoded validate(DomainContinuationTemplate template) {
        Objects.requireNonNull(template, "template");
        return validateCanonical(template.kind(), template.command());
    }

    private static DomainCommandEncoding.Decoded validateCanonical(DomainContinuationStore.Kind kind,
            EncodedObject command) {
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(command);
        DomainContinuationTemplate canonical = DomainContinuationTemplate.create(kind,
                DomainCommandEncoding.template(kind, decoded.operation(),
                        decoded.fields().toArray(String[]::new)).command());
        if (!MessageDigest.isEqual(command.bytes(), canonical.command().bytes())) {
            throw new IllegalStateException("Domain continuation command is noncanonical");
        }
        validateCommand(kind, decoded);
        return decoded;
    }

    /* default */ static boolean isPublishing(DomainContinuationStore store, PkiId operationId) {
        return store.getDomainContinuation(operationId)
                .filter(domain -> domain.state() == DomainContinuationStore.State.PUBLISHING)
                .isPresent();
    }

    private static void validateCommand(DomainContinuationStore.Kind kind,
            DomainCommandEncoding.Decoded command) {
        switch (kind) {
            case ISSUANCE -> validateIssuance(command);
            case STATUS -> validateStatus(command);
            case CA -> validateCa(command);
            case KEY_PROOF -> {
                try { ManagedKeyProofCommand.validateComplete(command); }
                catch (IllegalArgumentException invalid) {
                    throw new IllegalStateException("Managed key proof command is invalid", invalid);
                }
            }
        }
    }

    private static void validateIssuance(DomainCommandEncoding.Decoded command) {
        boolean lifecycle = switch (command.operation()) {
            case "ISSUE_END_ENTITY" -> false;
            case "RENEW_END_ENTITY", "REPLACE_END_ENTITY", "REISSUE_END_ENTITY" -> true;
            default -> throw new IllegalStateException("Domain continuation kind and operation differ");
        };
        command.requireFields(lifecycle ? 24 : 23);
        if (lifecycle) {
            pkiId(command, 23);
            String predecessor = command.field(23);
            if (!predecessor.startsWith("x509:")) {
                throw new IllegalStateException("Lifecycle predecessor is not an X.509 credential identity");
            }
            digest(predecessor.substring(5));
            if ("REISSUE_END_ENTITY".equals(command.operation())
                    && (!command.field(15).isEmpty() || !command.field(16).isEmpty())) {
                throw new IllegalStateException("Lifecycle continuation cannot contain an external publication identity");
            }
        }
        pkiId(command, 0);
        pkiId(command, 1);
        pkiId(command, 2);
        digest(command.field(3));
        profile(command, 4);
        new SubjectRef(command.field(7));
        instant(command.field(8));
        instant(command.field(9));
        integer(command.field(10));
        new KeyRef(command.field(11));
        digest(command.field(13));
        digest(command.field(14));
        AttributeSet evidence = DomainAttributeEncoding.decode(command.field(22));
        if (evidence.ids().contains(CredentialLineage.SUPERSEDES_CREDENTIAL_ID)
                || evidence.ids().contains(CredentialLineage.SUPERSESSION_REASON)) {
            throw new IllegalStateException("Issuance execution evidence cannot supply credential lineage");
        }
        validatePublicationIdentity(command);
    }

    private static void validateStatus(DomainCommandEncoding.Decoded command) {
        if (FullCrlSigningCommand.supports(command.operation())) {
            FullCrlSigningCommand.validate(command);
            return;
        }
        if (!"GENERATE_STATUS".equals(command.operation())) {
            throw new IllegalStateException("Domain continuation kind and operation differ");
        }
        StatusObjectType type = StatusObjectType.valueOf(command.field(1));
        if (type == StatusObjectType.OCSP) {
            // OCSP carries the DER-encoded signature AlgorithmIdentifier in field 9 (the tbsResponseData
            // does not embed it), and no CRL-entry content reference in fields 6/7.
            command.requireFields(10);
            pkiId(command, 0);
            new FormatId(command.field(2));
            instant(command.field(3));
            instant(command.field(4));
            new KeyRef(command.field(5));
            DomainAttributeEncoding.decode(command.field(8));
            HexFormat.of().parseHex(command.field(9));
            return;
        }
        command.requireFields(9);
        pkiId(command, 0);
        new FormatId(command.field(2));
        instant(command.field(3));
        instant(command.field(4));
        new KeyRef(command.field(5));
        digest(command.field(7));
        DomainAttributeEncoding.decode(command.field(8));
    }

    private static void validateCa(DomainCommandEncoding.Decoded command) {
        if (CREATE_ROOT.equals(command.operation()) || ROLLOVER_ROOT.equals(command.operation())) {
            // Both operations freeze the authority before signing. Creation derives
            // it from the operation; rollover retains the existing authority.
            command.requireFields(14);
            new FormatId(command.field(0));
            new SubjectRef(command.field(1));
            new KeyRef(command.field(3));
            profile(command, 4);
            instant(command.field(7));
            instant(command.field(8));
            integer(command.field(9));
            pkiId(command, 13);
            return;
        }
        if (!IntermediateSigningCommand.supports(command.operation())) {
            throw new IllegalStateException("Domain continuation kind and operation differ");
        }
        command.requireFields(23);
        new FormatId(command.field(0));
        pkiId(command, 1);
        pkiId(command, 2);
        pkiId(command, 3);
        pkiId(command, 4);
        digest(command.field(5));
        new KeyRef(command.field(6));
        profile(command, 7);
        new SubjectRef(command.field(10));
        instant(command.field(11));
        instant(command.field(12));
        integer(command.field(13));
        new KeyRef(command.field(14));
        digest(command.field(16));
        digest(command.field(17));
        IntermediateSigningCommand.validate(command);
    }

    private static void profile(DomainCommandEncoding.Decoded command, int offset) {
        String id = command.field(offset);
        long version = Long.parseLong(command.field(offset + 1));
        if (!Long.toString(version).equals(command.field(offset + 1))) {
            throw new IllegalStateException("Domain continuation profile version is noncanonical");
        }
        new zeroecho.pki.api.profile.CertificateProfileRef(id, version,
                HexFormat.of().parseHex(digest(command.field(offset + 2))));
    }

    private static PkiId pkiId(DomainCommandEncoding.Decoded command, int index) {
        return new PkiId(command.field(index));
    }

    private static void instant(String value) {
        if (!Instant.parse(value).toString().equals(value)) {
            throw new IllegalStateException("Domain continuation instant is noncanonical");
        }
    }

    private static void integer(String value) {
        if (!new BigInteger(value).toString().equals(value)) {
            throw new IllegalStateException("Domain continuation integer is noncanonical");
        }
    }

    private static String digest(String value) {
        if (!value.matches("[0-9a-f]{64}")) {
            throw new IllegalStateException("Domain continuation digest is noncanonical");
        }
        return value;
    }
    private static void validateProofRecord(DomainContinuationStore.Record record, DomainCommandEncoding.Decoded command) {
        if (record.correlationId().filter(ManagedKeyProofBindings.correlation(record.operationId())::equals).isEmpty()) {
            throw new IllegalStateException("Managed key proof correlation differs");
        }
        if (record.state() == DomainContinuationStore.State.SIGNING || record.state() == DomainContinuationStore.State.PUBLISHING) {
            ManagedKeyProofBindings.requireCandidate(command, record.signingContent().orElseThrow());
        } else if (record.state() == DomainContinuationStore.State.COMPLETED) {
            ManagedKeyProofBindings.requireResult(record);
        }
    }


    private static void validatePublicationIdentity(DomainCommandEncoding.Decoded command) {
        boolean hasPublicationIdentity = !command.field(15).isEmpty();
        if (hasPublicationIdentity != !command.field(16).isEmpty()) {
            throw new IllegalStateException("Domain continuation issuance identity is incomplete");
        }
        if (hasPublicationIdentity) {
            if (command.field(15).length() > 128
                    || !command.field(15).matches("[a-z0-9][a-z0-9._:-]{0,127}")) {
                throw new IllegalStateException("Domain continuation issuance identity is invalid");
            }
            digest(command.field(16));
        }
    }
}
