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
package zeroecho.pki.impl.core.async;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Central fail-closed validation for recovered durable domain continuations. */
public final class DomainContinuationValidation {
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
        DomainCommandEncoding.Decoded decoded = DomainCommandEncoding.decode(record.command());
        DomainContinuationTemplate canonical = DomainContinuationTemplate.create(record.kind(),
                DomainCommandEncoding.template(record.kind(), decoded.operation(),
                        decoded.fields().toArray(String[]::new)).command());
        if (!MessageDigest.isEqual(record.command().bytes(), canonical.command().bytes())) {
            throw new IllegalStateException("Domain continuation command is noncanonical");
        }
        validateCommand(record, decoded);
        return record;
    }

    /* default */ static boolean isPublishing(DomainContinuationStore store, PkiId operationId) {
        return store.getDomainContinuation(operationId)
                .filter(domain -> domain.state() == DomainContinuationStore.State.PUBLISHING)
                .isPresent();
    }

    private static void validateCommand(DomainContinuationStore.Record record,
            DomainCommandEncoding.Decoded command) {
        switch (record.kind()) {
            case ISSUANCE -> validateIssuance(record, command);
            case STATUS -> validateStatus(record, command);
            case CA -> validateCa(record, command);
        }
    }

    private static void validateIssuance(DomainContinuationStore.Record record,
            DomainCommandEncoding.Decoded command) {
        if (!"ISSUE_END_ENTITY".equals(command.operation())) {
            throw new IllegalStateException("Domain continuation kind and operation differ");
        }
        command.requireFields(23);
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
        DomainAttributeEncoding.decode(command.field(22));
        boolean correlated = !command.field(15).isEmpty();
        if (correlated != !command.field(16).isEmpty()
                || correlated != record.correlationId().isPresent()
                || correlated && record.correlationId().filter(command.field(15)::equals).isEmpty()) {
            throw new IllegalStateException("Domain continuation issuance correlation differs");
        }
        if (correlated) {
            digest(command.field(16));
        }
    }

    private static void validateStatus(DomainContinuationStore.Record record,
            DomainCommandEncoding.Decoded command) {
        if (!"GENERATE_STATUS".equals(command.operation()) || record.correlationId().isPresent()) {
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

    private static void validateCa(DomainContinuationStore.Record record,
            DomainCommandEncoding.Decoded command) {
        if (record.correlationId().isPresent()) {
            throw new IllegalStateException("CA continuation cannot carry a correlation identity");
        }
        if (CREATE_ROOT.equals(command.operation()) || ROLLOVER_ROOT.equals(command.operation())) {
            // ROLLOVER_ROOT reuses the CREATE_ROOT fields (0-12) and adds the frozen existing
            // authority id in field 13, so a new generation attaches to the existing CA.
            command.requireFields(ROLLOVER_ROOT.equals(command.operation()) ? 14 : 13);
            new FormatId(command.field(0));
            new SubjectRef(command.field(1));
            new KeyRef(command.field(3));
            profile(command, 4);
            instant(command.field(7));
            instant(command.field(8));
            integer(command.field(9));
            if (ROLLOVER_ROOT.equals(command.operation())) {
                pkiId(command, 13);
            }
            return;
        }
        if (!"CREATE_INTERMEDIATE".equals(command.operation())
                && !"ISSUE_INTERMEDIATE".equals(command.operation())
                && !"ROLLOVER_INTERMEDIATE".equals(command.operation())) {
            throw new IllegalStateException("Domain continuation kind and operation differ");
        }
        command.requireFields(21);
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
}
