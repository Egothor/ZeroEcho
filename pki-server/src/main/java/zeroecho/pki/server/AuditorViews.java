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
package zeroecho.pki.server;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.PkiId;

/** Explicit certificate/request/status projection boundary for auditor data views. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.FieldDeclarationsShouldBeAtStartOfClass" })
public final class AuditorViews {
    /**
     * Safe source metadata from which authorized projections are produced.
     *
     * @param objectId exact object identifier
     * @param type resource type
     * @param scope exact security scope
     * @param lifecycleState bounded lifecycle state
     * @param createdAt authoritative creation time
     * @param algorithmId algorithm identity
     * @param bindingId optional representation binding identifier
     * @param commitment immutable object commitment
     * @param subjectPresent whether subject PII exists
     * @param subjectAlternativeNameCount number of subject-alternative names
     * @param fullSubject optional full subject PII
     * @param fullSubjectAlternativeNames full subject-alternative-name PII
     * @param content optional full binary content
     */
    public record Source(PkiId objectId, Permission.ResourceType type, Permission.Scope scope, String lifecycleState,
            Instant createdAt, String algorithmId, Optional<String> bindingId, String commitment,
            boolean subjectPresent, int subjectAlternativeNameCount, Optional<String> fullSubject,
            java.util.List<String> fullSubjectAlternativeNames, Optional<byte[]> content) {
        /** Validates and snapshots finite source data. */
        public Source {
            Objects.requireNonNull(objectId, "objectId");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(scope, "scope");
            Permission.requireBounded(lifecycleState, 128, "lifecycle state");
            Objects.requireNonNull(createdAt, "createdAt");
            Permission.requireBounded(algorithmId, 1024, "algorithm identity");
            bindingId = Objects.requireNonNull(bindingId, "bindingId");
            if (commitment == null || !commitment.matches("[0-9a-f]{64}"))
                throw new IllegalArgumentException("Object commitment is invalid");
            if (subjectAlternativeNameCount < 0) throw new IllegalArgumentException("SAN count is negative");
            fullSubject = Objects.requireNonNull(fullSubject, "fullSubject");
            fullSubjectAlternativeNames = java.util.List.copyOf(
                    Objects.requireNonNull(fullSubjectAlternativeNames, "fullSubjectAlternativeNames"));
            content = Objects.requireNonNull(content, "content").map(byte[]::clone);
        }
    }

    /**
     * Redacted metadata projection containing indicators rather than PII.
     *
     * @param objectId exact object identifier
     * @param type resource type
     * @param scope exact security scope
     * @param lifecycleState bounded lifecycle state
     * @param createdAt authoritative creation time
     * @param algorithmId algorithm identity
     * @param bindingId optional representation binding identifier
     * @param commitment immutable object commitment
     * @param subjectPresent whether subject PII exists
     * @param subjectAlternativeNameCount number of subject-alternative names
     */
    public record Redacted(PkiId objectId, Permission.ResourceType type, Permission.Scope scope,
            String lifecycleState, Instant createdAt, String algorithmId, Optional<String> bindingId,
            String commitment, boolean subjectPresent, int subjectAlternativeNameCount) { }

    /**
     * Full non-PII metadata projection.
     *
     * @param redacted common redacted metadata
     * @param safeMetadata immutable additional non-PII metadata
     */
    public record FullMetadata(Redacted redacted, Map<String, String> safeMetadata) {
        /** Defensively snapshots safe metadata. */
        public FullMetadata {
            Objects.requireNonNull(redacted, "redacted");
            safeMetadata = Map.copyOf(Objects.requireNonNull(safeMetadata, "safeMetadata"));
        }
    }

    /**
     * Full binary content projection; byte content is never redacted in place.
     *
     * @param metadata authorized full metadata
     * @param content complete binary content
     */
    public record FullContent(FullMetadata metadata, byte[] content) {
        /** Defensively snapshots content. */
        public FullContent {
            Objects.requireNonNull(metadata, "metadata");
            content = Objects.requireNonNull(content, "content").clone();
        }
        /**
         * Returns a defensive content copy.
         *
         * @return complete binary content
         */
        @Override public byte[] content() { return content.clone(); }
    }

    /**
     * Explicit PII-enabled projection, separately authorized from content.
     *
     * @param metadata authorized full metadata
     * @param subject optional full subject name
     * @param subjectAlternativeNames full subject-alternative names
     */
    public record Pii(FullMetadata metadata, Optional<String> subject, java.util.List<String> subjectAlternativeNames) {
        /** Defensively snapshots PII data. */
        public Pii {
            Objects.requireNonNull(metadata, "metadata");
            subject = Objects.requireNonNull(subject, "subject");
            subjectAlternativeNames = java.util.List.copyOf(
                    Objects.requireNonNull(subjectAlternativeNames, "subjectAlternativeNames"));
        }
    }

    private final SafeAudit audit;

    /**
     * Creates an auditor-view boundary using an injected clock and audit sink.
     *
     * @param clock authoritative audit clock
     * @param auditSink required safe audit sink
     */
    public AuditorViews(Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.audit = new SafeAudit(clock, auditSink);
    }

    /**
     * Returns a standard redacted view with no full subject, SAN, or DER.
     *
     * @param source validated source projection
     * @return redacted non-PII projection
     */
    public Redacted redacted(Source source) {
        Source exact = Objects.requireNonNull(source, "source");
        return new Redacted(exact.objectId(), exact.type(), exact.scope(), exact.lifecycleState(), exact.createdAt(),
                exact.algorithmId(), exact.bindingId(), exact.commitment(), exact.subjectPresent(),
                exact.subjectAlternativeNameCount());
    }

    /**
     * Returns full non-PII metadata after explicit authorization by the caller.
     *
     * @param source validated source projection
     * @param authorized whether full metadata access is authorized
     * @return authorized full metadata
     */
    public FullMetadata fullMetadata(Source source, boolean authorized) {
        if (!authorized) throw new SecurityException("Auditor view is not authorized");
        return new FullMetadata(redacted(source), Map.of("view", "METADATA_FULL"));
    }

    /**
     * Returns full binary content only with separate content permission.
     *
     * @param source validated source projection
     * @param metadataFullAuthorized whether full metadata access is authorized
     * @param contentAuthorized whether binary-content access is authorized
     * @return authorized full binary-content projection
     */
    public FullContent fullContent(Source source, boolean metadataFullAuthorized, boolean contentAuthorized) {
        if (!contentAuthorized || source.content().isEmpty()) throw new SecurityException("Content view is unavailable");
        return new FullContent(fullMetadata(source, metadataFullAuthorized), source.content().orElseThrow());
    }

    /**
     * Returns PII only with explicit reason-bound authorization and records access safely.
     *
     * @param source validated source projection
     * @param principal authenticated audit principal
     * @param reasonReference bounded audit reason reference
     * @param metadataFullAuthorized whether full metadata access is authorized
     * @param piiAuthorized whether PII access is separately authorized
     * @return authorized PII projection
     */
    public Pii pii(Source source, SecurityPrincipal principal, String reasonReference,
            boolean metadataFullAuthorized, boolean piiAuthorized) {
        if (!metadataFullAuthorized || !piiAuthorized) throw new SecurityException("PII view is not authorized");
        Permission.requireBounded(reasonReference, 256, "PII reason reference");
        audit.record("PII_VIEW", principal.principalId(), Optional.of(source.objectId()),
                Map.of("reasonReference", reasonReference));
        return new Pii(fullMetadata(source, metadataFullAuthorized), source.fullSubject(),
                source.fullSubjectAlternativeNames());
    }
}
