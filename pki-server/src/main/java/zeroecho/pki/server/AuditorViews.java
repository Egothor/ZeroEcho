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
    /** Safe source metadata from which authorized projections are produced. */
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

    /** Redacted metadata projection containing indicators rather than PII. */
    public record Redacted(PkiId objectId, Permission.ResourceType type, Permission.Scope scope,
            String lifecycleState, Instant createdAt, String algorithmId, Optional<String> bindingId,
            String commitment, boolean subjectPresent, int subjectAlternativeNameCount) { }

    /** Full non-PII metadata projection. */
    public record FullMetadata(Redacted redacted, Map<String, String> safeMetadata) {
        /** Defensively snapshots safe metadata. */
        public FullMetadata {
            Objects.requireNonNull(redacted, "redacted");
            safeMetadata = Map.copyOf(Objects.requireNonNull(safeMetadata, "safeMetadata"));
        }
    }

    /** Full binary content projection; byte content is never redacted in place. */
    public record FullContent(FullMetadata metadata, byte[] content) {
        /** Defensively snapshots content. */
        public FullContent {
            Objects.requireNonNull(metadata, "metadata");
            content = Objects.requireNonNull(content, "content").clone();
        }
        /** Returns a defensive content copy. */ @Override public byte[] content() { return content.clone(); }
    }

    /** Explicit PII-enabled projection, separately authorized from content. */
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

    /** Creates an auditor-view boundary using an injected clock and audit sink. */
    public AuditorViews(Clock clock, zeroecho.pki.spi.audit.AuditSink auditSink) {
        this.audit = new SafeAudit(clock, auditSink);
    }

    /** Returns a standard redacted view with no full subject, SAN, or DER. */
    public Redacted redacted(Source source) {
        Source exact = Objects.requireNonNull(source, "source");
        return new Redacted(exact.objectId(), exact.type(), exact.scope(), exact.lifecycleState(), exact.createdAt(),
                exact.algorithmId(), exact.bindingId(), exact.commitment(), exact.subjectPresent(),
                exact.subjectAlternativeNameCount());
    }

    /** Returns full non-PII metadata after explicit authorization by the caller. */
    public FullMetadata fullMetadata(Source source, boolean authorized) {
        if (!authorized) throw new SecurityException("Auditor view is not authorized");
        return new FullMetadata(redacted(source), Map.of("view", "METADATA_FULL"));
    }

    /** Returns full binary content only with separate content permission. */
    public FullContent fullContent(Source source, boolean metadataFullAuthorized, boolean contentAuthorized) {
        if (!contentAuthorized || source.content().isEmpty()) throw new SecurityException("Content view is unavailable");
        return new FullContent(fullMetadata(source, metadataFullAuthorized), source.content().orElseThrow());
    }

    /** Returns PII only with explicit reason-bound authorization and records access safely. */
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
