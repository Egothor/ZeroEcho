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
package zeroecho.pki.application;

import java.util.Objects;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;

/**
 * Closed set of typed synchronous PKI operations available to transports.
 *
 * <p>Names are stable external semantic identities. Implementations dispatch by
 * explicit type and never by reflection or Java class name.</p>
 */
public sealed interface PkiOperation permits PkiOperation.ValidateConfiguration, PkiOperation.ValidateProfile,
        PkiOperation.ListAlgorithmBindings, PkiOperation.InspectAlgorithmBinding,
        PkiOperation.ValidateAlgorithmBindings,
        PkiOperation.RegisterProfile, PkiOperation.InspectProfile, PkiOperation.ListProfileVersions,
        PkiOperation.ActivateProfile, PkiOperation.InspectAuthority, PkiOperation.ListAuthorities,
        PkiOperation.CreateAuthority, PkiOperation.TransitionAuthority, PkiOperation.InspectRequest,
        PkiOperation.ImportRequest, PkiOperation.VerifyRequest, PkiOperation.InspectCredential,
        PkiOperation.IssueCredential, PkiOperation.RevokeCredential,
        PkiOperation.InspectRevocation, PkiOperation.ReadRevocationHistory, PkiOperation.SnapshotRevocations,
        PkiOperation.InspectStatus, PkiOperation.ListStatus, PkiOperation.GenerateStatus,
        PkiOperation.InspectPublication, PkiOperation.ListPublications, PkiOperation.RegisterPublication,
        PkiOperation.ProcessPublication, PkiOperation.RetryPublication, PkiOperation.ReconcilePublication {

    /** Maximum finite entries returned by one presentation operation. */
    int MAXIMUM_RESULT_ENTRIES = 1_000;

    /** @return stable semantic operation name */
    String name();

    /** Lists active X.509 algorithm bindings with optional finite filters. */
    record ListAlgorithmBindings(java.util.Optional<String> origin, java.util.Optional<String> role, int limit)
            implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "algorithm.binding.list";

        /** Validates immutable filters and the presentation limit. */
        public ListAlgorithmBindings {
            origin = Objects.requireNonNull(origin, "origin").map(ListAlgorithmBindings::requireText);
            role = Objects.requireNonNull(role, "role").map(ListAlgorithmBindings::requireText);
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }

        private static String requireText(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("Binding filter must not be blank");
            }
            return value;
        }
    }

    /** Inspects one active X.509 algorithm binding by stable identifier. */
    record InspectAlgorithmBinding(String bindingId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "algorithm.binding.inspect";

        /** Validates the stable identifier. */
        public InspectAlgorithmBinding {
            if (bindingId == null || bindingId.isBlank()) {
                throw new IllegalArgumentException("bindingId must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Validates the immutable active registry and optionally one exact binding. */
    record ValidateAlgorithmBindings(java.util.Optional<String> bindingId,
            java.util.Optional<String> expectedCommitment) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "algorithm.binding.validate";

        /** Validates paired optional fields. */
        public ValidateAlgorithmBindings {
            bindingId = Objects.requireNonNull(bindingId, "bindingId");
            expectedCommitment = Objects.requireNonNull(expectedCommitment, "expectedCommitment");
            if (bindingId.isPresent() != expectedCommitment.isPresent()) {
                throw new IllegalArgumentException("Binding validation fields must be supplied together");
            }
            bindingId.ifPresent(value -> {
                if (value.isBlank()) {
                    throw new IllegalArgumentException("bindingId must not be blank");
                }
            });
            expectedCommitment.ifPresent(value -> {
                if (!value.matches("[0-9a-f]{64}|[^\\s]{1,512}")) {
                    throw new IllegalArgumentException("Binding commitment is invalid");
                }
            });
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Validates the already-open session configuration. */
    record ValidateConfiguration() implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "configuration.validate";

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Validates one bounded certificate-profile JSON document without persisting it. */
    record ValidateProfile(byte[] document) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.validate";

        /** Defensively snapshots the document. */
        public ValidateProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }

        @Override
        public byte[] document() {
            return document.clone();
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Imports one bounded validated certificate-profile document. */
    record RegisterProfile(byte[] document) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.register";

        /** Defensively snapshots the document. */
        public RegisterProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }

        @Override
        public byte[] document() {
            return document.clone();
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads one exact imported certificate-profile version. */
    record InspectProfile(String profileId, long profileVersion) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.inspect";

        /** Validates the exact profile identity. */
        public InspectProfile {
            if (profileId == null || profileId.isBlank() || profileVersion <= 0) {
                throw new IllegalArgumentException("profile identity is invalid");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Lists the finite imported versions of one logical profile. */
    record ListProfileVersions(String profileId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.list";

        /** Validates the logical profile identity. */
        public ListProfileVersions {
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException("profileId must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Activates one already imported certificate-profile version. */
    record ActivateProfile(String profileId, long profileVersion) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.activate";

        /** Validates the exact profile identity. */
        public ActivateProfile {
            if (profileId == null || profileId.isBlank() || profileVersion <= 0) {
                throw new IllegalArgumentException("profile identity is invalid");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe metadata for one committed certificate authority. */
    record InspectAuthority(PkiId caId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.inspect";

        /** Validates the authority identity. */
        public InspectAuthority {
            Objects.requireNonNull(caId, "caId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Lists committed certificate authorities with a finite presentation limit. */
    record ListAuthorities(int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.list";

        /** Validates the presentation limit. */
        public ListAuthorities {
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Creates one root certificate authority using an existing managed key reference. */
    record CreateAuthority(FormatId formatId, SubjectRef subjectRef, String profileId, KeyRef keyRef)
            implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.create";

        /** Validates the closed authority-creation input. */
        public CreateAuthority {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(subjectRef, "subjectRef");
            Objects.requireNonNull(keyRef, "keyRef");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException("profileId must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Applies one explicit lifecycle transition to an existing authority. */
    record TransitionAuthority(PkiId caId, CaState state, String reason) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.transition";

        /** Validates the lifecycle-transition input. */
        public TransitionAuthority {
            Objects.requireNonNull(caId, "caId");
            Objects.requireNonNull(state, "state");
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("reason must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe metadata for one stored certification request. */
    record InspectRequest(PkiId requestId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "request.inspect";

        /** Validates the request identity. */
        public InspectRequest {
            Objects.requireNonNull(requestId, "requestId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Strictly parses and durably imports one certification request. */
    record ImportRequest(FormatId formatId, EncodedObject encoded) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "request.import";

        /** Validates the finite request input. */
        public ImportRequest {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(encoded, "encoded");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Verifies proof of possession for one stored request. */
    record VerifyRequest(PkiId requestId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "request.verify";

        /** Validates the request identity. */
        public VerifyRequest {
            Objects.requireNonNull(requestId, "requestId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe metadata for one committed credential. */
    record InspectCredential(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.inspect";

        /** Validates the identifier. */
        public InspectCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Issues one end-entity credential from an already imported request. */
    record IssueCredential(PkiId issuerCaId, PkiId requestId, String profileId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.issue";

        /** Validates the issuance input. */
        public IssueCredential {
            Objects.requireNonNull(issuerCaId, "issuerCaId");
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException("profileId must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Permanently revokes one committed credential. */
    record RevokeCredential(PkiId credentialId, RevocationReason reason) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.revoke";

        /** Validates permanent-revocation inputs. */
        public RevokeCredential {
            Objects.requireNonNull(credentialId, "credentialId");
            Objects.requireNonNull(reason, "reason");
            if (reason == RevocationReason.CERTIFICATE_HOLD || reason == RevocationReason.REMOVE_FROM_CRL) {
                throw new IllegalArgumentException("reason must be permanent");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads a bounded prefix from one closeable authoritative history cursor. */
    record ReadRevocationHistory(PkiId credentialId, int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.history";
        /** Maximum finite result entries for one invocation. */
        public static final int MAXIMUM_RESULT_ENTRIES = 1_000;

        /** Validates the identifier and finite result limit. */
        public ReadRevocationHistory {
            Objects.requireNonNull(credentialId, "credentialId");
            if (limit < 1 || limit > MAXIMUM_RESULT_ENTRIES) {
                throw new IllegalArgumentException("limit must be between 1 and 1000");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads the validated current revocation state for one credential. */
    record InspectRevocation(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.inspect";

        /** Validates the credential identity. */
        public InspectRevocation {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads a bounded page from one immutable current-revocation snapshot. */
    record SnapshotRevocations(int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.snapshot";

        /** Validates the presentation limit. */
        public SnapshotRevocations {
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe metadata for one committed status object. */
    record InspectStatus(PkiId statusObjectId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "status.inspect";

        /** Validates the status-object identity. */
        public InspectStatus {
            Objects.requireNonNull(statusObjectId, "statusObjectId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Lists status objects for one issuer with a finite presentation limit. */
    record ListStatus(PkiId issuerCaId, int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "inventory.status";

        /** Validates the issuer identity and presentation limit. */
        public ListStatus {
            Objects.requireNonNull(issuerCaId, "issuerCaId");
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Generates one signed status object from a stable revocation view. */
    record GenerateStatus(PkiId issuerCaId, StatusObjectType type, FormatId formatId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "status.generate";

        /** Validates the generation input. */
        public GenerateStatus {
            Objects.requireNonNull(issuerCaId, "issuerCaId");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(formatId, "formatId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reads safe durable state for one publication operation. */
    record InspectPublication(PkiId publicationId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.inspect";

        /** Validates the identifier. */
        public InspectPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Lists publication records using a bounded-memory cursor and finite result page. */
    record ListPublications(int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.list";

        /** Validates the presentation limit. */
        public ListPublications {
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Registers post-commit publication of one authoritative source object. */
    record RegisterPublication(PkiId publicationId, PublicationSourceType sourceType, PkiId sourceId,
            PublicationTarget target) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.register";

        /** Validates the immutable publication registration fields. */
        public RegisterPublication {
            Objects.requireNonNull(publicationId, "publicationId");
            Objects.requireNonNull(sourceType, "sourceType");
            Objects.requireNonNull(sourceId, "sourceId");
            Objects.requireNonNull(target, "target");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Processes one explicitly selected pending publication operation. */
    record ProcessPublication(PkiId publicationId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.process";

        /** Validates the publication identity. */
        public ProcessPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Explicitly retries one eligible publication operation. */
    record RetryPublication(PkiId publicationId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.retry";

        /** Validates the publication identity. */
        public RetryPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /** Reconciles one publication operation whose external outcome is unknown. */
    record ReconcilePublication(PkiId publicationId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "publication.reconcile";

        /** Validates the publication identity. */
        public ReconcilePublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    private static void requireLimit(int limit) {
        if (limit < 1 || limit > MAXIMUM_RESULT_ENTRIES) {
            throw new IllegalArgumentException("limit must be between 1 and 1000");
        }
    }
}
