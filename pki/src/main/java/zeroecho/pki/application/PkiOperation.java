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
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
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
// This closed command model intentionally exposes one record per supported operation.
@SuppressWarnings("PMD.ExcessivePublicCount")
public sealed interface PkiOperation permits PkiOperation.ValidateConfiguration, PkiOperation.ValidateProfile,
        PkiOperation.ListAlgorithmBindings, PkiOperation.InspectAlgorithmBinding,
        PkiOperation.ValidateAlgorithmBindings,
        PkiOperation.RegisterProfile, PkiOperation.InspectProfile, PkiOperation.ListProfileVersions,
        PkiOperation.ActivateProfile, PkiOperation.InspectAuthority, PkiOperation.ListAuthorities,
        PkiOperation.CreateAuthority, PkiOperation.TransitionAuthority, PkiOperation.InspectRequest,
        PkiOperation.ImportRequest, PkiOperation.VerifyRequest, PkiOperation.InspectCredential,
        PkiOperation.ListPendingCredentialConfirmations, PkiOperation.IssueCredentialConfirmationChallenge,
        PkiOperation.CompleteCredentialConfirmationProof, PkiOperation.RevokePendingCredentialConfirmation,
        PkiOperation.IssueCredential, PkiOperation.RenewCredential, PkiOperation.ReplaceCredential,
        PkiOperation.ReissueCredential, PkiOperation.RolloverCaCertificate, PkiOperation.RotateCaKey,
        PkiOperation.RevokeCredential,
        PkiOperation.InspectRevocation, PkiOperation.ReadRevocationHistory, PkiOperation.SnapshotRevocations,
        PkiOperation.InspectStatus, PkiOperation.ListStatus, PkiOperation.GenerateStatus,
        PkiOperation.InspectPublication, PkiOperation.ListPublications, PkiOperation.RegisterPublication,
        PkiOperation.ProcessPublication, PkiOperation.RetryPublication, PkiOperation.ReconcilePublication,
        PkiOperation.CreateIntermediate, PkiOperation.IssueIntermediateCertificate,
        PkiOperation.InspectIssuerGeneration, PkiOperation.InspectIssuerChainPath,
        PkiOperation.ListIssuerChainPaths, PkiOperation.SelectIssuancePath,
        PkiOperation.RegisterIssuerChainPath {

    /** Maximum finite entries returned by one presentation operation. */
    int MAXIMUM_RESULT_ENTRIES = 1_000;

    /** Returns the stable validation message shared by profile operations. */
    private static String profileIdRequiredMessage() {
        return "profileId must not be blank";
    }

    /** Returns the stable authority-identifier argument name. */
    private static String authorityIdParameter() {
        return "caId";
    }

    /** Returns the stable issuer-authority argument name. */
    private static String issuerAuthorityIdParameter() {
        return "issuerCaId";
    }

    /**
     * Returns the stable semantic name used by transport dispatch and audit records.
     *
     * @return stable semantic operation name
     */
    String name();

    /**
     * Lists active X.509 algorithm bindings with optional finite filters.
     *
     * @param origin optional nonblank binding-origin filter
     * @param role optional nonblank binding-role filter
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
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

    /**
     * Inspects one active X.509 algorithm binding by stable identifier.
     *
     * @param bindingId nonblank stable algorithm-binding identifier
     */
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

    /**
     * Validates the immutable active registry and optionally one exact binding.
     *
     * @param bindingId optional nonblank binding identifier to validate
     * @param expectedCommitment expected binding commitment; present exactly when {@code bindingId} is present
     */
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

    /**
     * Validates one bounded certificate-profile JSON document without persisting it.
     *
     * @param document bounded certificate-profile JSON bytes; the operation keeps a defensive copy
     */
    record ValidateProfile(byte[] document) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.validate";

        /** Defensively snapshots the document. */
        public ValidateProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }

        /**
         * Returns the profile document without exposing the operation's internal array.
         *
         * @return a defensive copy of the certificate-profile JSON bytes
         */
        @Override
        public byte[] document() {
            return document.clone();
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Imports one bounded validated certificate-profile document.
     *
     * @param document bounded certificate-profile JSON bytes; the operation keeps a defensive copy
     */
    record RegisterProfile(byte[] document) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.register";

        /** Defensively snapshots the document. */
        public RegisterProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }

        /**
         * Returns the profile document without exposing the operation's internal array.
         *
         * @return a defensive copy of the certificate-profile JSON bytes
         */
        @Override
        public byte[] document() {
            return document.clone();
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads one exact imported certificate-profile version.
     *
     * @param profileId nonblank stable certificate-profile identifier
     * @param profileVersion positive imported profile version
     */
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

    /**
     * Lists the finite imported versions of one logical profile.
     *
     * @param profileId nonblank stable certificate-profile identifier
     */
    record ListProfileVersions(String profileId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "profile.list";

        /** Validates the logical profile identity. */
        public ListProfileVersions {
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Activates one already imported certificate-profile version.
     *
     * @param profileId nonblank stable certificate-profile identifier
     * @param profileVersion positive imported profile version
     */
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

    /**
     * Reads safe metadata for one committed certificate authority.
     *
     * @param caId exact certificate-authority identifier
     */
    record InspectAuthority(PkiId caId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.inspect";

        /** Validates the authority identity. */
        public InspectAuthority {
            Objects.requireNonNull(caId, authorityIdParameter());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists committed certificate authorities with a finite presentation limit.
     *
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
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

    /**
     * Creates one root certificate authority using an existing managed key reference.
     *
     * @param formatId encoding format for the created or imported object
     * @param subjectRef subject name for the new authority
     * @param profileId nonblank stable certificate-profile identifier
     * @param keyRef managed key reference used by the authority
     */
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
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Applies one explicit lifecycle transition to an existing authority.
     *
     * @param caId exact certificate-authority identifier
     * @param state target authority lifecycle state
     * @param reason nonblank auditable reason for the transition
     */
    record TransitionAuthority(PkiId caId, CaState state, String reason) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.transition";

        /** Validates the lifecycle-transition input. */
        public TransitionAuthority {
            Objects.requireNonNull(caId, authorityIdParameter());
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

    /**
     * Reads safe metadata for one stored certification request.
     *
     * @param requestId exact imported certification-request identifier
     */
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

    /**
     * Strictly parses and durably imports one certification request.
     *
     * @param formatId encoding format for the created or imported object
     * @param encoded encoded certification-request object
     */
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

    /**
     * Verifies proof of possession for one stored request.
     *
     * @param requestId exact imported certification-request identifier
     */
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

    /**
     * Reads safe metadata for one committed credential.
     *
     * @param credentialId exact committed credential identifier
     */
    record InspectCredential(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.inspect";

        /** Validates the identifier. */
        public InspectCredential {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists reduced pending credential-confirmation reviews in one authorized scope.
     *
     * @param authorityId exact authorized authority scope
     * @param profileId optional nonblank profile filter
     * @param cutoffInclusive latest challenge expiration included in the query
     * @param afterExclusive optional keyset cursor after which results begin
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
    record ListPendingCredentialConfirmations(PkiId authorityId,
            java.util.Optional<String> profileId, java.time.Instant cutoffInclusive,
            java.util.Optional<zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor> afterExclusive,
            int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.confirmation.pending.list";

        /** Validates the exact bounded keyset query. */
        public ListPendingCredentialConfirmations {
            Objects.requireNonNull(authorityId, "authorityId");
            requireScopeText(authorityId.value(), "authorityId");
            profileId = Objects.requireNonNull(profileId, "profileId");
            profileId.ifPresent(value -> requireScopeText(value, "profileId"));
            Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
            if (cutoffInclusive.getEpochSecond() < 0L
                    || cutoffInclusive.getEpochSecond() > 253_402_300_799L) {
                throw new IllegalArgumentException("cutoffInclusive is outside the supported UTC range");
            }
            afterExclusive = Objects.requireNonNull(afterExclusive, "afterExclusive");
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }

        private static void requireScopeText(String value, String name) {
            Objects.requireNonNull(value, name);
            byte[] encoded = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (value.isBlank() || encoded.length > 256
                    || !value.equals(new String(encoded, java.nio.charset.StandardCharsets.UTF_8))) {
                throw new IllegalArgumentException(name + " is not bounded strict UTF-8");
            }
        }
    }

    /**
     * Issues or replays the current proof challenge for one pending credential confirmation.
     *
     * <p>The external operation accepts only the canonical credential identity. The
     * executor loads the current lifecycle revision and record commitment from
     * authoritative state; suite configuration, nonce, audience, lifetime, certificate
     * material, and provider selection are never caller-controlled.</p>
     *
     * <p>After authorization, challenge construction uses {@code O(D + K + T)}
     * CPU, bounded credential-content I/O, and a constant number of
     * {@code O(log M)} metadata point operations, where {@code D} is certificate
     * DER length (at most 1 MiB), {@code K} is public-key processing, {@code T} is
     * suite presentation work (at most 2048 bytes before Base64url), and {@code M}
     * is the metadata population. Per-request memory is bounded by those finite
     * inputs and no request state is retained. Whole-request cost additionally
     * includes the gateway's configured grant/role scans and audit/transport I/O.</p>
     *
     * @param credentialId exact committed credential identity
     */
    record IssueCredentialConfirmationChallenge(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.confirmation.challenge.issue";

        /** Validates the sole external argument. */
        public IssueCredentialConfirmationChallenge {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Verifies and completes one credential confirmation using existing CAS coordinates.
     *
     * <p>The submission owns a bounded response defensively and redacts it from
     * structural text. Realm, authority, profile, owner, suite, audience, nonce,
     * certificate material, and provider selection are never caller inputs.</p>
     *
     * <p>After authorization, pending verification uses
     * {@code O(D + T + R + V(K))} CPU and a constant number of {@code O(log M)}
     * metadata point operations. Exact terminal replay uses {@code O(R + log M)}
     * without provider invocation, DER loading, or proof verification. Bounds are
     * {@code D <= 1 MiB}, {@code T <= 2 KiB}, and {@code R <= 16 KiB}. Whole-request
     * cost additionally includes configured grant/role scans and audit/transport I/O.</p>
     *
     * @param submission exact proof CAS and bounded response
     */
    record CompleteCredentialConfirmationProof(CredentialConfirmationProofSubmission submission)
            implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.confirmation.proof.complete";

        /** Validates the exact immutable submission. */
        public CompleteCredentialConfirmationProof {
            Objects.requireNonNull(submission, "submission");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Permanently revokes one still-pending non-public credential after its
     * authoritative confirmation-review boundary.
     *
     * <p>The executor re-evaluates eligibility from authoritative state under
     * the credential lock. The permanent PKIX reason is always
     * {@link RevocationReason#UNSPECIFIED}; callers cannot supply a reason,
     * cutoff, lifecycle expectation, profile, owner, issuer, or responder.</p>
     *
     * @param credentialId exact committed credential identity
     * @param operatorJustification optional operator justification or ticket, limited to 1024 characters
     */
    record RevokePendingCredentialConfirmation(PkiId credentialId,
            java.util.Optional<String> operatorJustification) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.confirmation.pending.revoke";

        /** Validates the exact bounded administrative inputs. */
        public RevokePendingCredentialConfirmation {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
            operatorJustification = Objects.requireNonNull(operatorJustification, "operatorJustification")
                    .map(value -> requireText(value, 1024, "operatorJustification"));
        }

        /**
         * Creates a request without an operator justification.
         *
         * @param credentialId exact pending credential identifier
         */
        public RevokePendingCredentialConfirmation(PkiId credentialId) {
            this(credentialId, java.util.Optional.empty());
        }

        @Override
        public String name() {
            return NAME;
        }

        private static String requireText(String value, int maximumLength, String label) {
            if (value.isBlank() || value.length() > maximumLength) {
                throw new IllegalArgumentException(label + " is invalid");
            }
            return value;
        }
    }

    /**
     * Issues one end-entity credential from an already imported request.
     *
     * @param issuerCaId issuing certificate-authority identifier
     * @param requestId exact imported certification-request identifier
     * @param profileId nonblank stable certificate-profile identifier
     */
    record IssueCredential(PkiId issuerCaId, PkiId requestId, String profileId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.issue";

        /** Validates the issuance input. */
        public IssueCredential {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Renews one end-entity credential, keeping its subject and key under a fresh validity.
     *
     * @param credentialId exact committed credential identifier
     */
    record RenewCredential(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.renew";

        /** Validates the renewal input. */
        public RenewCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Replaces one end-entity credential from a new imported request and supersedes the predecessor.
     *
     * @param existingCredentialId exact credential that the replacement supersedes
     * @param requestId exact imported certification-request identifier
     * @param profileId nonblank stable certificate-profile identifier
     */
    record ReplaceCredential(PkiId existingCredentialId, PkiId requestId, String profileId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.replace";

        /** Validates the replacement input. */
        public ReplaceCredential {
            Objects.requireNonNull(existingCredentialId, "existingCredentialId");
            Objects.requireNonNull(requestId, "requestId");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reissues one end-entity credential from its stored issuance record and supersedes the predecessor.
     *
     * @param credentialId exact committed credential identifier
     */
    record ReissueCredential(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.reissue";

        /** Validates the reissue input. */
        public ReissueCredential {
            Objects.requireNonNull(credentialId, "credentialId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Rolls over one CA credential, keeping the same key and advancing the current issuance generation.
     *
     * @param caId exact certificate-authority identifier
     * @param issuerCaId optional issuing authority; empty selects the configured issuer
     */
    record RolloverCaCertificate(PkiId caId, java.util.Optional<PkiId> issuerCaId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.rollover";

        /** Validates the rollover input. */
        public RolloverCaCertificate {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Rotates one CA key and issues a new corresponding generation, advancing the current issuance pointers.
     *
     * @param caId exact certificate-authority identifier
     * @param newKeyRef optional managed replacement key; empty requests key generation
     * @param issuerCaId optional issuing authority; empty selects the configured issuer
     */
    record RotateCaKey(PkiId caId, java.util.Optional<KeyRef> newKeyRef, java.util.Optional<PkiId> issuerCaId)
            implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.rotate";

        /** Validates the rotation input. */
        public RotateCaKey {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(newKeyRef, "newKeyRef");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Permanently revokes one committed credential.
     *
     * @param credentialId exact credential identity
     * @param reason standardized permanent revocation reason
     * @param operatorJustification optional operator justification or ticket, limited to 1024 characters
     */
    record RevokeCredential(PkiId credentialId, RevocationReason reason,
            java.util.Optional<String> operatorJustification) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "credential.revoke";

        /** Validates permanent-revocation inputs. */
        public RevokeCredential {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
            Objects.requireNonNull(reason, "reason");
            operatorJustification = Objects.requireNonNull(operatorJustification, "operatorJustification")
                    .map(value -> requireText(value, 1024, "operatorJustification"));
            if (reason == RevocationReason.CERTIFICATE_HOLD || reason == RevocationReason.REMOVE_FROM_CRL) {
                throw new IllegalArgumentException("reason must be permanent");
            }
        }

        /**
         * Creates a revocation without an operator justification.
         *
         * @param credentialId exact credential identifier
         * @param reason permanent revocation reason
         */
        public RevokeCredential(PkiId credentialId, RevocationReason reason) {
            this(credentialId, reason, java.util.Optional.empty());
        }

        @Override
        public String name() {
            return NAME;
        }

        private static String requireText(String value, int maximumLength, String label) {
            if (value.isBlank() || value.length() > maximumLength) {
                throw new IllegalArgumentException(label + " is invalid");
            }
            return value;
        }
    }

    /**
     * Reads a bounded prefix from one closeable authoritative history cursor.
     *
     * @param credentialId exact committed credential identifier
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
    record ReadRevocationHistory(PkiId credentialId, int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.history";
        /** Maximum finite result entries for one invocation. */
        public static final int MAXIMUM_RESULT_ENTRIES = 1_000;

        /** Validates the identifier and finite result limit. */
        public ReadRevocationHistory {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
            if (limit < 1 || limit > MAXIMUM_RESULT_ENTRIES) {
                throw new IllegalArgumentException("limit must be between 1 and 1000");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads the validated current revocation state for one credential.
     *
     * @param credentialId exact committed credential identifier
     */
    record InspectRevocation(PkiId credentialId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "revocation.inspect";

        /** Validates the credential identity. */
        public InspectRevocation {
            Objects.requireNonNull(credentialId, credentialIdArgumentName());
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads a bounded page from one immutable current-revocation snapshot.
     *
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
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

    /**
     * Reads safe metadata for one committed status object.
     *
     * @param statusObjectId exact committed status-object identifier
     */
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

    /**
     * Lists status objects for one issuer with a finite presentation limit.
     *
     * @param issuerCaId issuing certificate-authority identifier
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
    record ListStatus(PkiId issuerCaId, int limit) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "inventory.status";

        /** Validates the issuer identity and presentation limit. */
        public ListStatus {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            requireLimit(limit);
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Generates one signed status object from a stable revocation view.
     *
     * @param issuerCaId issuing certificate-authority identifier
     * @param type kind of status object to generate
     * @param formatId encoding format for the created or imported object
     */
    record GenerateStatus(PkiId issuerCaId, StatusObjectType type, FormatId formatId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "status.generate";

        /** Validates the generation input. */
        public GenerateStatus {
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(formatId, "formatId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads safe durable state for one publication operation.
     *
     * @param publicationId exact publication-operation identifier
     */
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

    /**
     * Lists publication records using a bounded-memory cursor and finite result page.
     *
     * @param limit maximum number of entries to return, from 1 through {@link #MAXIMUM_RESULT_ENTRIES}
     */
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

    /**
     * Registers post-commit publication of one authoritative source object.
     *
     * @param publicationId exact publication-operation identifier
     * @param sourceType authoritative kind of the published source object
     * @param sourceId exact authoritative source-object identifier
     * @param target validated publication destination
     */
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

    /**
     * Processes one explicitly selected pending publication operation.
     *
     * @param publicationId exact publication-operation identifier
     */
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

    /**
     * Explicitly retries one eligible publication operation.
     *
     * @param publicationId exact publication-operation identifier
     */
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

    /**
     * Reconciles one publication operation whose external outcome is unknown.
     *
     * @param publicationId exact publication-operation identifier
     */
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

    /**
     * Creates one intermediate certificate authority and its initial CA credential.
     *
     * @param formatId encoding format for the created or imported object
     * @param issuerCaId issuing certificate-authority identifier
     * @param subjectRef subject name for the new authority
     * @param profileId nonblank stable certificate-profile identifier
     * @param keyRef optional existing managed key; empty requests key generation
     */
    record CreateIntermediate(FormatId formatId, PkiId issuerCaId, SubjectRef subjectRef, String profileId,
            java.util.Optional<KeyRef> keyRef) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.intermediate.create";

        /** Validates the closed intermediate-creation input. */
        public CreateIntermediate {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectRef, "subjectRef");
            keyRef = Objects.requireNonNull(keyRef, "keyRef");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Issues a new CA credential for an existing intermediate authority (cross-sign or renewal).
     *
     * @param formatId encoding format for the created or imported object
     * @param issuerCaId issuing certificate-authority identifier
     * @param subjectCaId subject intermediate-authority identifier
     * @param profileId nonblank stable certificate-profile identifier
     * @param requestedValidity optional requested validity constrained by the profile and issuer
     */
    record IssueIntermediateCertificate(FormatId formatId, PkiId issuerCaId, PkiId subjectCaId, String profileId,
            java.util.Optional<Validity> requestedValidity) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "ca.intermediate.issue";

        /** Validates the closed intermediate-issuance input. */
        public IssueIntermediateCertificate {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(issuerCaId, issuerAuthorityIdParameter());
            Objects.requireNonNull(subjectCaId, "subjectCaId");
            requestedValidity = Objects.requireNonNull(requestedValidity, "requestedValidity");
            if (profileId == null || profileId.isBlank()) {
                throw new IllegalArgumentException(profileIdRequiredMessage());
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads safe metadata for one concrete issuer generation.
     *
     * @param issuerId exact issuer-generation identifier
     */
    record InspectIssuerGeneration(PkiId issuerId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "issuer.generation.inspect";

        /** Validates the issuer-generation identity. */
        public InspectIssuerGeneration {
            Objects.requireNonNull(issuerId, "issuerId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads one immutable explicit issuer chain path.
     *
     * @param pathId exact issuer-chain-path identifier
     */
    record InspectIssuerChainPath(PkiId pathId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "issuer.path.inspect";

        /** Validates the chain-path identity. */
        public InspectIssuerChainPath {
            Objects.requireNonNull(pathId, "pathId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists all explicit chain paths for one issuer generation.
     *
     * @param issuerId exact issuer-generation identifier
     */
    record ListIssuerChainPaths(PkiId issuerId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "issuer.path.list";

        /** Validates the issuer-generation identity. */
        public ListIssuerChainPaths {
            Objects.requireNonNull(issuerId, "issuerId");
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Atomically selects the issuer generation and path used for future issuance.
     *
     * @param caId exact certificate-authority identifier
     * @param issuerId exact issuer-generation identifier
     * @param pathId exact issuer-chain-path identifier
     * @param reason nonblank auditable reason for the transition
     */
    record SelectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "issuer.path.select";

        /** Validates the closed path-selection input. */
        public SelectIssuancePath {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(pathId, "pathId");
            if (reason == null || reason.isBlank()) {
                throw new IllegalArgumentException("reason must not be blank");
            }
        }

        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Registers an additional explicit chain path for an existing issuer generation.
     *
     * @param caId exact certificate-authority identifier
     * @param issuerId exact issuer-generation identifier
     * @param parentPathId exact parent path to extend
     */
    record RegisterIssuerChainPath(PkiId caId, PkiId issuerId, PkiId parentPathId) implements PkiOperation {
        /** Stable operation name. */
        public static final String NAME = "issuer.path.register";

        /** Validates the closed path-registration input. */
        public RegisterIssuerChainPath {
            Objects.requireNonNull(caId, authorityIdParameter());
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(parentPathId, "parentPathId");
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

    private static String credentialIdArgumentName() {
        return "credentialId";
    }
}
