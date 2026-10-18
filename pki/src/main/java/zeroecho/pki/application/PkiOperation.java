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
package zeroecho.pki.application;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;

/** Closed set of synchronous non-signing PKI operations. */
public sealed interface PkiOperation permits PkiOperation.ValidateConfiguration, PkiOperation.ValidateProfile, // NOPMD ExcessivePublicCount - Sealed public operation algebra preserves stable consumer API.
        PkiOperation.ListProfiles, PkiOperation.ListRequests, PkiOperation.SearchCredentials,
        PkiOperation.ListIssuerGenerations, PkiOperation.ListAlgorithmBindings, PkiOperation.InspectAlgorithmBinding,
        PkiOperation.ValidateAlgorithmBindings, PkiOperation.RegisterProfile,
        PkiOperation.InspectProfile, PkiOperation.ListProfileVersions, PkiOperation.ActivateProfile,
        PkiOperation.InspectRequest, PkiOperation.ImportRequest, PkiOperation.VerifyRequest,
        PkiOperation.InspectAuthority, PkiOperation.InspectCredential, PkiOperation.InspectIssuerGeneration,
        PkiOperation.InspectIssuerChainPath, PkiOperation.InspectStatus,
        PkiOperation.ListAuthorities, PkiOperation.ListStatus, PkiOperation.ListIssuerChainPaths,
        PkiOperation.TransitionAuthority, PkiOperation.SelectIssuancePath, PkiOperation.RegisterIssuerChainPath,
        PkiOperation.ListPendingCredentialConfirmations, PkiOperation.IssueCredentialConfirmationChallenge,
        PkiOperation.CompleteCredentialConfirmationProof, PkiOperation.RevokePendingCredentialConfirmation,
        PkiOperation.RevokeCredential, PkiOperation.HoldCredential, PkiOperation.UnholdCredential, PkiOperation.InspectRevocation,
        PkiOperation.ReadRevocationHistory, PkiOperation.SnapshotRevocations,
        PkiOperation.InspectPublication, PkiOperation.ListPublications,
        PkiOperation.RegisterPublication, PkiOperation.ProcessPublication,
        PkiOperation.RetryPublication, PkiOperation.ReconcilePublication,
        PkiOperation.SetStatusSchedule, PkiOperation.InspectStatusSchedule, PkiOperation.ListStatusSchedules,
        PkiOperation.QueryAuthorityMetrics, PkiOperation.QueryCertificateMetrics,
        PkiOperation.QueryRevocationMetrics, PkiOperation.QueryPublicationMetrics,
        PkiOperation.QueryServerMetrics {

    /** Maximum allowed limit for capped presentation operations. */
    int MAXIMUM_RESULT_ENTRIES = 1_000;

    private static void requireAuthority(PkiId caId) {
        Objects.requireNonNull(caId, "caId");
    }

    /**
     * Returns the stable semantic operation name.
     *
     * @return stable semantic operation name
     */
    String name();

    /**
     * Lists logical profile identifiers in ascending identifier order without subject data.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListProfiles(int limit, Optional<String> after) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "profile.list-all";
        /** Validates the page limit and exclusive cursor. */
        public ListProfiles { requireLimit(limit); after = requireCursor(after); }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists stored requests in ascending identifier order without subject or key material.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListRequests(int limit, Optional<String> after) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "request.list";
        /** Validates the page limit and exclusive cursor. */
        public ListRequests { requireLimit(limit); after = requireCursor(after); }
        @Override public String name() { return NAME; }
    }

    /**
     * Searches credentials issued by one authoritative authority with optional filters.
     *
     * @param authorityId      exact authority identifier that scopes the query
     * @param limit            maximum number of returned entries, from 1 to 1000
     * @param after            optional exclusive identifier cursor; empty starts the first page
     * @param subjectFilter    optional case-insensitive substring match on the subject DN
     * @param serialFilter     optional case-insensitive substring match on the serial/unique id
     * @param fingerprintFilter optional case-insensitive prefix match on the credential ID; not a digest
     * @param statusFilter     optional exact credential status name (ISSUED, REVOKED, EXPIRED)
     * @param profileIdFilter  optional exact profile logical id
     * @param sanFilter optional exact typed SAN, encoded as DNS_NAME:value, IP_ADDRESS:value, URI:value or RFC822_NAME:value
     */
    record SearchCredentials(PkiId authorityId, int limit, Optional<String> after,
            Optional<String> subjectFilter, Optional<String> serialFilter,
            Optional<String> fingerprintFilter, Optional<String> statusFilter,
            Optional<String> profileIdFilter, Optional<String> sanFilter) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "credential.search";
        /** Validates the scope, page limit, exclusive cursor and optional filters. */
        public SearchCredentials {
            Objects.requireNonNull(authorityId, "authorityId");
            requireLimit(limit); after = requireCursor(after);
            Objects.requireNonNull(subjectFilter, "subjectFilter");
            Objects.requireNonNull(serialFilter, "serialFilter");
            Objects.requireNonNull(fingerprintFilter, "fingerprintFilter");
            Objects.requireNonNull(statusFilter, "statusFilter");
            Objects.requireNonNull(profileIdFilter, "profileIdFilter");
            Objects.requireNonNull(sanFilter, "sanFilter").ifPresent(
                    zeroecho.pki.api.credential.CredentialSearchQuery::parseSanFilter);
        }

        /**
         * Creates a search without a SAN constraint, preserving the original constructor.
         * @param authorityId authoritative issuing authority
         * @param limit page size
         * @param after exclusive ID cursor
         * @param subjectFilter optional subject substring
         * @param serialFilter optional serial substring
         * @param fingerprintFilter optional credential-ID prefix
         * @param statusFilter optional inventory status
         * @param profileIdFilter optional profile logical ID
         */
        public SearchCredentials(PkiId authorityId, int limit, Optional<String> after,
                Optional<String> subjectFilter, Optional<String> serialFilter, Optional<String> fingerprintFilter,
                Optional<String> statusFilter, Optional<String> profileIdFilter) {
            this(authorityId, limit, after, subjectFilter, serialFilter, fingerprintFilter,
                    statusFilter, profileIdFilter, Optional.empty());
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists all historical issuer generations of one authority, ordered by identifier.
     *
     * @param authorityId exact authority identifier that scopes the query
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListIssuerGenerations(PkiId authorityId, int limit, Optional<String> after) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "issuer.generation.list";
        /** Validates the scope, page limit and exclusive cursor. */
        public ListIssuerGenerations {
            Objects.requireNonNull(authorityId, "authorityId");
            requireLimit(limit); after = requireCursor(after);
        }
        @Override public String name() { return NAME; }
    }

    private static Optional<String> requireCursor(Optional<String> after) {
        Objects.requireNonNull(after, "after");
        after.ifPresent(value -> {
            if (value.isBlank() || value.length() > 1024 || value.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("after must be a bounded nonblank identifier");
            }
        });
        return after;
    }

    /**
     * Lists active X.509 algorithm bindings.
     *
     * @param origin optional nonblank binding-origin filter
     * @param role optional nonblank binding-role filter
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListAlgorithmBindings(Optional<String> origin, Optional<String> role, int limit, Optional<String> after)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "algorithm.binding.list";
        /**
         * Validates the bounded query.
         *
         * @param origin optional nonblank binding-origin filter
         * @param role optional nonblank binding-role filter
         * @param limit maximum number of returned entries, from 1 to 1000
         */
        public ListAlgorithmBindings(Optional<String> origin, Optional<String> role, int limit) {
            this(origin, role, limit, Optional.empty());
        }
        /** Validates the bounded keyset query. */
        public ListAlgorithmBindings {
            after = requireCursor(after);
            origin = requireOptionalText(origin, "origin");
            role = requireOptionalText(role, "role");
            requireLimit(limit);
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects one active X.509 algorithm binding.
     *
     * @param bindingId exact binding identifier
     */
    record InspectAlgorithmBinding(String bindingId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "algorithm.binding.inspect";
        /** Validates the identifier. */
        public InspectAlgorithmBinding { requireText(bindingId, "bindingId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Validates the active binding registry and optionally one exact binding.
     *
     * @param bindingId optional exact binding identifier; empty validates the complete registry
     * @param expectedCommitment expected binding commitment, supplied together with the binding identifier
     */
    record ValidateAlgorithmBindings(Optional<String> bindingId, Optional<String> expectedCommitment)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "algorithm.binding.validate";
        /** Validates paired optional values. */
        public ValidateAlgorithmBindings {
            bindingId = Objects.requireNonNull(bindingId, "bindingId");
            expectedCommitment = Objects.requireNonNull(expectedCommitment, "expectedCommitment");
            if (bindingId.isPresent() != expectedCommitment.isPresent()) {
                throw new IllegalArgumentException("Binding validation fields must be supplied together");
            }
            bindingId.ifPresent(value -> requireText(value, "bindingId"));
            expectedCommitment.ifPresent(value -> {
                if (!value.matches("[0-9a-f]{64}|[^\\s]{1,512}")) {
                    throw new IllegalArgumentException("Binding commitment is invalid");
                }
            });
        }
        @Override public String name() { return NAME; }
    }

    /** Validates the opened session configuration. */
    record ValidateConfiguration() implements PkiOperation {
        /** Stable name. */ public static final String NAME = "configuration.validate";
        @Override public String name() { return NAME; }
    }

    /**
     * Validates one profile document without storing it.
     *
     * @param document non-null encoded profile document, defensively copied
     */
    record ValidateProfile(byte[] document) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "profile.validate";
        /** Defensively copies the document. */
        public ValidateProfile { document = Objects.requireNonNull(document, "document").clone(); }
        /** {@return a defensive document copy} */
        @Override public byte[] document() { return document.clone(); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers one profile document.
     *
     * @param document non-null encoded profile document, defensively copied
     */
    record RegisterProfile(byte[] document) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "profile.register";
        /** Defensively copies the document. */
        public RegisterProfile { document = Objects.requireNonNull(document, "document").clone(); }
        /** {@return a defensive document copy} */
        @Override public byte[] document() { return document.clone(); }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects one exact profile version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported profile version
     */
    record InspectProfile(String profileId, long profileVersion) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "profile.inspect";
        /** Validates the identity. */
        @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
        public InspectProfile {
            requireText(profileId, "profileId");
            if (profileVersion < 1L) { throw new IllegalArgumentException("profileVersion must be positive"); }
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists imported versions of one profile.
     *
     * @param profileId nonblank logical profile identifier
     */
    record ListProfileVersions(String profileId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "profile.list";
        /** Validates the identifier. */
        public ListProfileVersions { requireText(profileId, "profileId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Activates one imported profile version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported profile version
     */
    record ActivateProfile(String profileId, long profileVersion) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "profile.activate";
        /** Validates the identity. */
        @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
        public ActivateProfile {
            requireText(profileId, "profileId");
            if (profileVersion < 1L) { throw new IllegalArgumentException("profileVersion must be positive"); }
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the metadata of one stored authority through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code caId}, {@code kind}, {@code state}, {@code issuerGenerationCount},
     * and {@code currentIssuanceIssuerId}.
     * A missing object produces {@link PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * @param caId exact non-null stored-object identifier
     */
    record InspectAuthority(PkiId caId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "ca.inspect";

        /**
         * Creates an immutable point-inspection request.
         *
         * @param caId exact stored-object identifier
         * @throws NullPointerException if {@code caId} is {@code null}
         */
        public InspectAuthority { requireAuthority(caId); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the metadata of one stored credential through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code credentialId}, {@code formatId}, {@code authorityId}, {@code issuerId},
     * {@code publicKeyId}, {@code profileId}, {@code profileVersion}, {@code status},
     * {@code notBefore}, and {@code notAfter}.
     * A missing object produces {@link PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * <p>The status is persisted inventory metadata, not a current trust or revocation decision.</p>
     *
     * @param credentialId exact non-null stored-object identifier
     */
    record InspectCredential(PkiId credentialId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "credential.inspect";

        /**
         * Creates an immutable point-inspection request.
         *
         * @param credentialId exact stored-object identifier
         * @throws NullPointerException if {@code credentialId} is {@code null}
         */
        public InspectCredential { requireCredentialId(credentialId); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the metadata of one stored issuer generation through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code issuerId}, {@code authorityId}, {@code credentialId}, {@code state},
     * {@code profilePolicyCommitment}, and {@code x509BindingCommitment}.
     * A missing object produces {@link PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * @param issuerId exact non-null stored-object identifier
     */
    record InspectIssuerGeneration(PkiId issuerId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "issuer.generation.inspect";

        /**
         * Creates an immutable point-inspection request.
         *
         * @param issuerId exact stored-object identifier
         * @throws NullPointerException if {@code issuerId} is {@code null}
         */
        public InspectIssuerGeneration { Objects.requireNonNull(issuerId, "issuerId"); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the metadata of one stored issuer chain path through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code pathId}, {@code authorityId}, {@code issuerId}, {@code pathCommitment},
     * {@code orderedCredentialIds} in leaf-to-anchor order, and {@code count}.
     * A missing object produces {@link PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * @param pathId exact non-null stored-object identifier
     */
    record InspectIssuerChainPath(PkiId pathId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "issuer.path.inspect";

        /**
         * Creates an immutable point-inspection request.
         *
         * @param pathId exact stored-object identifier
         * @throws NullPointerException if {@code pathId} is {@code null}
         */
        public InspectIssuerChainPath { Objects.requireNonNull(pathId, "pathId"); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the metadata of one stored status object through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code statusObjectId}, {@code issuerCaId}, {@code type}, {@code formatId},
     * {@code thisUpdate}, optional {@code nextUpdate}, {@code contentLength},
     * and {@code contentSha256}.
     * A missing object produces {@link PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * @param statusObjectId exact non-null stored-object identifier
     */
    record InspectStatus(PkiId statusObjectId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "status.inspect";

        /**
         * Creates an immutable point-inspection request.
         *
         * @param statusObjectId exact stored-object identifier
         * @throws NullPointerException if {@code statusObjectId} is {@code null}
         */
        public InspectStatus { Objects.requireNonNull(statusObjectId, "statusObjectId"); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Lists the first authorities in authoritative store order.
     *
     * <p>The result contains {@code count}, {@code truncated}, and {@code authorities};
     * each entry has the fields of {@link InspectAuthority}. The limit bounds only
     * presentation: the store loads and validates its complete authority population
     * before the prefix is selected. An empty population returns an empty list.</p>
     *
     * @param limit maximum returned authorities, from 1 through 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListAuthorities(int limit, Optional<String> after) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "ca.list";

        /**
         * Creates an immutable authority-list request.
         *
         * @param limit maximum returned authorities
         * @throws IllegalArgumentException if {@code limit} is outside 1 through 1000
         */
        public ListAuthorities(int limit) { this(limit, Optional.empty()); }
        /** Validates the bounded keyset query. */
        public ListAuthorities { requireLimit(limit); after = requireCursor(after); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Lists the first status objects for one issuer in authoritative store order.
     *
     * <p>The result contains {@code issuerCaId}, {@code count}, {@code truncated},
     * and {@code statusObjects}; each entry has the fields of {@link InspectStatus}.
     * An unknown issuer returns an empty list. The limit bounds only presentation:
     * existing store validation reads status metadata and content across all issuers
     * before filtering and selecting the requested prefix.</p>
     *
     * @param issuerCaId exact non-null issuer authority identifier
     * @param limit maximum returned status objects, from 1 through 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListStatus(PkiId issuerCaId, int limit, Optional<String> after) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "inventory.status";

        /**
         * Creates an immutable status-list request.
         *
         * @param issuerCaId exact issuer authority identifier
         * @param limit maximum returned status objects
         * @throws NullPointerException if {@code issuerCaId} is {@code null}
         * @throws IllegalArgumentException if {@code limit} is outside 1 through 1000
         */
        public ListStatus(PkiId issuerCaId, int limit) { this(issuerCaId, limit, Optional.empty()); }
        /** Validates the bounded keyset query. */
        public ListStatus {
            after = requireCursor(after);
            Objects.requireNonNull(issuerCaId, "issuerCaId");
            requireLimit(limit);
        }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Lists all chain paths for one issuer generation in authoritative store order.
     *
     * <p>The result contains {@code issuerId}, {@code count}, and {@code paths};
     * each entry has the fields of {@link InspectIssuerChainPath}. An unknown issuer
     * returns an empty list. This operation has no presentation cap or truncation
     * field. Existing store validation examines all stored paths before filtering.</p>
     *
     * @param issuerId exact non-null issuer-generation identifier
     */
    record ListIssuerChainPaths(PkiId issuerId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "issuer.path.list";

        /**
         * Creates an immutable issuer-path-list request.
         *
         * @param issuerId exact issuer-generation identifier
         * @throws NullPointerException if {@code issuerId} is {@code null}
         */
        public ListIssuerChainPaths { Objects.requireNonNull(issuerId, "issuerId"); }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Changes one authority's operational state without changing its generation selection.
     *
     * <p>Every {@link CaState} is supported. Requesting the current state performs
     * no CA write. A different state uses one conditional replacement; a concurrent
     * change produces {@link PkiOperationFailure#CONFLICT} without retry. Success
     * returns the fields of {@link InspectAuthority} from a subsequent authoritative
     * read, which may include a later concurrent change.</p>
     *
     * @param caId exact non-null authority identifier
     * @param state requested non-null operational state
     * @param reason nonblank administrative reason
     */
    record TransitionAuthority(PkiId caId, CaState state, String reason) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "ca.transition";

        /**
         * Creates an immutable state-transition request.
         *
         * @param caId exact authority identifier
         * @param state requested operational state
         * @param reason nonblank administrative reason
         * @throws NullPointerException if the identifier or state is null
         * @throws IllegalArgumentException if the reason is null or blank
         */
        public TransitionAuthority {
            requireAuthority(caId);
            Objects.requireNonNull(state, "state");
            requireText(reason, "reason");
        }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Selects an active issuer generation and matching chain path owned by one authority.
     *
     * <p>The CA need not be active. One conditional replacement preserves its state,
     * memberships and immutable base while selecting the generation, path and the
     * generation's signing key. Re-selecting the current coordinates still writes.
     * A concurrent change produces {@link PkiOperationFailure#CONFLICT} without retry.
     * Success returns exactly {@code caId}, {@code issuerId} and {@code pathId}.</p>
     *
     * @param caId exact non-null authority identifier
     * @param issuerId exact non-null member issuer-generation identifier
     * @param pathId exact non-null matching path identifier
     * @param reason nonblank administrative reason
     */
    record SelectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "issuer.path.select";

        /**
         * Creates an immutable issuance-selection request.
         *
         * @param caId exact authority identifier
         * @param issuerId exact member generation identifier
         * @param pathId exact matching path identifier
         * @param reason nonblank administrative reason
         * @throws NullPointerException if an identifier is null
         * @throws IllegalArgumentException if the reason is null or blank
         */
        public SelectIssuancePath {
            requireAuthority(caId);
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(pathId, "pathId");
            requireText(reason, "reason");
        }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Registers a chain path by prepending a member generation's credential to a parent path.
     *
     * <p>The CA and generation need not be active. Existing store validation enforces
     * certificate relationships and a maximum of 32 credentials. Registration never
     * changes the CA head or selected path. Success returns the fields of
     * {@link InspectIssuerChainPath}; duplicate immutable creation retains the store's
     * rejection behavior.</p>
     *
     * @param caId exact non-null authority identifier
     * @param issuerId exact non-null member generation identifier
     * @param parentPathId exact non-null immutable parent-path identifier
     */
    record RegisterIssuerChainPath(PkiId caId, PkiId issuerId, PkiId parentPathId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "issuer.path.register";

        /**
         * Creates an immutable path-registration request.
         *
         * @param caId exact authority identifier
         * @param issuerId exact member generation identifier
         * @param parentPathId exact parent-path identifier
         * @throws NullPointerException if an identifier is null
         */
        public RegisterIssuerChainPath {
            requireAuthority(caId);
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(parentPathId, "parentPathId");
        }

        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects one stored certification request.
     *
     * @param requestId exact stored certification-request identifier
     */
    record InspectRequest(PkiId requestId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "request.inspect";
        /** Validates the identifier. */
        public InspectRequest { Objects.requireNonNull(requestId, "requestId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Imports one certification request.
     *
     * @param formatId credential framework format identifier
     * @param encoded encoded certification-request object
     */
    record ImportRequest(FormatId formatId, EncodedObject encoded) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "request.import";
        /** Validates the object. */
        public ImportRequest {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(encoded, "encoded");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Verifies proof of possession for one stored request.
     *
     * @param requestId exact stored certification-request identifier
     */
    record VerifyRequest(PkiId requestId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "request.verify";
        /** Validates the identifier. */
        public VerifyRequest { Objects.requireNonNull(requestId, "requestId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists pending credential-confirmation reviews in one authorized scope.
     *
     * @param authorityId exact authority identifier that scopes the query
     * @param profileId optional nonblank profile identifier limiting the query
     * @param cutoffInclusive inclusive UTC cutoff for pending confirmation deadlines
     * @param afterExclusive optional exclusive confirmation-review cursor
     * @param limit maximum number of returned entries, from 1 to 1000
     */
    record ListPendingCredentialConfirmations(PkiId authorityId, Optional<String> profileId,
            Instant cutoffInclusive, Optional<CredentialConfirmationReviewCursor> afterExclusive, int limit)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "credential.confirmation.pending.list";
        /** Validates the keyset query. */
        public ListPendingCredentialConfirmations {
            Objects.requireNonNull(authorityId, "authorityId");
            requireBoundedText(authorityId.value(), "authorityId", 256);
            profileId = Objects.requireNonNull(profileId, "profileId");
            profileId.ifPresent(value -> requireBoundedText(value, "profileId", 256));
            Objects.requireNonNull(cutoffInclusive, "cutoffInclusive");
            if (cutoffInclusive.getEpochSecond() < 0L || cutoffInclusive.getEpochSecond() > 253_402_300_799L) {
                throw new IllegalArgumentException("cutoffInclusive is outside the supported UTC range");
            }
            afterExclusive = Objects.requireNonNull(afterExclusive, "afterExclusive");
            requireLimit(limit);
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Issues or replays the proof challenge for one pending confirmation.
     *
     * @param credentialId exact stored credential identifier
     */
    record IssueCredentialConfirmationChallenge(PkiId credentialId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "credential.confirmation.challenge.issue";
        /** Validates the identifier. */
        public IssueCredentialConfirmationChallenge { requireCredentialId(credentialId); }
        @Override public String name() { return NAME; }
    }

    /**
     * Completes one credential confirmation proof.
     *
     * @param submission non-null challenge response and proof submission
     */
    record CompleteCredentialConfirmationProof(CredentialConfirmationProofSubmission submission)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "credential.confirmation.proof.complete";
        /** Validates the submission. */
        public CompleteCredentialConfirmationProof { Objects.requireNonNull(submission, "submission"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Permanently revokes one still-pending non-public credential.
     *
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank administrative justification, at most 1024 characters
     */
    record RevokePendingCredentialConfirmation(PkiId credentialId, Optional<String> operatorJustification)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "credential.confirmation.pending.revoke";
        /** Validates bounded administrative input. */
        public RevokePendingCredentialConfirmation {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /**
         * Creates a revocation without justification.
         *
         * @param credentialId exact stored credential identifier
         */
        public RevokePendingCredentialConfirmation(PkiId credentialId) { this(credentialId, Optional.empty()); }
        @Override public String name() { return NAME; }
    }

    /**
     * Places one committed credential on temporary hold using the authoritative clock.
     * Permanent revocation cannot be replaced by a hold.
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank justification, at most 1024 characters
     */
    record HoldCredential(PkiId credentialId, Optional<String> operatorJustification) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "credential.hold";
        /** Validates the exact target and bounded optional justification. */
        public HoldCredential {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /** Creates a hold without justification.
         * @param credentialId exact stored credential identifier
         */
        public HoldCredential(PkiId credentialId) { this(credentialId, Optional.empty()); }
        @Override public String name() { return NAME; }
    }

    /**
     * Releases an existing temporary hold using the authoritative clock.
     * Permanent revocation is irreversible and is never released by this operation.
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank justification, at most 1024 characters
     */
    record UnholdCredential(PkiId credentialId, Optional<String> operatorJustification) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "credential.unhold";
        /** Validates the exact target and bounded optional justification. */
        public UnholdCredential {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /** Creates a release without justification.
         * @param credentialId exact stored credential identifier
         */
        public UnholdCredential(PkiId credentialId) { this(credentialId, Optional.empty()); }
        @Override public String name() { return NAME; }
    }

    /**
     * Permanently revokes one committed credential.
     *
     * @param credentialId exact stored credential identifier
     * @param reason permanent revocation reason; hold and remove-from-CRL are rejected
     * @param operatorJustification optional nonblank administrative justification, at most 1024 characters
     */
    record RevokeCredential(PkiId credentialId, RevocationReason reason, Optional<String> operatorJustification)
            implements PkiOperation {
        /** Stable name. */ public static final String NAME = "credential.revoke";
        /** Validates permanent revocation input. */
        public RevokeCredential {
            requireCredentialId(credentialId);
            Objects.requireNonNull(reason, "reason");
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
            if (reason == RevocationReason.CERTIFICATE_HOLD || reason == RevocationReason.REMOVE_FROM_CRL) {
                throw new IllegalArgumentException("reason must be permanent");
            }
        }
        /**
         * Creates a revocation without justification.
         *
         * @param credentialId exact stored credential identifier
         * @param reason permanent revocation reason; hold and remove-from-CRL are rejected
         */
        public RevokeCredential(PkiId credentialId, RevocationReason reason) {
            this(credentialId, reason, Optional.empty());
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Reads a bounded prefix of one revocation history.
     *
     * @param credentialId exact stored credential identifier
     * @param limit maximum number of returned entries, from 1 to 1000
     */
    record ReadRevocationHistory(PkiId credentialId, int limit) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "revocation.history";
        /** Validates the bounded query. */
        public ReadRevocationHistory {
            requireCredentialId(credentialId);
            requireLimit(limit);
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the current revocation state.
     *
     * @param credentialId exact stored credential identifier
     */
    record InspectRevocation(PkiId credentialId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "revocation.inspect";
        /** Validates the identifier. */
        public InspectRevocation { requireCredentialId(credentialId); }
        @Override public String name() { return NAME; }
    }

    /**
     * Reads a bounded current-revocation snapshot.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     */
    record SnapshotRevocations(int limit) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "revocation.snapshot";
        /** Validates the limit. */
        public SnapshotRevocations { requireLimit(limit); }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects one publication operation.
     *
     * @param publicationId exact publication operation identifier
     */
    record InspectPublication(PkiId publicationId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.inspect";
        /** Validates the identifier. */
        public InspectPublication { Objects.requireNonNull(publicationId, "publicationId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists publication operations.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListPublications(int limit, Optional<String> after) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.list";
        /**
         * Validates the limit.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         */
        public ListPublications(int limit) { this(limit, Optional.empty()); }
        /** Validates the bounded keyset query. */
        public ListPublications { requireLimit(limit); after = requireCursor(after); }
        @Override public String name() { return NAME; }
    }

    /**
     * Registers post-commit publication of one authoritative object.
     *
     * @param publicationId exact publication operation identifier
     * @param sourceType type of authoritative object to publish
     * @param sourceId exact identifier of the authoritative source object
     * @param target configured publication destination
     */
    record RegisterPublication(PkiId publicationId, PublicationSourceType sourceType, PkiId sourceId,
            PublicationTarget target) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.register";
        /** Validates the registration. */
        public RegisterPublication {
            Objects.requireNonNull(publicationId, "publicationId");
            Objects.requireNonNull(sourceType, "sourceType");
            Objects.requireNonNull(sourceId, "sourceId");
            Objects.requireNonNull(target, "target");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Processes one pending publication.
     *
     * @param publicationId exact publication operation identifier
     */
    record ProcessPublication(PkiId publicationId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.process";
        /** Validates the identifier. */
        public ProcessPublication { Objects.requireNonNull(publicationId, "publicationId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Retries one eligible publication.
     *
     * @param publicationId exact publication operation identifier
     */
    record RetryPublication(PkiId publicationId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.retry";
        /** Validates the identifier. */
        public RetryPublication { Objects.requireNonNull(publicationId, "publicationId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Reconciles one publication with an unknown external outcome.
     *
     * @param publicationId exact publication operation identifier
     */
    record ReconcilePublication(PkiId publicationId) implements PkiOperation {
        /** Stable name. */ public static final String NAME = "publication.reconcile";
        /** Validates the identifier. */
        public ReconcilePublication { Objects.requireNonNull(publicationId, "publicationId"); }
        @Override public String name() { return NAME; }
    }

    /**
     * Creates or replaces the automatic generation schedule for one CA status family.
     *
     * @param caId exact authority identifier
     * @param statusType kind of status object to generate
     * @param formatId encoding format for generated objects
     * @param interval positive generation interval (minimum PT1M)
     * @param graceSeconds non-negative grace seconds before the worker retries after {@code nextUpdate}
     * @param enabled whether automatic generation is active
     * @param publicationTarget optional publication destination; empty = generate only
     */
    record SetStatusSchedule(PkiId caId, StatusObjectType statusType, FormatId formatId,
            Duration interval, long graceSeconds, boolean enabled,
            Optional<PublicationTarget> publicationTarget) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "status.schedule.set";
        /** Validates the schedule configuration. */
        public SetStatusSchedule {
            requireAuthority(caId);
            Objects.requireNonNull(statusType, "statusType");
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(interval, "interval");
            if (interval.isNegative() || interval.isZero()
                    || interval.compareTo(zeroecho.pki.api.schedule.StatusSchedule.MINIMUM_INTERVAL) < 0) {
                throw new IllegalArgumentException("interval must be at least PT1M");
            }
            if (graceSeconds < 0L || graceSeconds >= interval.getSeconds()) {
                throw new IllegalArgumentException("graceSeconds must leave at least one whole second of cadence");
            }
            if (enabled && (statusType == StatusObjectType.OCSP || !"x509".equals(formatId.value()))) {
                throw new IllegalArgumentException("Only X.509 full and delta CRL schedules are executable");
            }
            publicationTarget = Objects.requireNonNull(publicationTarget, "publicationTarget");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Inspects the generation schedule for one CA status family.
     *
     * @param caId exact authority identifier
     * @param statusType kind of status object
     */
    record InspectStatusSchedule(PkiId caId, StatusObjectType statusType) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "status.schedule.inspect";
        /** Validates the identity. */
        public InspectStatusSchedule {
            requireAuthority(caId);
            Objects.requireNonNull(statusType, "statusType");
        }
        @Override public String name() { return NAME; }
    }

    /**
     * Lists all configured generation schedules.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive cursor; empty starts the first page
     */
    record ListStatusSchedules(int limit, Optional<String> after) implements PkiOperation {
        /** Stable operation name. */ public static final String NAME = "status.schedule.list";
        /**
         * Creates the first page query.
         * @param limit maximum number of results, from 1 to 1000
         * @throws IllegalArgumentException if the limit is outside the supported range
         */
        public ListStatusSchedules(int limit) { this(limit, Optional.empty()); }
        /** Validates the bounded keyset query. */
        public ListStatusSchedules { requireLimit(limit); after = requireCursor(after); }
        @Override public String name() { return NAME; }
    }

    /**
     * Queries authority-inventory metrics for one CA: issuer-generation states,
     * chain depth, and CA lifecycle state.
     *
     * @param caId exact authority identifier
     */
    record QueryAuthorityMetrics(PkiId caId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "dashboard.authority";
        /** Validates the identifier. */
        public QueryAuthorityMetrics { requireAuthority(caId); }
        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Queries certificate-lifecycle metrics for one CA: active, expiring, and revoked counts.
     * Pending-request lifecycle measurement is explicitly unavailable because requests have
     * no authoritative CA lifecycle binding.
     *
     * @param caId exact authority identifier
     */
    record QueryCertificateMetrics(PkiId caId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "dashboard.certificate";
        /** Validates the identifier. */
        public QueryCertificateMetrics { requireAuthority(caId); }
        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Queries revocation and CRL freshness metrics for one CA.
     *
     * @param caId exact authority identifier
     */
    record QueryRevocationMetrics(PkiId caId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "dashboard.revocation";
        /** Validates the identifier. */
        public QueryRevocationMetrics { requireAuthority(caId); }
        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Queries publication-health metrics for one CA: pending and failing publication counts.
     *
     * @param caId exact authority identifier
     */
    record QueryPublicationMetrics(PkiId caId) implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "dashboard.publication";
        /** Validates the identifier. */
        public QueryPublicationMetrics { requireAuthority(caId); }
        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    /**
     * Queries server-health and enrollment metrics: JVM heap, approval queue depth,
     * admin request totals, and audit-projection failure counts.
     */
    record QueryServerMetrics() implements PkiOperation {
        /** Stable semantic operation name. */
        public static final String NAME = "dashboard.server";
        /** {@return the stable semantic name {@value #NAME}} */
        @Override public String name() { return NAME; }
    }

    private static void requireCredentialId(PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
    }

    private static void requireLimit(int limit) {
        if (limit < 1 || limit > MAXIMUM_RESULT_ENTRIES) {
            throw new IllegalArgumentException("limit must be between 1 and 1000");
        }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    private static Optional<String> requireOptionalText(Optional<String> value, String name) {
        return Objects.requireNonNull(value, name).map(text -> {
            requireText(text, name);
            return text;
        });
    }

    private static Optional<String> boundedOptional(Optional<String> value, String name, int maximumLength) {
        return Objects.requireNonNull(value, name).map(text -> {
            requireBoundedText(text, name, maximumLength);
            return text;
        });
    }

    private static void requireBoundedText(String value, String name, int maximumLength) {
        Objects.requireNonNull(value, name);
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        if (value.isBlank() || encoded.length > maximumLength
                || !value.equals(new String(encoded, StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException(name + " is not bounded strict UTF-8");
        }
    }
}
