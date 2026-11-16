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

/**
 * Closed set of synchronous PKI queries and non-signing administrative commands.
 *
 * <p>Constructing a value performs only the local checks documented by its
 * constructor. It does not authorize the caller, open a session, resolve stored
 * identifiers or commit a change. The executor and its admission context enforce
 * those boundaries. Validation and inspection remain distinct from registration,
 * lifecycle mutation and external publication.</p>
 *
 * <p>These values are not a general-purpose redacted audit representation. In
 * particular, profile documents, request objects, search filters and administrative
 * reasons may contain sensitive application data. Select an explicit projection
 * rather than logging a record's generated string representation.</p>
 */
public sealed interface PkiOperation permits PkiOperation.ValidateConfiguration, PkiOperation.ValidateProfile, // NOPMD ExcessivePublicCount - Sealed public operation algebra preserves stable consumer API.
        PkiOperation.ListProfiles, PkiOperation.ListRequests, PkiOperation.ListCredentials, PkiOperation.SearchCredentials,
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

    /**
     * Maximum allowed limit for capped presentation operations.
     */
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "profile.list-all";
        /**
         * Checks the presentation limit and exclusive profile cursor before a store query.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListProfiles {
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists stored requests in ascending identifier order without subject or key material.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListRequests(int limit, Optional<String> after) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "request.list";
        /**
         * Checks the presentation limit and exclusive request cursor before a store query.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListRequests {
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists authoritative credential metadata without requiring an optional search index.
     * CA and leaf credentials are scoped to their canonical issuing authority.
     * Authorization predicates are applied before page capacity is consumed.
     * @param authorityId exact issuing authority identifier
     * @param limit maximum returned entries, from 1 through 1000
     * @param after optional exclusive credential-ID cursor
     */
    record ListCredentials(PkiId authorityId, int limit, Optional<String> after) implements PkiOperation {
        /**
         * Stable mandatory inventory operation name.
         */
        public static final String NAME = "credential.list";
        /**
         * Checks the authority scope and bounded credential cursor without resolving the authority.
         *
         * @param authorityId exact issuing authority identifier
         * @param limit maximum returned entries, from 1 through 1000
         * @param after optional exclusive credential-ID cursor
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListCredentials {
            Objects.requireNonNull(authorityId, "authorityId");
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
     * @param sanFilter optional exact typed SAN, encoded as DNS_NAME:value, IP_ADDRESS:value, URI:value
     *     or RFC822_NAME:value
     */
    record SearchCredentials(PkiId authorityId, int limit, Optional<String> after,
            Optional<String> subjectFilter, Optional<String> serialFilter,
            Optional<String> fingerprintFilter, Optional<String> statusFilter,
            Optional<String> profileIdFilter, Optional<String> sanFilter) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.search";
        /**
         * Checks the authority, page and typed SAN syntax; other optional filter text is retained unchanged.
         *
         * @param authorityId exact authority identifier that scopes the query
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @param subjectFilter optional case-insensitive substring match on the subject DN
         * @param serialFilter optional case-insensitive substring match on the serial/unique id
         * @param fingerprintFilter optional case-insensitive prefix match on the credential ID; not a digest
         * @param statusFilter optional exact credential status name (ISSUED, REVOKED, EXPIRED)
         * @param profileIdFilter optional exact profile logical id
         * @param sanFilter optional exact typed SAN, encoded as DNS_NAME:value, IP_ADDRESS:value,
         *     URI:value or RFC822_NAME:value
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character; a present
         *     SAN filter has an unsupported type or invalid value
         */
        public SearchCredentials {
            Objects.requireNonNull(authorityId, "authorityId");
            requireLimit(limit);
            after = requireCursor(after);
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
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists all historical issuer generations of one authority, ordered by identifier.
     *
     * @param authorityId exact authority identifier that scopes the query
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListIssuerGenerations(PkiId authorityId, int limit, Optional<String> after) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "issuer.generation.list";
        /**
         * Checks the required authority scope and bounded generation cursor.
         *
         * @param authorityId exact authority identifier that scopes the query
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListIssuerGenerations {
            Objects.requireNonNull(authorityId, "authorityId");
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable name.
         */
        public static final String NAME = "algorithm.binding.list";
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
        /**
         * Checks the page bounds and nonblank optional binding filters.
         *
         * @param origin optional nonblank binding-origin filter
         * @param role optional nonblank binding-role filter
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character; a present
         *     origin or role filter is blank
         */
        public ListAlgorithmBindings {
            after = requireCursor(after);
            origin = requireOptionalText(origin, "origin");
            role = requireOptionalText(role, "role");
            requireLimit(limit);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects one active X.509 algorithm binding.
     *
     * @param bindingId exact binding identifier
     */
    record InspectAlgorithmBinding(String bindingId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "algorithm.binding.inspect";
        /**
         * Requires a nonblank binding identifier without resolving the active registry.
         *
         * @param bindingId exact binding identifier
         * @throws IllegalArgumentException if the identifier is null or blank
         */
        public InspectAlgorithmBinding {
            requireText(bindingId, "bindingId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Validates the active binding registry and optionally one exact binding.
     *
     * @param bindingId optional exact binding identifier; empty validates the complete registry
     * @param expectedCommitment expected binding commitment, supplied together with the binding identifier
     */
    record ValidateAlgorithmBindings(Optional<String> bindingId, Optional<String> expectedCommitment)
            implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "algorithm.binding.validate";
        /**
         * Checks paired registry coordinates without comparing the expected commitment to a stored binding.
         *
         * @param bindingId optional exact binding identifier; empty validates the complete registry
         * @param expectedCommitment expected binding commitment, supplied together with the binding identifier
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the identifier and commitment are not supplied
         *     together, the identifier is blank or the commitment is not 1 through 512
         *     non-whitespace characters
         */
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
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Validates the opened session configuration.
     */
    record ValidateConfiguration() implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "configuration.validate";
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Validates one profile document without storing it.
     *
     * @param document non-null encoded profile document, defensively copied
     */
    record ValidateProfile(byte[] document) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "profile.validate";
        /**
         * Copies the supplied document without parsing or validating its profile semantics.
         *
         * @param document non-null encoded profile document, defensively copied
         * @throws NullPointerException if a required object or optional container is null
         */
        public ValidateProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }
        /**
         * Returns a defensive document copy.
         *
         * @return a defensive document copy
         */
        @Override
        public byte[] document() {
            return document.clone();
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Registers one profile document.
     *
     * @param document non-null encoded profile document, defensively copied
     */
    record RegisterProfile(byte[] document) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "profile.register";
        /**
         * Copies the supplied document without parsing or validating its profile semantics.
         *
         * @param document non-null encoded profile document, defensively copied
         * @throws NullPointerException if a required object or optional container is null
         */
        public RegisterProfile {
            document = Objects.requireNonNull(document, "document").clone();
        }
        /**
         * Returns a defensive document copy.
         *
         * @return a defensive document copy
         */
        @Override
        public byte[] document() {
            return document.clone();
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects one exact profile version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported profile version
     */
    record InspectProfile(String profileId, long profileVersion) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "profile.inspect";
        /**
         * Requires a nonblank profile identifier and positive version without loading the profile.
         *
         * @param profileId nonblank logical profile identifier
         * @param profileVersion positive imported profile version
         * @throws IllegalArgumentException if the profile identifier is null or blank, or the
         *     version is not positive
         */
        @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
        public InspectProfile {
            requireText(profileId, "profileId");
            if (profileVersion < 1L) {
                throw new IllegalArgumentException("profileVersion must be positive");
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists imported versions of one profile.
     *
     * @param profileId nonblank logical profile identifier
     */
    record ListProfileVersions(String profileId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "profile.list";
        /**
         * Requires a nonblank logical identifier without loading its version history.
         *
         * @param profileId nonblank logical profile identifier
         * @throws IllegalArgumentException if the identifier is null or blank
         */
        public ListProfileVersions {
            requireText(profileId, "profileId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Activates one imported profile version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported profile version
     */
    record ActivateProfile(String profileId, long profileVersion) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "profile.activate";
        /**
         * Checks the requested version coordinates without changing the active profile.
         *
         * @param profileId nonblank logical profile identifier
         * @param profileVersion positive imported profile version
         * @throws IllegalArgumentException if the profile identifier is null or blank, or the
         *     version is not positive
         */
        @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
        public ActivateProfile {
            requireText(profileId, "profileId");
            if (profileVersion < 1L) {
                throw new IllegalArgumentException("profileVersion must be positive");
            }
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "ca.inspect";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact non-null stored-object identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectAuthority {
            requireAuthority(caId);
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "credential.inspect";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param credentialId exact non-null stored-object identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectCredential {
            requireCredentialId(credentialId);
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects the metadata of one stored issuer generation through an authoritative point lookup.
     *
     * <p>Successful execution returns {@code issuerId}, {@code authorityId}, {@code credentialId}, {@code state},
     * {@code profilePolicyCommitment}, {@code x509BindingCommitment}, and {@code cryptographicBinding}.
     * The latter contains the stored version, commitment, certificateSha256,
     * certificateHybridBaseline, bindingSetCommitment, evidenceSha256 and outgoing
     * primary/optional alternative roles. Each role contains keyRef (never private
     * bytes), publicKeyAlgorithmId and signatureAlgorithmId in canonical identity
     * form, signatureAlgorithmIdentifierDer as unpadded base64url DER, and
     * subjectSpkiSha256. These describe outgoing signing roles, not the incoming
     * signatures on the issuer certificate. No current default is inferred.
     * A missing object or required stored cryptographic binding produces {@link
     * PkiOperationFailure#NOT_FOUND} with code
     * {@code OBJECT_NOT_FOUND}. The executor projects metadata without opening content,
     * signing, or durable admission; the store retains its existing integrity checks.</p>
     *
     * @param issuerId exact non-null stored-object identifier
     */
    record InspectIssuerGeneration(PkiId issuerId) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "issuer.generation.inspect";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param issuerId exact non-null stored-object identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectIssuerGeneration {
            Objects.requireNonNull(issuerId, "issuerId");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "issuer.path.inspect";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param pathId exact non-null stored-object identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectIssuerChainPath {
            Objects.requireNonNull(pathId, "pathId");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "status.inspect";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param statusObjectId exact non-null stored-object identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectStatus {
            Objects.requireNonNull(statusObjectId, "statusObjectId");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "ca.list";

        /**
         * Creates an immutable authority-list request.
         *
         * @param limit maximum returned authorities
         * @throws IllegalArgumentException if {@code limit} is outside 1 through 1000
         */
        public ListAuthorities(int limit) {
            this(limit, Optional.empty());
        }
        /**
         * Checks the page bounds without loading or validating authority records.
         *
         * @param limit maximum returned authorities, from 1 through 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListAuthorities {
            requireLimit(limit);
            after = requireCursor(after);
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "inventory.status";

        /**
         * Creates an immutable status-list request.
         *
         * @param issuerCaId exact issuer authority identifier
         * @param limit maximum returned status objects
         * @throws NullPointerException if {@code issuerCaId} is {@code null}
         * @throws IllegalArgumentException if {@code limit} is outside 1 through 1000
         */
        public ListStatus(PkiId issuerCaId, int limit) {
            this(issuerCaId, limit, Optional.empty());
        }
        /**
         * Checks the issuer scope and page bounds without reading status content.
         *
         * @param issuerCaId exact non-null issuer authority identifier
         * @param limit maximum returned status objects, from 1 through 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListStatus {
            after = requireCursor(after);
            Objects.requireNonNull(issuerCaId, "issuerCaId");
            requireLimit(limit);
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "issuer.path.list";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param issuerId exact non-null issuer-generation identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public ListIssuerChainPaths {
            Objects.requireNonNull(issuerId, "issuerId");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "ca.transition";

        /**
         * Requires the authority, target state and nonblank reason without changing stored state.
         *
         * @param caId exact non-null authority identifier
         * @param state requested non-null operational state
         * @param reason nonblank administrative reason
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the reason is null or blank
         */
        public TransitionAuthority {
            requireAuthority(caId);
            Objects.requireNonNull(state, "state");
            requireText(reason, "reason");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Selects an active issuer generation and matching chain path owned by one authority.
     *
     * <p>Construction checks the coordinate shape only, not membership, current
     * head equality or operator authority. Normalization freezes the selected head.
     * Changing a root anchor requires a matching retained candidate commitment and
     * distribution acknowledgment, followed by the dedicated durable activation
     * path; acknowledgment does not verify external trust-store installation.</p>
     *
     * <p>For ordinary same-anchor selection, the CA need not be active. One
     * conditional replacement preserves its state,
     * memberships and immutable base while selecting the generation, path and the
     * generation's signing key. Re-selecting the current coordinates still writes.
     * A concurrent change produces {@link PkiOperationFailure#CONFLICT} without retry.
     * Ordinary selection returns exactly {@code caId}, {@code issuerId} and
     * {@code pathId}; root activation returns its retained activation evidence.</p>
     *
     * @param caId exact non-null authority identifier
     * @param issuerId exact non-null member issuer-generation identifier
     * @param pathId exact non-null matching path identifier
     * @param reason nonblank administrative reason
     * @param expectedHead exact original selected head, empty only before normalization
     * @param transitionCommitment root candidate commitment, absent for ordinary same-anchor selection
     * @param distributionAcknowledged explicit operator acknowledgment, never external trust-store verification
     */
    record SelectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason,
            Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expectedHead, Optional<String> transitionCommitment,
            boolean distributionAcknowledged) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "issuer.path.select";

        /**
         * Checks coordinate shape without testing membership, current head equality or root-candidate admission.
         *
         * @param caId exact non-null authority identifier
         * @param issuerId exact non-null member issuer-generation identifier
         * @param pathId exact non-null matching path identifier
         * @param reason nonblank administrative reason
         * @param expectedHead exact original selected head, empty only before normalization
         * @param transitionCommitment root candidate commitment, absent for ordinary same-anchor selection
         * @param distributionAcknowledged explicit operator acknowledgment, never external trust-store verification
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the reason is null or blank, the commitment is not 64
         *     lowercase hexadecimal characters, or acknowledgment is supplied without a commitment
         */
        public SelectIssuancePath {
            requireAuthority(caId);
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(pathId, "pathId");
            requireText(reason, "reason");
            Objects.requireNonNull(expectedHead, "expectedHead");
            Objects.requireNonNull(transitionCommitment, "transitionCommitment");
            if (transitionCommitment.filter(value -> !value.matches("[0-9a-f]{64}")).isPresent()
                    || distributionAcknowledged && transitionCommitment.isEmpty()) {
                throw new IllegalArgumentException("Invalid root activation coordinates");
            }
        }

        /**
         * Preserves ordinary selection before head normalization; cannot activate a root candidate.
         * @param caId exact authority identifier
         * @param issuerId member issuer-generation identifier
         * @param pathId matching chain-path identifier
         * @param reason nonblank operator reason
         * @throws NullPointerException if an identifier is null
         * @throws IllegalArgumentException if the reason is null or blank
         */
        public SelectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason) {
            this(caId, issuerId, pathId, reason, Optional.empty(), Optional.empty(), false);
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "issuer.path.register";

        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact non-null authority identifier
         * @param issuerId exact non-null member generation identifier
         * @param parentPathId exact non-null immutable parent-path identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public RegisterIssuerChainPath {
            requireAuthority(caId);
            Objects.requireNonNull(issuerId, "issuerId");
            Objects.requireNonNull(parentPathId, "parentPathId");
        }

        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects one stored certification request.
     *
     * @param requestId exact stored certification-request identifier
     */
    record InspectRequest(PkiId requestId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "request.inspect";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param requestId exact stored certification-request identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectRequest {
            Objects.requireNonNull(requestId, "requestId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Imports one certification request.
     *
     * @param formatId credential framework format identifier
     * @param encoded encoded certification-request object
     */
    record ImportRequest(FormatId formatId, EncodedObject encoded) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "request.import";
        /**
         * Retains the required encoded request and format references without parsing or verifying possession.
         *
         * @param formatId credential framework format identifier
         * @param encoded encoded certification-request object
         * @throws NullPointerException if a required object or optional container is null
         */
        public ImportRequest {
            Objects.requireNonNull(formatId, "formatId");
            Objects.requireNonNull(encoded, "encoded");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Verifies proof of possession for one stored request.
     *
     * @param requestId exact stored certification-request identifier
     */
    record VerifyRequest(PkiId requestId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "request.verify";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param requestId exact stored certification-request identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public VerifyRequest {
            Objects.requireNonNull(requestId, "requestId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable name.
         */
        public static final String NAME = "credential.confirmation.pending.list";
        /**
         * Checks bounded UTF-8 scope identifiers, supported cutoff and page limit without querying pending reviews.
         *
         * @param authorityId exact authority identifier that scopes the query
         * @param profileId optional nonblank profile identifier limiting the query
         * @param cutoffInclusive inclusive UTC cutoff for pending confirmation deadlines
         * @param afterExclusive optional exclusive confirmation-review cursor
         * @param limit maximum number of returned entries, from 1 to 1000
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; an identifier is
         *     blank or not strict UTF-8 within 256 bytes, or the cutoff epoch second is outside 0
         *     through 253402300799
         */
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
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Issues or replays the proof challenge for one pending confirmation.
     *
     * @param credentialId exact stored credential identifier
     */
    record IssueCredentialConfirmationChallenge(PkiId credentialId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "credential.confirmation.challenge.issue";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param credentialId exact stored credential identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public IssueCredentialConfirmationChallenge {
            requireCredentialId(credentialId);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Completes one credential confirmation proof.
     *
     * @param submission non-null challenge response and proof submission
     */
    record CompleteCredentialConfirmationProof(CredentialConfirmationProofSubmission submission)
            implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "credential.confirmation.proof.complete";
        /**
         * Retains the required proof submission without verifying its challenge response.
         *
         * @param submission non-null challenge response and proof submission
         * @throws NullPointerException if a required object or optional container is null
         */
        public CompleteCredentialConfirmationProof {
            Objects.requireNonNull(submission, "submission");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Permanently revokes one still-pending non-public credential.
     *
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank administrative justification, at most 1024 UTF-8 bytes
     */
    record RevokePendingCredentialConfirmation(PkiId credentialId, Optional<String> operatorJustification)
            implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "credential.confirmation.pending.revoke";
        /**
         * Checks the credential and bounded justification without resolving pending confirmation state.
         *
         * @param credentialId exact stored credential identifier
         * @param operatorJustification optional nonblank administrative justification, at most 1024 UTF-8 bytes
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if a present justification is blank, invalid UTF-8 or
         *     longer than 1024 UTF-8 bytes
         */
        public RevokePendingCredentialConfirmation {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /**
         * Creates a revocation without justification.
         *
         * @param credentialId exact stored credential identifier
         */
        public RevokePendingCredentialConfirmation(PkiId credentialId) {
            this(credentialId, Optional.empty());
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Places one committed credential on temporary hold using the authoritative clock.
     * Permanent revocation cannot be replaced by a hold.
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank justification, at most 1024 UTF-8 bytes
     */
    record HoldCredential(PkiId credentialId, Optional<String> operatorJustification) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.hold";
        /**
         * Checks the credential and bounded justification without recording a hold.
         *
         * @param credentialId exact stored credential identifier
         * @param operatorJustification optional nonblank justification, at most 1024 UTF-8 bytes
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if a present justification is blank, invalid UTF-8 or
         *     longer than 1024 UTF-8 bytes
         */
        public HoldCredential {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /**
         * Creates a hold without justification.
         * @param credentialId exact stored credential identifier
         */
        public HoldCredential(PkiId credentialId) {
            this(credentialId, Optional.empty());
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Releases an existing temporary hold using the authoritative clock.
     * Permanent revocation is irreversible and is never released by this operation.
     * @param credentialId exact stored credential identifier
     * @param operatorJustification optional nonblank justification, at most 1024 UTF-8 bytes
     */
    record UnholdCredential(PkiId credentialId, Optional<String> operatorJustification) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "credential.unhold";
        /**
         * Checks the credential and bounded justification without releasing a hold.
         *
         * @param credentialId exact stored credential identifier
         * @param operatorJustification optional nonblank justification, at most 1024 UTF-8 bytes
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if a present justification is blank, invalid UTF-8 or
         *     longer than 1024 UTF-8 bytes
         */
        public UnholdCredential {
            requireCredentialId(credentialId);
            operatorJustification = boundedOptional(operatorJustification, "operatorJustification", 1_024);
        }
        /**
         * Creates a release without justification.
         * @param credentialId exact stored credential identifier
         */
        public UnholdCredential(PkiId credentialId) {
            this(credentialId, Optional.empty());
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Permanently revokes one committed credential.
     *
     * @param credentialId exact stored credential identifier
     * @param reason permanent revocation reason; hold and remove-from-CRL are rejected
     * @param operatorJustification optional nonblank administrative justification, at most 1024 UTF-8 bytes
     */
    record RevokeCredential(PkiId credentialId, RevocationReason reason, Optional<String> operatorJustification)
            implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "credential.revoke";
        /**
         * Checks the credential, permanent reason and bounded justification without recording revocation.
         *
         * @param credentialId exact stored credential identifier
         * @param reason permanent revocation reason; hold and remove-from-CRL are rejected
         * @param operatorJustification optional nonblank administrative justification, at most 1024 UTF-8 bytes
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if a present justification is blank, invalid UTF-8 or
         *     longer than 1024 UTF-8 bytes; the reason is certificate hold or remove-from-CRL
         */
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
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads a bounded prefix of one revocation history.
     *
     * @param credentialId exact stored credential identifier
     * @param limit maximum number of returned entries, from 1 to 1000
     */
    record ReadRevocationHistory(PkiId credentialId, int limit) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "revocation.history";
        /**
         * Checks the credential and result limit without loading revocation history.
         *
         * @param credentialId exact stored credential identifier
         * @param limit maximum number of returned entries, from 1 to 1000
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000
         */
        public ReadRevocationHistory {
            requireCredentialId(credentialId);
            requireLimit(limit);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects the current revocation state.
     *
     * @param credentialId exact stored credential identifier
     */
    record InspectRevocation(PkiId credentialId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "revocation.inspect";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param credentialId exact stored credential identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectRevocation {
            requireCredentialId(credentialId);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reads a bounded current-revocation snapshot.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     */
    record SnapshotRevocations(int limit) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "revocation.snapshot";
        /**
         * Checks the presentation limit without taking a revocation snapshot.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         * @throws IllegalArgumentException if the limit is outside 1 through 1000
         */
        public SnapshotRevocations {
            requireLimit(limit);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects one publication operation.
     *
     * @param publicationId exact publication operation identifier
     */
    record InspectPublication(PkiId publicationId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "publication.inspect";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param publicationId exact publication operation identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists publication operations.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive identifier cursor; empty starts the first page
     */
    record ListPublications(int limit, Optional<String> after) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "publication.list";
        /**
         * Validates the limit.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         */
        public ListPublications(int limit) {
            this(limit, Optional.empty());
        }
        /**
         * Checks the presentation limit and exclusive publication cursor without contacting a destination.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive identifier cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListPublications {
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable name.
         */
        public static final String NAME = "publication.register";
        /**
         * Retains required publication coordinates without resolving the source or contacting the destination.
         *
         * @param publicationId exact publication operation identifier
         * @param sourceType type of authoritative object to publish
         * @param sourceId exact identifier of the authoritative source object
         * @param target configured publication destination
         * @throws NullPointerException if a required object or optional container is null
         */
        public RegisterPublication {
            Objects.requireNonNull(publicationId, "publicationId");
            Objects.requireNonNull(sourceType, "sourceType");
            Objects.requireNonNull(sourceId, "sourceId");
            Objects.requireNonNull(target, "target");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Processes one pending publication.
     *
     * @param publicationId exact publication operation identifier
     */
    record ProcessPublication(PkiId publicationId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "publication.process";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param publicationId exact publication operation identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public ProcessPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Retries one eligible publication.
     *
     * @param publicationId exact publication operation identifier
     */
    record RetryPublication(PkiId publicationId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "publication.retry";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param publicationId exact publication operation identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public RetryPublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Reconciles one publication with an unknown external outcome.
     *
     * @param publicationId exact publication operation identifier
     */
    record ReconcilePublication(PkiId publicationId) implements PkiOperation {
        /**
         * Stable name.
         */
        public static final String NAME = "publication.reconcile";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param publicationId exact publication operation identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public ReconcilePublication {
            Objects.requireNonNull(publicationId, "publicationId");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
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
        /**
         * Stable operation name.
         */
        public static final String NAME = "status.schedule.set";
        /**
         * Checks interval, grace and executable-family constraints without registering or running a schedule.
         *
         * @param caId exact authority identifier
         * @param statusType kind of status object to generate
         * @param formatId encoding format for generated objects
         * @param interval positive generation interval (minimum PT1M)
         * @param graceSeconds non-negative grace seconds before the worker retries after {@code nextUpdate}
         * @param enabled whether automatic generation is active
         * @param publicationTarget optional publication destination; empty = generate only
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the interval is shorter than one minute, grace is
         *     negative or reaches the interval whole-second count, or an enabled schedule is not an
         *     X.509 full or delta CRL schedule
         */
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
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Inspects the generation schedule for one CA status family.
     *
     * @param caId exact authority identifier
     * @param statusType kind of status object
     */
    record InspectStatusSchedule(PkiId caId, StatusObjectType statusType) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "status.schedule.inspect";
        /**
         * Checks the authority and status-family coordinates without resolving a schedule.
         *
         * @param caId exact authority identifier
         * @param statusType kind of status object
         * @throws NullPointerException if a required object or optional container is null
         */
        public InspectStatusSchedule {
            requireAuthority(caId);
            Objects.requireNonNull(statusType, "statusType");
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Lists all configured generation schedules.
     *
     * @param limit maximum number of returned entries, from 1 to 1000
     * @param after optional exclusive cursor; empty starts the first page
     */
    record ListStatusSchedules(int limit, Optional<String> after) implements PkiOperation {
        /**
         * Stable operation name.
         */
        public static final String NAME = "status.schedule.list";
        /**
         * Creates the first page query.
         * @param limit maximum number of results, from 1 to 1000
         * @throws IllegalArgumentException if the limit is outside the supported range
         */
        public ListStatusSchedules(int limit) {
            this(limit, Optional.empty());
        }
        /**
         * Checks the presentation limit and exclusive schedule cursor without scheduling work.
         *
         * @param limit maximum number of returned entries, from 1 to 1000
         * @param after optional exclusive cursor; empty starts the first page
         * @throws NullPointerException if a required object or optional container is null
         * @throws IllegalArgumentException if the limit is outside 1 through 1000; a present cursor
         *     is blank, longer than 1024 characters or contains an ISO control character
         */
        public ListStatusSchedules {
            requireLimit(limit);
            after = requireCursor(after);
        }
        /**
         * {@inheritDoc}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Queries authority-inventory metrics for one CA: issuer-generation states,
     * chain depth, and CA lifecycle state.
     *
     * @param caId exact authority identifier
     */
    record QueryAuthorityMetrics(PkiId caId) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "dashboard.authority";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact authority identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public QueryAuthorityMetrics {
            requireAuthority(caId);
        }
        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Queries certificate-lifecycle metrics for one CA: active, expiring, and revoked counts.
     * Pending-request lifecycle measurement is explicitly unavailable because requests have
     * no authoritative CA lifecycle binding.
     *
     * @param caId exact authority identifier
     */
    record QueryCertificateMetrics(PkiId caId) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "dashboard.certificate";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact authority identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public QueryCertificateMetrics {
            requireAuthority(caId);
        }
        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Queries revocation and CRL freshness metrics for one CA.
     *
     * @param caId exact authority identifier
     */
    record QueryRevocationMetrics(PkiId caId) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "dashboard.revocation";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact authority identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public QueryRevocationMetrics {
            requireAuthority(caId);
        }
        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Queries publication-health metrics for one CA: pending and failing publication counts.
     *
     * @param caId exact authority identifier
     */
    record QueryPublicationMetrics(PkiId caId) implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "dashboard.publication";
        /**
         * Requires the exact lookup coordinates without resolving the stored object or evaluating the result.
         *
         * @param caId exact authority identifier
         * @throws NullPointerException if a required object or optional container is null
         */
        public QueryPublicationMetrics {
            requireAuthority(caId);
        }
        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
    }

    /**
     * Queries server-health and enrollment metrics: JVM heap, approval queue depth,
     * admin request totals, and audit-projection failure counts.
     */
    record QueryServerMetrics() implements PkiOperation {
        /**
         * Stable semantic operation name.
         */
        public static final String NAME = "dashboard.server";
        /**
         * Returns the stable semantic name {@value #NAME}.
         *
         * @return the stable semantic name {@value #NAME}
         */
        @Override
        public String name() {
            return NAME;
        }
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
