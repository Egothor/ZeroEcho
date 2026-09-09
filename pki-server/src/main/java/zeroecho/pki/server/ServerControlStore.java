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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Dedicated durable authority for finite server security and disclosure control
 * metadata.
 *
 * <p>All public operations are synchronized to serialize compare-and-replace
 * within one realm process. Cross-process exclusion and durability remain the
 * responsibility of the composed {@link TransactionalMetadataStore}. No PKI
 * certificate, CRL, CSR, key, secret, or unrestricted exception data is stored.</p>
 */
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity",
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.AvoidSynchronizedAtMethodLevel",
        "PMD.ControlStatementBraces", "PMD.PreserveStackTrace", "PMD.CloseResource",
        "PMD.UseEnumCollections", "PMD.CommentRequired", "PMD.UncommentedEmptyMethodBody",
        "PMD.TooManyMethods", "PMD.ExcessivePublicCount", "PMD.AvoidInstantiatingObjectsInLoops" })
public final class ServerControlStore implements AutoCloseable {
    /** Stable namespace for the realm record. */ public static final String REALM = "io.zeroecho.server.realm";
    /** Stable namespace for principals. */ public static final String PRINCIPAL = "io.zeroecho.server.principal";
    /** Stable namespace for scoped role assignments. */ public static final String ASSIGNMENT = "io.zeroecho.server.assignment";
    /** Stable namespace for direct permission grants. */ public static final String GRANT = "io.zeroecho.server.grant";
    /** Stable namespace for approvals. */ public static final String APPROVAL = "io.zeroecho.server.approval";
    /** Stable namespace for break-glass records. */ public static final String BREAK_GLASS = "io.zeroecho.server.break-glass";
    /** Stable namespace for disclosure records. */ public static final String DISCLOSURE = "io.zeroecho.server.disclosure";
    /** Stable namespace for capability commitments. */ public static final String CAPABILITY = "io.zeroecho.server.capability";
    /** Stable namespace for non-authoritative public repository aliases. */
    public static final String REPOSITORY_ALIAS = "io.zeroecho.server.repository-alias";
    /** Stable namespace for ACME directory records. */
    public static final String ACME_DIRECTORY = "io.zeroecho.server.acme-directory";
    /** Stable namespace for ACME account records. */
    public static final String ACME_ACCOUNT = "io.zeroecho.server.acme-account";
    /** Stable namespace for ACME order records. */
    public static final String ACME_ORDER = "io.zeroecho.server.acme-order";
    /** Stable namespace for ACME authorization records. */
    public static final String ACME_AUTHORIZATION = "io.zeroecho.server.acme-authorization";
    /** Stable namespace for ACME challenge records. */
    public static final String ACME_CHALLENGE = "io.zeroecho.server.acme-challenge";
    /** Stable namespace for ACME validation-evidence records. */
    public static final String ACME_EVIDENCE = "io.zeroecho.server.acme-evidence";
    /** Stable namespace for durable OCSP responder bindings. */
    public static final String OCSP_RESPONDER = "io.zeroecho.server.ocsp-responder";
    /** Stable namespace for non-authoritative revocation-audit projection state. */
    public static final String REVOCATION_AUDIT_PROJECTION =
            "io.zeroecho.server.revocation-audit-projection";
    /** Stable namespace for the durable cross-store audit-log integrity anchor. */
    public static final String AUDIT_ANCHOR = "io.zeroecho.server.audit-anchor";
    /** Stable namespace for per-family success-evidence audit-projection cursors. */
    public static final String AUDIT_EVIDENCE_PROJECTION = "io.zeroecho.server.audit-evidence-projection";

    private static final int MAGIC = 0x5a455331;
    private static final int SCHEMA = 6;
    private static final int MAXIMUM_RECORD_BYTES = 1_048_576;
    private static final int MAXIMUM_STRING_BYTES = 16_384;
    private static final int MAXIMUM_COLLECTION = 4_096;
    private static final int KIND_REALM = 1;
    private static final int KIND_PRINCIPAL = 2;
    private static final int KIND_ASSIGNMENT = 3;
    private static final int KIND_GRANT = 4;
    private static final int KIND_APPROVAL = 5;
    private static final int KIND_BREAK_GLASS = 6;
    private static final int KIND_DISCLOSURE = 7;
    private static final int KIND_CAPABILITY = 8;
    private static final int KIND_REPOSITORY_ALIAS = 9;
    private static final int KIND_PROTOCOL = 10;

    /**
     * Strict opaque protocol payload framed by the server-control authority.
     *
     * <p>The owning closed protocol codec owns the payload schema. This record keeps the
     * transactional metadata layer independent of protocol classes while still
     * enforcing canonical key identity and bounded content.</p>
     *
     * @param namespace one closed protocol namespace
     * @param recordId canonical domain identity
     * @param commitment SHA-256 commitment of the complete domain payload
     * @param payload strict versioned protocol-domain encoding
     */
    public record ProtocolRecord(String namespace, String recordId, String commitment, byte[] payload) {
        /** Validates namespace, identity, commitment, and defensive payload bounds. */
        public ProtocolRecord {
            if (!PROTOCOL_NAMESPACES.contains(namespace)) {
                throw new IllegalArgumentException("Unknown protocol control namespace");
            }
            Permission.requireId(recordId, "protocol record");
            requireDigest(commitment);
            payload = Objects.requireNonNull(payload, "payload").clone();
            if (payload.length == 0 || payload.length > MAXIMUM_RECORD_BYTES / 2) {
                throw new IllegalArgumentException("Protocol control payload bound is invalid");
            }
        }

        /**
         * Returns the protocol payload.
         *
         * @return defensive copy of the bounded payload
         */
        @Override public byte[] payload() { return payload.clone(); }
    }

    private static final Set<String> PROTOCOL_NAMESPACES = Set.of(ACME_DIRECTORY, ACME_ACCOUNT, ACME_ORDER,
            ACME_AUTHORIZATION, ACME_CHALLENGE, ACME_EVIDENCE, OCSP_RESPONDER,
            REVOCATION_AUDIT_PROJECTION, AUDIT_ANCHOR, AUDIT_EVIDENCE_PROJECTION);

    /**
     * Durable realm-control identity and commitments.
     *
     * @param realmId realm identity
     * @param displayName safe administrative display name
     * @param exposure authority exposure policy
     * @param authorizationCommitment authorization configuration commitment
     * @param approvalCommitment HIGH_RISK approval-policy commitment
     * @param extendedApprovalCommitment commitment over all non-HIGH_RISK approval policies
     *        (canonical digest of the category-sorted map; the empty-map digest when none are configured)
     * @param disclosureCommitment disclosure-default commitment
     * @param controlStoreId exact metadata-store identity
     */
    public record RealmRecord(RealmId realmId, String displayName, AuthorityExposurePolicy exposure,
            String authorizationCommitment, String approvalCommitment, String extendedApprovalCommitment,
            String disclosureCommitment, MetadataStoreId controlStoreId) {
        /** Validates finite realm control metadata. */
        public RealmRecord {
            Objects.requireNonNull(realmId, "realmId");
            Permission.requireBounded(displayName, 256, "realm display name");
            Objects.requireNonNull(exposure, "exposure");
            requireDigest(authorizationCommitment);
            requireDigest(approvalCommitment);
            requireDigest(extendedApprovalCommitment);
            requireDigest(disclosureCommitment);
            Objects.requireNonNull(controlStoreId, "controlStoreId");
        }
    }

    private final TransactionalMetadataStore metadata;
    private boolean closed;

    /**
     * Creates a server-control adapter over one exclusively owned metadata store.
     *
     * @param metadata lifecycle-owned metadata authority
     */
    public ServerControlStore(TransactionalMetadataStore metadata) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
    }

    /**
     * Returns the durable server-control metadata-store identity.
     *
     * @return durable metadata-store identity
     * @throws IllegalStateException if this adapter is closed
     */
    public synchronized MetadataStoreId id() {
        requireOpen();
        return metadata.id();
    }

    /**
     * Creates or validates the sole realm identity record.
     *
     * @param expected expected immutable realm record
     * @return existing or newly created exact realm record
     */
    public synchronized RealmRecord ensureRealm(RealmRecord expected) {
        Objects.requireNonNull(expected, "expected");
        List<RealmRecord> existing = scan(REALM, KIND_REALM, ServerControlStore::readRealm);
        if (existing.isEmpty()) {
            create(REALM, expected.realmId().value(), output -> writeRealm(output, expected));
            return expected;
        }
        if (existing.size() != 1 || !existing.getFirst().equals(expected)) {
            throw new IllegalStateException("Persisted realm control identity or commitment differs");
        }
        return existing.getFirst();
    }

    /**
     * Creates one principal.
     *
     * @param value validated record to create
     */
    public synchronized void createPrincipal(SecurityPrincipal value) {
        create(PRINCIPAL, value.principalId(), output -> writePrincipal(output, value));
    }

    /**
     * Replaces one exact principal.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replacePrincipal(SecurityPrincipal current, SecurityPrincipal updated) {
        requireSame(current.principalId(), updated.principalId());
        replace(PRINCIPAL, current.principalId(), output -> writePrincipal(output, updated));
    }

    /**
     * Returns one principal or fails without revealing storage details.
     *
     * @param principalId stable principal identifier
     * @return exact principal
     */
    public synchronized SecurityPrincipal requirePrincipal(String principalId) {
        return read(PRINCIPAL, principalId, KIND_PRINCIPAL, ServerControlStore::readPrincipal)
                .orElseThrow(() -> new IllegalArgumentException("Principal is unavailable"));
    }

    /**
     * Returns a bounded stable page of principals in metadata-key order.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded principal page
     */
    public synchronized Page<SecurityPrincipal> principals(int offset, int limit) {
        return scanPage(PRINCIPAL, KIND_PRINCIPAL, ServerControlStore::readPrincipal, offset, limit);
    }

    /**
     * Creates one scoped role assignment.
     *
     * @param value validated record to create
     */
    public synchronized void createAssignment(RoleTemplateCatalog.Assignment value) {
        create(ASSIGNMENT, value.assignmentId(), output -> writeAssignment(output, value));
    }

    /**
     * Returns one role assignment.
     *
     * @param assignmentId stable role-assignment identifier
     * @return exact role assignment
     */
    public synchronized RoleTemplateCatalog.Assignment requireAssignment(String assignmentId) {
        return read(ASSIGNMENT, assignmentId, KIND_ASSIGNMENT, ServerControlStore::readAssignment)
                .orElseThrow(() -> new IllegalArgumentException("Role assignment is unavailable"));
    }

    /**
     * Replaces one exact role assignment.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceAssignment(RoleTemplateCatalog.Assignment current,
            RoleTemplateCatalog.Assignment updated) {
        requireSame(current.assignmentId(), updated.assignmentId());
        replace(ASSIGNMENT, current.assignmentId(), output -> writeAssignment(output, updated));
    }

    /**
     * Returns a bounded stable page of role assignments.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded role-assignment page
     */
    public synchronized Page<RoleTemplateCatalog.Assignment> assignments(int offset, int limit) {
        return scanPage(ASSIGNMENT, KIND_ASSIGNMENT, ServerControlStore::readAssignment, offset, limit);
    }

    /**
     * Lists assignments for one principal from one stable metadata snapshot.
     *
     * @param principalId stable principal identifier
     * @return immutable assignments for the principal
     */
    public synchronized List<RoleTemplateCatalog.Assignment> assignmentsFor(String principalId) {
        return scan(ASSIGNMENT, KIND_ASSIGNMENT, ServerControlStore::readAssignment).stream()
                .filter(item -> item.principalId().equals(principalId)).toList();
    }

    /**
     * Creates one direct grant.
     *
     * @param value validated record to create
     */
    public synchronized void createGrant(Permission.Grant value) {
        create(GRANT, value.grantId(), output -> writeGrant(output, value));
    }

    /**
     * Returns one direct grant.
     *
     * @param grantId stable grant identifier
     * @return exact permission grant
     */
    public synchronized Permission.Grant requireGrant(String grantId) {
        return read(GRANT, grantId, KIND_GRANT, ServerControlStore::readGrant)
                .orElseThrow(() -> new IllegalArgumentException("Permission grant is unavailable"));
    }

    /**
     * Returns a bounded stable page of direct grants.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded grant page
     */
    public synchronized Page<Permission.Grant> grants(int offset, int limit) {
        return scanPage(GRANT, KIND_GRANT, ServerControlStore::readGrant, offset, limit);
    }

    /**
     * Replaces one direct grant.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceGrant(Permission.Grant current, Permission.Grant updated) {
        requireSame(current.grantId(), updated.grantId());
        replace(GRANT, current.grantId(), output -> writeGrant(output, updated));
    }

    /**
     * Lists direct grants for one principal from one stable snapshot.
     *
     * @param principalId stable principal identifier
     * @return immutable direct grants for the principal
     */
    public synchronized List<Permission.Grant> grantsFor(String principalId) {
        return scan(GRANT, KIND_GRANT, ServerControlStore::readGrant).stream()
                .filter(item -> item.principalId().equals(principalId)).toList();
    }

    /**
     * Creates one approval request.
     *
     * @param value validated record to create
     */
    public synchronized void createApproval(ApprovalService.Request value) {
        create(APPROVAL, value.approvalId(), output -> writeApproval(output, value));
    }

    /**
     * Replaces one approval request through compare-and-replace.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceApproval(ApprovalService.Request current, ApprovalService.Request updated) {
        requireSame(current.approvalId(), updated.approvalId());
        replace(APPROVAL, current.approvalId(), output -> writeApproval(output, updated));
    }

    /**
     * Returns one approval request.
     *
     * @param approvalId stable approval identifier
     * @return exact approval request
     */
    public synchronized ApprovalService.Request requireApproval(String approvalId) {
        return read(APPROVAL, approvalId, KIND_APPROVAL, ServerControlStore::readApproval)
                .orElseThrow(() -> new IllegalArgumentException("Approval is unavailable"));
    }

    /**
     * Returns a bounded stable page of approval records.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded approval page
     */
    public synchronized Page<ApprovalService.Request> approvals(int offset, int limit) {
        return scanPage(APPROVAL, KIND_APPROVAL, ServerControlStore::readApproval, offset, limit);
    }

    /**
     * Creates one break-glass record.
     *
     * @param value validated record to create
     */
    public synchronized void createBreakGlass(BreakGlassService.Record value) {
        create(BREAK_GLASS, value.breakGlassId(), output -> writeBreakGlass(output, value));
    }

    /**
     * Replaces one break-glass record.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceBreakGlass(BreakGlassService.Record current, BreakGlassService.Record updated) {
        requireSame(current.breakGlassId(), updated.breakGlassId());
        replace(BREAK_GLASS, current.breakGlassId(), output -> writeBreakGlass(output, updated));
    }

    /**
     * Returns one break-glass record.
     *
     * @param breakGlassId stable break-glass identifier
     * @return exact break-glass record
     */
    public synchronized BreakGlassService.Record requireBreakGlass(String breakGlassId) {
        return read(BREAK_GLASS, breakGlassId, KIND_BREAK_GLASS, ServerControlStore::readBreakGlass)
                .orElseThrow(() -> new IllegalArgumentException("Break-glass record is unavailable"));
    }

    /**
     * Lists break-glass records for one principal.
     *
     * @param principalId stable principal identifier
     * @return immutable break-glass records for the principal
     */
    public synchronized List<BreakGlassService.Record> breakGlassFor(String principalId) {
        return scan(BREAK_GLASS, KIND_BREAK_GLASS, ServerControlStore::readBreakGlass).stream()
                .filter(item -> item.principalId().equals(principalId)).toList();
    }

    /**
     * Returns a bounded stable page of break-glass records.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded break-glass page
     */
    public synchronized Page<BreakGlassService.Record> breakGlass(int offset, int limit) {
        return scanPage(BREAK_GLASS, KIND_BREAK_GLASS, ServerControlStore::readBreakGlass, offset, limit);
    }

    /**
     * Creates one disclosure record.
     *
     * @param value validated record to create
     */
    public synchronized void createDisclosure(DisclosureService.Record value) {
        create(DISCLOSURE, value.objectId().value(), output -> writeDisclosure(output, value));
    }

    /**
     * Replaces one disclosure record.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceDisclosure(DisclosureService.Record current, DisclosureService.Record updated) {
        requireSame(current.objectId().value(), updated.objectId().value());
        replace(DISCLOSURE, current.objectId().value(), output -> writeDisclosure(output, updated));
    }

    /**
     * Returns one disclosure record.
     *
     * @param objectId exact protected object identifier
     * @return exact disclosure record
     */
    public synchronized DisclosureService.Record requireDisclosure(PkiId objectId) {
        return read(DISCLOSURE, objectId.value(), KIND_DISCLOSURE, ServerControlStore::readDisclosure)
                .orElseThrow(() -> new IllegalArgumentException("Disclosure record is unavailable"));
    }

    /**
     * Finds one disclosure record without converting absence into an error.
     *
     * @param objectId exact protected object identifier
     * @return matching record or empty
     */
    public synchronized Optional<DisclosureService.Record> findDisclosure(PkiId objectId) {
        return read(DISCLOSURE, objectId.value(), KIND_DISCLOSURE, ServerControlStore::readDisclosure);
    }

    /**
     * Returns a bounded stable page of disclosure records.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded disclosure page
     */
    public synchronized Page<DisclosureService.Record> disclosures(int offset, int limit) {
        return scanPage(DISCLOSURE, KIND_DISCLOSURE, ServerControlStore::readDisclosure, offset, limit);
    }

    /**
     * Creates one commitment-only capability record.
     *
     * @param value validated record to create
     */
    public synchronized void createCapability(DisclosureService.Capability value) {
        create(CAPABILITY, value.capabilityId(), output -> writeCapability(output, value));
    }

    /**
     * Replaces one capability record.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     */
    public synchronized void replaceCapability(DisclosureService.Capability current,
            DisclosureService.Capability updated) {
        requireSame(current.capabilityId(), updated.capabilityId());
        replace(CAPABILITY, current.capabilityId(), output -> writeCapability(output, updated));
    }

    /**
     * Returns one capability record.
     *
     * @param capabilityId stable capability identifier
     * @return exact capability metadata
     */
    public synchronized DisclosureService.Capability requireCapability(String capabilityId) {
        return read(CAPABILITY, capabilityId, KIND_CAPABILITY, ServerControlStore::readCapability)
                .orElseThrow(() -> new IllegalArgumentException("Capability is unavailable"));
    }

    /**
     * Finite page returned without materializing the complete namespace.
     *
     * @param <T> record type
     * @param values immutable page values
     * @param nextOffset offset for the next page
     * @param hasMore whether another page may contain values
     */
    public record Page<T>(List<T> values, int nextOffset, boolean hasMore) {
        /** Snapshots the bounded page. */
        public Page {
            values = List.copyOf(Objects.requireNonNull(values, "values"));
            if (nextOffset < 0) throw new IllegalArgumentException("Next offset is negative");
        }
    }

    /**
     * One compare-and-set mutation participating in an atomic protocol-state change.
     *
     * @param record replacement protocol record
     * @param expectedCommitment empty for create-only, otherwise the required current commitment
     */
    public record ProtocolMutation(ProtocolRecord record, Optional<String> expectedCommitment) {
        /** Validates the immutable mutation request. */
        public ProtocolMutation {
            Objects.requireNonNull(record, "record");
            expectedCommitment = Objects.requireNonNull(expectedCommitment, "expectedCommitment");
            expectedCommitment.ifPresent(ServerControlStore::requireDigest);
        }
    }

    /**
     * Reads one exact protocol record from its closed namespace.
     *
     * @param namespace closed protocol namespace
     * @param recordId canonical protocol record identifier
     * @return matching protocol record or empty
     */
    public synchronized Optional<ProtocolRecord> protocolRecord(String namespace, String recordId) {
        requireProtocolNamespace(namespace);
        return read(namespace, recordId, KIND_PROTOCOL, input -> readProtocol(input, namespace));
    }

    /**
     * Returns one bounded deterministic page of protocol records.
     *
     * @param namespace closed protocol namespace
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded protocol-record page
     */
    public synchronized Page<ProtocolRecord> protocolRecords(String namespace, int offset, int limit) {
        requireProtocolNamespace(namespace);
        return scanPage(namespace, KIND_PROTOCOL, input -> readProtocol(input, namespace), offset, limit);
    }

    /**
     * Atomically creates or compare-and-replaces a finite set of protocol records.
     * Empty expected commitments mean create-only; present commitments mean exact
     * compare-and-replace. Provider I/O and PKI operations must occur outside this
     * method.
     *
     * @param requested finite nonempty atomic mutation set
     */
    public synchronized void mutateProtocol(List<ProtocolMutation> requested) {
        requireOpen();
        List<ProtocolMutation> mutations = List.copyOf(Objects.requireNonNull(requested, "requested"));
        if (mutations.isEmpty() || mutations.size() > 256) {
            throw new IllegalArgumentException("Protocol transaction size is invalid");
        }
        Set<String> keys = new HashSet<>();
        if (mutations.stream().anyMatch(item -> !keys.add(item.record().namespace() + '\n'
                + item.record().recordId()))) {
            throw new IllegalArgumentException("Duplicate protocol transaction identity");
        }
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataTransaction transaction = metadata.beginTransaction()) {
            for (ProtocolMutation mutation : mutations) {
                ProtocolRecord value = mutation.record();
                MetadataKey metadataKey = key(value.namespace(), value.recordId());
                Optional<MetadataSnapshot.Record> existing = snapshot.get(metadataKey);
                byte[] encoded = encode(output -> writeProtocol(output, value));
                RepeatableContent content = new ByteContent(encoded);
                if (mutation.expectedCommitment().isEmpty()) {
                    if (existing.isPresent()) throw new IllegalStateException("Protocol record already exists");
                    transaction.create(metadataKey, content, CancellationSignal.NONE);
                } else {
                    MetadataSnapshot.Record current = existing
                            .orElseThrow(() -> new IllegalStateException("Protocol record is unavailable"));
                    ProtocolRecord decoded = decode(current, KIND_PROTOCOL,
                            input -> readProtocol(input, value.namespace()));
                    if (!mutation.expectedCommitment().orElseThrow().equals(decoded.commitment())) {
                        throw new IllegalStateException("Protocol record commitment conflict");
                    }
                    transaction.replace(metadataKey, current.recordRevision(), content, CancellationSignal.NONE);
                }
            }
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                throw new IllegalStateException("Protocol metadata commit requires reconciliation");
            }
        } catch (IOException failure) {
            throw new IllegalStateException("Protocol metadata mutation failed");
        }
    }

    /**
     * Lists capability commitments bound to one object.
     *
     * @param objectId exact protected object identifier
     * @return immutable capability metadata for the object
     */
    public synchronized List<DisclosureService.Capability> capabilitiesFor(PkiId objectId) {
        return scan(CAPABILITY, KIND_CAPABILITY, ServerControlStore::readCapability).stream()
                .filter(item -> item.objectId().equals(objectId)).toList();
    }

    /**
     * Creates one exact repository alias record.
     *
     * @param value validated record to create
     */
    public synchronized void createRepositoryAlias(RepositoryAliasService.Record value) {
        create(REPOSITORY_ALIAS, value.aliasId(), output -> writeRepositoryAlias(output, value));
    }

    /**
     * Finds one exact repository alias record.
     *
     * @param aliasId stable repository-alias identifier
     * @return matching alias or empty
     */
    public synchronized Optional<RepositoryAliasService.Record> findRepositoryAlias(String aliasId) {
        return read(REPOSITORY_ALIAS, aliasId, KIND_REPOSITORY_ALIAS, ServerControlStore::readRepositoryAlias);
    }

    /**
     * Returns one exact repository alias record.
     *
     * @param aliasId stable repository-alias identifier
     * @return exact alias record
     */
    public synchronized RepositoryAliasService.Record requireRepositoryAlias(String aliasId) {
        return findRepositoryAlias(aliasId)
                .orElseThrow(() -> new IllegalArgumentException("Repository alias is unavailable"));
    }

    /**
     * Atomically replaces an alias after exact expected-current validation.
     *
     * @param current caller-observed current record
     * @param updated replacement record with the same identity
     * @param expectedCurrentCommitment optional expected current record commitment
     */
    public synchronized void replaceRepositoryAlias(RepositoryAliasService.Record current,
            RepositoryAliasService.Record updated, Optional<String> expectedCurrentCommitment) {
        requireSame(current.aliasId(), updated.aliasId());
        RepositoryAliasService.Record authoritative = requireRepositoryAlias(current.aliasId());
        if (!authoritative.equals(current)) {
            throw new IllegalStateException("Repository alias changed concurrently");
        }
        if (expectedCurrentCommitment.isPresent()
                && !expectedCurrentCommitment.orElseThrow().equals(current.recordCommitment())) {
            throw new IllegalStateException("Repository alias expected-current commitment differs");
        }
        replace(REPOSITORY_ALIAS, current.aliasId(), output -> writeRepositoryAlias(output, updated));
    }

    /**
     * Returns a bounded repository alias page.
     *
     * @param offset zero-based page offset
     * @param limit positive page-size limit
     * @return bounded repository-alias page
     */
    public synchronized Page<RepositoryAliasService.Record> repositoryAliases(int offset, int limit) {
        return scanPage(REPOSITORY_ALIAS, KIND_REPOSITORY_ALIAS, ServerControlStore::readRepositoryAlias,
                offset, limit);
    }

    /**
     * Strictly decodes and cross-checks every authoritative control record from
     * stable metadata snapshots before the realm is exposed.
     */
    public synchronized void validateAll() {
        scan(REALM, KIND_REALM, ServerControlStore::readRealm);
        scan(PRINCIPAL, KIND_PRINCIPAL, ServerControlStore::readPrincipal);
        scan(ASSIGNMENT, KIND_ASSIGNMENT, ServerControlStore::readAssignment);
        scan(GRANT, KIND_GRANT, ServerControlStore::readGrant);
        scan(APPROVAL, KIND_APPROVAL, ServerControlStore::readApproval);
        scan(BREAK_GLASS, KIND_BREAK_GLASS, ServerControlStore::readBreakGlass);
        scan(DISCLOSURE, KIND_DISCLOSURE, ServerControlStore::readDisclosure);
        scan(CAPABILITY, KIND_CAPABILITY, ServerControlStore::readCapability);
        scan(REPOSITORY_ALIAS, KIND_REPOSITORY_ALIAS, ServerControlStore::readRepositoryAlias);
        for (String namespace : PROTOCOL_NAMESPACES) {
            scan(namespace, KIND_PROTOCOL, input -> readProtocol(input, namespace));
        }
    }

    /**
     * Validates durable relationships against the active strict role catalog.
     *
     * @param roles active strict role-template catalog
     */
    public synchronized void validateReferences(RoleTemplateCatalog roles) {
        Objects.requireNonNull(roles, "roles");
        Set<String> principals = scan(PRINCIPAL, KIND_PRINCIPAL, ServerControlStore::readPrincipal).stream()
                .map(SecurityPrincipal::principalId).collect(java.util.stream.Collectors.toUnmodifiableSet());
        for (RoleTemplateCatalog.Assignment assignment
                : scan(ASSIGNMENT, KIND_ASSIGNMENT, ServerControlStore::readAssignment)) {
            requirePrincipalReference(principals, assignment.principalId());
            roles.instantiate(assignment);
        }
        for (Permission.Grant grant : scan(GRANT, KIND_GRANT, ServerControlStore::readGrant)) {
            requirePrincipalReference(principals, grant.principalId());
        }
        for (BreakGlassService.Record record
                : scan(BREAK_GLASS, KIND_BREAK_GLASS, ServerControlStore::readBreakGlass)) {
            requirePrincipalReference(principals, record.principalId());
            requirePrincipalReference(principals, record.issuerPrincipalId());
        }
        for (ApprovalService.Request request
                : scan(APPROVAL, KIND_APPROVAL, ServerControlStore::readApproval)) {
            requirePrincipalReference(principals, request.requesterPrincipalId());
            request.decisions().forEach(decision -> requirePrincipalReference(principals, decision.principalId()));
        }
        for (DisclosureService.Record record
                : scan(DISCLOSURE, KIND_DISCLOSURE, ServerControlStore::readDisclosure)) {
            record.ownerPrincipalId().ifPresent(owner -> requirePrincipalReference(principals, owner));
        }
        for (DisclosureService.Capability capability
                : scan(CAPABILITY, KIND_CAPABILITY, ServerControlStore::readCapability)) {
            requirePrincipalReference(principals, capability.issuerPrincipalId());
        }
        for (RepositoryAliasService.Record alias
                : scan(REPOSITORY_ALIAS, KIND_REPOSITORY_ALIAS, ServerControlStore::readRepositoryAlias)) {
            requirePrincipalReference(principals, alias.actorPrincipalId());
        }
    }

    /** Opens no sidecar authority and closes the sole metadata authority idempotently. */
    @Override
    public synchronized void close() throws IOException {
        if (!closed) {
            closed = true;
            metadata.close();
        }
    }

    private <T> Optional<T> read(String namespace, String identity, int kind, Decoder<T> decoder) {
        requireOpen();
        MetadataKey key = key(namespace, identity);
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            Optional<MetadataSnapshot.Record> record = snapshot.get(key);
            if (record.isEmpty()) return Optional.empty();
            T decoded = decode(record.orElseThrow(), kind, decoder);
            requireSame(identity, identityOf(decoded));
            return Optional.of(decoded);
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata read failed");
        }
    }

    private <T> List<T> scan(String namespace, int kind, Decoder<T> decoder) {
        requireOpen();
        List<T> values = new ArrayList<>();
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace),
                        CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                MetadataSnapshot.Record record = next.orElseThrow();
                T decoded = decode(record, kind, decoder);
                if (!record.key().equals(key(namespace, identityOf(decoded)))) {
                    throw new IllegalStateException("Server-control metadata key mismatch");
                }
                values.add(decoded);
                if (values.size() > MAXIMUM_COLLECTION) {
                    throw new IllegalStateException("Server-control metadata population exceeds technical bound");
                }
            }
            return List.copyOf(values);
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata scan failed");
        }
    }

    private <T> Page<T> scanPage(String namespace, int kind, Decoder<T> decoder, int offset, int limit) {
        requireOpen();
        if (offset < 0 || limit <= 0 || limit > 256) {
            throw new IllegalArgumentException("Control page bounds are invalid");
        }
        List<T> values = new ArrayList<>(limit);
        int seen = 0;
        boolean more = false;
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace),
                        CancellationSignal.NONE)) {
            Optional<MetadataSnapshot.Record> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                MetadataSnapshot.Record record = next.orElseThrow();
                T decoded = decode(record, kind, decoder);
                if (!record.key().equals(key(namespace, identityOf(decoded)))) {
                    throw new IllegalStateException("Server-control metadata key mismatch");
                }
                if (seen++ < offset) continue;
                if (values.size() == limit) { more = true; break; }
                values.add(decoded);
            }
            return new Page<>(values, Math.addExact(offset, values.size()), more);
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata scan failed");
        }
    }

    private void create(String namespace, String identity, Encoder encoder) {
        mutate(namespace, identity, true, encoder);
    }

    private void replace(String namespace, String identity, Encoder encoder) {
        mutate(namespace, identity, false, encoder);
    }

    private void mutate(String namespace, String identity, boolean create, Encoder encoder) {
        requireOpen();
        byte[] value = encode(encoder);
        MetadataKey key = key(namespace, identity);
        try (MetadataSnapshot snapshot = metadata.snapshot(); MetadataTransaction transaction = metadata.beginTransaction();
                RepeatableContent content = new ByteContent(value)) {
            Optional<MetadataSnapshot.Record> existing = snapshot.get(key);
            if (create) {
                if (existing.isPresent()) throw new IllegalStateException("Server-control record already exists");
                transaction.create(key, content, CancellationSignal.NONE);
            } else {
                MetadataSnapshot.Record record = existing
                        .orElseThrow(() -> new IllegalStateException("Server-control record is unavailable"));
                transaction.replace(key, record.recordRevision(), content, CancellationSignal.NONE);
            }
            MetadataCommitResult result = transaction.commit();
            if (result.outcome() != MetadataCommitResult.Outcome.COMMITTED) {
                throw new IllegalStateException("Server-control metadata commit was not confirmed");
            }
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata mutation failed");
        }
    }

    private static byte[] encode(Encoder encoder) {
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(); DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(MAGIC);
            output.writeInt(SCHEMA);
            encoder.write(output);
            output.flush();
            byte[] result = bytes.toByteArray();
            if (result.length > MAXIMUM_RECORD_BYTES) throw new IllegalArgumentException("Control record too large");
            return result;
        } catch (IOException impossible) {
            throw new IllegalStateException("In-memory control encoding failed", impossible);
        }
    }

    private static <T> T decode(RepeatableContent content, int expectedKind, Decoder<T> decoder) throws IOException {
        try (InputStream stream = content.openStream()) {
            byte[] bytes = stream.readNBytes(MAXIMUM_RECORD_BYTES + 1);
            if (bytes.length > MAXIMUM_RECORD_BYTES || stream.read() != -1) {
                throw new IllegalArgumentException("Control record exceeds its technical bound");
            }
            try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != MAGIC || input.readInt() != SCHEMA || input.readInt() != expectedKind) {
                    throw new IllegalArgumentException("Control record framing or kind is invalid");
                }
                T result = decoder.read(input);
                if (input.read() != -1) throw new IllegalArgumentException("Trailing control record input");
                return result;
            }
        }
    }

    private static MetadataKey key(String namespace, String identity) {
        return new MetadataKey(namespace, digest(identity));
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static String identityOf(Object value) {
        return switch (value) {
            case RealmRecord item -> item.realmId().value();
            case SecurityPrincipal item -> item.principalId();
            case RoleTemplateCatalog.Assignment item -> item.assignmentId();
            case Permission.Grant item -> item.grantId();
            case ApprovalService.Request item -> item.approvalId();
            case BreakGlassService.Record item -> item.breakGlassId();
            case DisclosureService.Record item -> item.objectId().value();
            case DisclosureService.Capability item -> item.capabilityId();
            case RepositoryAliasService.Record item -> item.aliasId();
            case ProtocolRecord item -> item.recordId();
            default -> throw new IllegalArgumentException("Unsupported control record type");
        };
    }

    private static void requireProtocolNamespace(String namespace) {
        if (!PROTOCOL_NAMESPACES.contains(namespace)) {
            throw new IllegalArgumentException("Unknown protocol control namespace");
        }
    }

    private static void requireSame(String first, String second) {
        if (!Objects.equals(first, second)) throw new IllegalArgumentException("Control record identity mismatch");
    }

    private static void requirePrincipalReference(Set<String> principals, String principalId) {
        if (!principals.contains(principalId)) {
            throw new IllegalStateException("Server-control record references an unavailable principal");
        }
    }

    private void requireOpen() {
        if (closed) throw new IllegalStateException("Server-control store is closed");
    }

    private static void writeRealm(DataOutputStream out, RealmRecord value) throws IOException {
        out.writeInt(KIND_REALM); writeString(out, value.realmId().value()); writeString(out, value.displayName());
        out.writeInt(value.exposure().mode().code()); out.writeBoolean(value.exposure().authorityCreationPermitted());
        writePkiSet(out, value.exposure().authorityIds()); writeString(out, value.authorizationCommitment());
        writeString(out, value.approvalCommitment()); writeString(out, value.extendedApprovalCommitment());
        writeString(out, value.disclosureCommitment());
        writeString(out, value.controlStoreId().value());
    }

    private static RealmRecord readRealm(DataInputStream in) throws IOException {
        RealmId realm = new RealmId(readString(in)); String displayName = readString(in);
        AuthorityExposurePolicy.Mode mode = AuthorityExposurePolicy.Mode.fromCode(in.readInt());
        boolean creation = in.readBoolean(); Set<PkiId> ids = readPkiSet(in);
        return new RealmRecord(realm, displayName, new AuthorityExposurePolicy(mode, ids, creation),
                readString(in), readString(in), readString(in), readString(in), new MetadataStoreId(readString(in)));
    }

    private static void writeProtocol(DataOutputStream out, ProtocolRecord value) throws IOException {
        out.writeInt(KIND_PROTOCOL); writeString(out, value.namespace()); writeString(out, value.recordId());
        writeString(out, value.commitment()); writeBytes(out, value.payload());
    }

    private static ProtocolRecord readProtocol(DataInputStream in, String expectedNamespace) throws IOException {
        String namespace = readString(in);
        if (!expectedNamespace.equals(namespace)) throw new IllegalArgumentException("ACME namespace mismatch");
        return new ProtocolRecord(namespace, readString(in), readString(in),
                readBoundedBytes(in, MAXIMUM_RECORD_BYTES / 2));
    }

    private static void writePrincipal(DataOutputStream out, SecurityPrincipal value) throws IOException {
        out.writeInt(KIND_PRINCIPAL); writeString(out, value.principalId()); out.writeInt(value.type().code());
        writeString(out, value.displayName()); writeOptionalString(out, value.organization()); writeStringMap(out, value.attributes());
        out.writeBoolean(value.enabled());
    }

    private static SecurityPrincipal readPrincipal(DataInputStream in) throws IOException {
        return new SecurityPrincipal(readString(in), SecurityPrincipal.Type.fromCode(in.readInt()), readString(in),
                readOptionalString(in), readStringMap(in), in.readBoolean());
    }

    private static void writeAssignment(DataOutputStream out, RoleTemplateCatalog.Assignment value) throws IOException {
        out.writeInt(KIND_ASSIGNMENT); writeString(out, value.assignmentId()); writeString(out, value.principalId());
        writeString(out, value.templateId()); out.writeInt(value.templateVersion()); writeScope(out, value.scope());
        writeOptionalInstant(out, value.expiresAt()); out.writeBoolean(value.enabled());
    }

    private static RoleTemplateCatalog.Assignment readAssignment(DataInputStream in) throws IOException {
        return new RoleTemplateCatalog.Assignment(readString(in), readString(in), readString(in), in.readInt(),
                readScope(in), readOptionalInstant(in), in.readBoolean());
    }

    private static void writeGrant(DataOutputStream out, Permission.Grant value) throws IOException {
        out.writeInt(KIND_GRANT); writeGrantBody(out, value);
    }

    private static Permission.Grant readGrant(DataInputStream in) throws IOException { return readGrantBody(in); }

    private static void writeGrantBody(DataOutputStream out, Permission.Grant value) throws IOException {
        writeString(out, value.grantId()); writeString(out, value.principalId()); out.writeInt(value.effect().code());
        out.writeInt(value.action().code()); out.writeInt(value.resourceType().code()); writeScope(out, value.scope());
        out.writeInt(value.relationship().code()); out.writeInt(value.dataView().code());
        List<Permission.Condition> conditions = value.conditions().stream().sorted(Comparator.comparingInt(Permission.Condition::code)).toList();
        out.writeInt(conditions.size()); for (Permission.Condition item : conditions) out.writeInt(item.code());
        writeOptionalInstant(out, value.expiresAt()); out.writeBoolean(value.enabled());
    }

    private static Permission.Grant readGrantBody(DataInputStream in) throws IOException {
        String id = readString(in); String principal = readString(in); Permission.Effect effect = Permission.Effect.fromCode(in.readInt());
        Permission.Action action = Permission.Action.fromCode(in.readInt()); Permission.ResourceType type = Permission.ResourceType.fromCode(in.readInt());
        Permission.Scope scope = readScope(in); Permission.Relationship relationship = Permission.Relationship.fromCode(in.readInt());
        Permission.DataView view = Permission.DataView.fromCode(in.readInt()); int count = readCount(in); Set<Permission.Condition> conditions = new HashSet<>();
        for (int index = 0; index < count; index++) if (!conditions.add(Permission.Condition.fromCode(in.readInt()))) throw new IllegalArgumentException("Duplicate grant condition");
        return new Permission.Grant(id, principal, effect, action, type, scope, relationship, view, conditions,
                readOptionalInstant(in), in.readBoolean());
    }

    private static void writeApproval(DataOutputStream out, ApprovalService.Request value) throws IOException {
        out.writeInt(KIND_APPROVAL); writeString(out, value.approvalId()); writeString(out, value.operationId());
        writeString(out, value.operationCommitment()); writeScope(out, value.scope()); writeString(out, value.requesterPrincipalId());
        writeInstant(out, value.createdAt()); writeInstant(out, value.expiresAt()); writeApprovalPolicy(out, value.policy());
        writeString(out, value.policyCommitment()); out.writeInt(value.state().code()); out.writeInt(value.decisions().size());
        for (ApprovalService.Decision decision : value.decisions()) { writeString(out, decision.principalId()); out.writeInt(decision.choice().code());
            writeString(out, decision.justification()); writeInstant(out, decision.decidedAt()); }
        writeOptionalString(out, value.resultClassification());
    }

    private static ApprovalService.Request readApproval(DataInputStream in) throws IOException {
        String id = readString(in); String operation = readString(in); String commitment = readString(in); Permission.Scope scope = readScope(in);
        String requester = readString(in); Instant created = readInstant(in); Instant expires = readInstant(in); ApprovalService.Policy policy = readApprovalPolicy(in);
        String policyCommitment = readString(in); ApprovalService.State state = ApprovalService.State.fromCode(in.readInt()); int count = readCount(in);
        List<ApprovalService.Decision> decisions = new ArrayList<>();
        for (int index = 0; index < count; index++) decisions.add(new ApprovalService.Decision(readString(in), ApprovalService.Choice.fromCode(in.readInt()), readString(in), readInstant(in)));
        return new ApprovalService.Request(id, operation, commitment, scope, requester, created, expires, policy,
                policyCommitment, state, decisions, readOptionalString(in));
    }

    private static void writeApprovalPolicy(DataOutputStream out, ApprovalService.Policy value) throws IOException {
        writeString(out, value.policyId()); out.writeInt(value.threshold()); writeStringSet(out, value.eligibleApprovers());
        writeStringSet(out, value.requiredRoleTemplateIds()); out.writeBoolean(value.requesterSeparation());
        out.writeLong(value.lifetime().toSeconds()); out.writeBoolean(value.justificationRequired());
    }

    private static ApprovalService.Policy readApprovalPolicy(DataInputStream in) throws IOException {
        return new ApprovalService.Policy(readString(in), in.readInt(), readStringSet(in), readStringSet(in),
                in.readBoolean(), java.time.Duration.ofSeconds(in.readLong()), in.readBoolean());
    }

    private static void writeBreakGlass(DataOutputStream out, BreakGlassService.Record value) throws IOException {
        out.writeInt(KIND_BREAK_GLASS); writeString(out, value.breakGlassId()); writeString(out, value.principalId());
        writeGrantBody(out, value.grant()); writeString(out, value.reason()); writeString(out, value.issuerPrincipalId());
        writeOptionalString(out, value.approvalId()); writeInstant(out, value.createdAt()); writeOptionalInstant(out, value.activatedAt());
        writeInstant(out, value.expiresAt()); out.writeInt(value.state().code()); writeString(out, value.auditCommitment());
    }

    private static BreakGlassService.Record readBreakGlass(DataInputStream in) throws IOException {
        return new BreakGlassService.Record(readString(in), readString(in), readGrantBody(in), readString(in),
                readString(in), readOptionalString(in), readInstant(in), readOptionalInstant(in), readInstant(in),
                BreakGlassService.State.fromCode(in.readInt()), readString(in));
    }

    private static void writeDisclosure(DataOutputStream out, DisclosureService.Record value) throws IOException {
        out.writeInt(KIND_DISCLOSURE); writeString(out, value.objectId().value()); out.writeInt(value.objectType().code());
        out.writeInt(value.policy().code()); writeOptionalString(out, value.ownerPrincipalId());
        writeOptionalString(out, value.ownerAcmeAccountId());
        writeString(out, value.policyCommitment()); writeInstant(out, value.updatedAt());
    }

    private static DisclosureService.Record readDisclosure(DataInputStream in) throws IOException {
        return new DisclosureService.Record(new PkiId(readString(in)), DisclosureService.ObjectType.fromCode(in.readInt()),
                DisclosureService.Policy.fromCode(in.readInt()), readOptionalString(in), readOptionalString(in),
                readString(in), readInstant(in));
    }

    private static void writeCapability(DataOutputStream out, DisclosureService.Capability value) throws IOException {
        out.writeInt(KIND_CAPABILITY); writeString(out, value.capabilityId()); writeString(out, value.realmId().value());
        writeString(out, value.objectId().value()); writeString(out, value.action());
        writeString(out, value.issuerPrincipalId()); writeBytes(out, value.tokenCommitment());
        writeInstant(out, value.expiresAt()); out.writeInt(value.deliveryState().code()); out.writeBoolean(value.revoked());
    }

    private static DisclosureService.Capability readCapability(DataInputStream in) throws IOException {
        return new DisclosureService.Capability(readString(in), new RealmId(readString(in)), new PkiId(readString(in)),
                readString(in), readString(in), readBytes(in, 32), readInstant(in),
                DisclosureService.DeliveryState.fromCode(in.readInt()), in.readBoolean());
    }

    private static void writeRepositoryAlias(DataOutputStream out, RepositoryAliasService.Record value)
            throws IOException {
        out.writeInt(KIND_REPOSITORY_ALIAS);
        writeString(out, value.aliasId());
        writeString(out, value.realmId().value());
        writeString(out, value.authorityId().value());
        out.writeInt(value.type().code());
        writeString(out, value.targetObjectId().value());
        writeOptionalPki(out, value.issuerId());
        writeOptionalPki(out, value.pathId());
        writeString(out, value.targetCommitment());
        writeInstant(out, value.createdAt());
        writeInstant(out, value.updatedAt());
        writeString(out, value.actorPrincipalId());
        out.writeInt(value.state().code());
        writeString(out, value.recordCommitment());
    }

    private static RepositoryAliasService.Record readRepositoryAlias(DataInputStream in) throws IOException {
        return new RepositoryAliasService.Record(readString(in), new RealmId(readString(in)),
                new PkiId(readString(in)), RepositoryAliasService.Type.fromCode(in.readInt()),
                new PkiId(readString(in)), readOptionalPki(in), readOptionalPki(in), readString(in),
                readInstant(in), readInstant(in), readString(in), RepositoryAliasService.State.fromCode(in.readInt()),
                readString(in));
    }

    private static void writeScope(DataOutputStream out, Permission.Scope value) throws IOException {
        writeString(out, value.realmId().value()); writeOptionalPki(out, value.authorityId());
        writeOptionalPki(out, value.issuerId()); writeOptionalString(out, value.profileId());
        writeOptionalString(out, value.responderId());
    }

    private static Permission.Scope readScope(DataInputStream in) throws IOException {
        return new Permission.Scope(new RealmId(readString(in)), readOptionalPki(in), readOptionalPki(in),
                readOptionalString(in), readOptionalString(in));
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = Objects.requireNonNull(value, "value").getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAXIMUM_STRING_BYTES) throw new IllegalArgumentException("Control string too long");
        out.writeInt(bytes.length); out.write(bytes);
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = in.readInt(); if (length < 0 || length > MAXIMUM_STRING_BYTES) throw new IllegalArgumentException("Control string length invalid");
        byte[] bytes = in.readNBytes(length); if (bytes.length != length) throw new IllegalArgumentException("Truncated control string");
        String result = new String(bytes, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(bytes, result.getBytes(StandardCharsets.UTF_8))) throw new IllegalArgumentException("Control string UTF-8 invalid");
        return result;
    }

    private static void writeOptionalString(DataOutputStream out, Optional<String> value) throws IOException {
        out.writeBoolean(value.isPresent()); if (value.isPresent()) writeString(out, value.orElseThrow());
    }
    private static Optional<String> readOptionalString(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(readString(in)) : Optional.empty(); }
    private static void writeOptionalPki(DataOutputStream out, Optional<PkiId> value) throws IOException { writeOptionalString(out, value.map(PkiId::value)); }
    private static Optional<PkiId> readOptionalPki(DataInputStream in) throws IOException { return readOptionalString(in).map(PkiId::new); }
    private static void writeInstant(DataOutputStream out, Instant value) throws IOException { out.writeLong(value.toEpochMilli()); }
    private static Instant readInstant(DataInputStream in) throws IOException { return Instant.ofEpochMilli(in.readLong()); }
    private static void writeOptionalInstant(DataOutputStream out, Optional<Instant> value) throws IOException { out.writeBoolean(value.isPresent()); if (value.isPresent()) writeInstant(out, value.orElseThrow()); }
    private static Optional<Instant> readOptionalInstant(DataInputStream in) throws IOException { return in.readBoolean() ? Optional.of(readInstant(in)) : Optional.empty(); }
    private static void writePkiSet(DataOutputStream out, Set<PkiId> values) throws IOException { List<PkiId> sorted = values.stream().sorted(Comparator.comparing(PkiId::value)).toList(); out.writeInt(sorted.size()); for (PkiId value : sorted) writeString(out, value.value()); }
    private static Set<PkiId> readPkiSet(DataInputStream in) throws IOException { int count = readCount(in); Set<PkiId> result = new HashSet<>(); for (int index = 0; index < count; index++) if (!result.add(new PkiId(readString(in)))) throw new IllegalArgumentException("Duplicate authority identity"); return result; }
    private static void writeStringSet(DataOutputStream out, Set<String> values) throws IOException { List<String> sorted = values.stream().sorted().toList(); out.writeInt(sorted.size()); for (String value : sorted) writeString(out, value); }
    private static Set<String> readStringSet(DataInputStream in) throws IOException { int count = readCount(in); Set<String> result = new HashSet<>(); for (int index = 0; index < count; index++) if (!result.add(readString(in))) throw new IllegalArgumentException("Duplicate control set value"); return result; }
    private static void writeStringMap(DataOutputStream out, Map<String, String> values) throws IOException { List<Map.Entry<String, String>> sorted = values.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList(); out.writeInt(sorted.size()); for (Map.Entry<String, String> entry : sorted) { writeString(out, entry.getKey()); writeString(out, entry.getValue()); } }
    private static Map<String, String> readStringMap(DataInputStream in) throws IOException { int count = readCount(in); Map<String, String> result = new LinkedHashMap<>(); for (int index = 0; index < count; index++) if (result.put(readString(in), readString(in)) != null) throw new IllegalArgumentException("Duplicate control map key"); return Map.copyOf(result); }
    private static int readCount(DataInputStream in) throws IOException { int count = in.readInt(); if (count < 0 || count > MAXIMUM_COLLECTION) throw new IllegalArgumentException("Control collection size invalid"); return count; }
    private static void writeBytes(DataOutputStream out, byte[] value) throws IOException { out.writeInt(value.length); out.write(value); }
    private static byte[] readBytes(DataInputStream in, int expected) throws IOException { int length = in.readInt(); if (length != expected) throw new IllegalArgumentException("Control byte value length invalid"); byte[] value = in.readNBytes(length); if (value.length != length) throw new IllegalArgumentException("Truncated control byte value"); return value; }
    private static byte[] readBoundedBytes(DataInputStream in, int maximum) throws IOException { int length = in.readInt(); if (length <= 0 || length > maximum) throw new IllegalArgumentException("Control byte value bound invalid"); byte[] value = in.readNBytes(length); if (value.length != length) throw new IllegalArgumentException("Truncated control byte value"); return value; }
    private static void requireDigest(String value) { if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Control commitment invalid"); }

    @FunctionalInterface private interface Encoder { void write(DataOutputStream output) throws IOException; }
    @FunctionalInterface private interface Decoder<T> { T read(DataInputStream input) throws IOException; }

    private record ByteContent(byte[] value) implements RepeatableContent {
        private ByteContent { value = value.clone(); }
        @Override public InputStream openStream() { return new ByteArrayInputStream(value); }
        @Override public OptionalLong length() { return OptionalLong.of(value.length); }
        @Override public String contentId() { return "server-control-record"; }
        @Override public void close() { }
    }
}
