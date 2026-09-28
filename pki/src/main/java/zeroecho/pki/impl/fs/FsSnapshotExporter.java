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
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.SignWorkflowStore;

/**
 * Snapshot exporter ("time travel") for {@link FilesystemPkiStore}.
 *
 * <p>
 * The exporter never mutates the source store. It creates a brand-new store
 * root and populates it with a reconstructed view at time {@code at}. This is
 * an internal implementation facility and is not part of any public PKI API.
 * </p>
 *
 * <p>
 * Semantics:
 * </p>
 * <ul>
 * <li>For entities with history enabled, the exporter selects the latest
 * history entry with timestamp {@code <= at}. If none exists, it may fall back
 * to the current metadata head only when strict mode is disabled. Disabled
 * history retains the current head regardless of strict mode.</li>
 * <li>Issuer generations and paths are selected from the retained CA heads and
 * the exact dependencies required by retained signing workflows and exported credentials, not from unrelated
 * standalone authority records. Other write-once objects are copied as-is. Every valid
 * standalone credential is streamed from the live source into a new target-owned
 * content reference before selected ID-only CA records are published.</li>
 * <li>Signing namespace, signing-time watermark, and authoritative
 * {@code sign-workflows} records are current safety metadata copied at export
 * time. They are intentionally not reconstructed at {@code at}: rolling them
 * back could make a stable identifier reusable or discard a completed signing
 * result.</li>
 * <li>Scope ownership and CRL-number counters are copied together from pinned
 * current metadata. Neither historical {@code at} nor target initial-number
 * configuration can roll back a consumed or reserved CRL number.</li>
 * </ul>
 *
 * <p>
 * Export requires time linear in examined authority metadata, copied files,
 * and selected credential bytes,
 * with auxiliary memory including selected CA/credential metadata and all
 * retained generation/path payloads, including the sum of their KeyRef bytes,
 * plus one fixed-size transfer buffer. Startup streaming does not imply that
 * the export plan is constant-memory.
 * </p>
 */
final class FsSnapshotExporter {

    private static final Logger LOG = Logger.getLogger(FsSnapshotExporter.class.getName());
    private static final String ACTIVE_POINTER_FILE = "active.bin";
    private static final String BINARY_EXTENSION = ".bin";
    private static final int TRANSFER_BUFFER_BYTES = 16 * 1024;
    private static final String REVOCATION_PREFIX_STAGE = ".revocation-prefix.snapshot";

    private final FsPkiStoreOptions options;

    /* default */ FsSnapshotExporter(final FsPkiStoreOptions options) {
        this.options = Objects.requireNonNull(options, "options");
    }

    /*
     * Snapshot/profile failures deliberately cross this boundary without input-
     * bearing causes or filesystem paths.
     */
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ void exportSnapshot(final FilesystemPkiStore source, final Path targetRoot, final Instant at) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(targetRoot, "targetRoot");
        Objects.requireNonNull(at, "at");

        try (MetadataSnapshot snapshot = source.metadataStore().snapshot()) {
            requireNewTarget(targetRoot);
            Path sourceRoot = source.snapshotRoot();
            List<SnapshotProfileArtifact> profiles = preflightImportedProfiles(sourceRoot.resolve("profiles"), at);
            SnapshotAuthority authority = new AuthorityPlanner(source, options, snapshot).plan(at);
            Set<String> nonCredentialContentIds = source.snapshotNonCredentialContentIds(snapshot);
            SnapshotPlan plan = new SnapshotPlan(profiles, authority, nonCredentialContentIds);
            new SnapshotPublisher(source, options, plan, snapshot).publish(targetRoot, at);
        } catch (SnapshotProfileFailure failure) {
            throw new IllegalStateException(failure.getMessage());
        } catch (IOException e) {
            throw new IllegalStateException("Snapshot export failed: code=SNAPSHOT_EXPORT_FAILED");
        }
    }

    private static DurableContentReference transferContent(FilesystemPkiStore source,
            FilesystemPkiStore target, DurableContentReference sourceReference) throws IOException {
        try (RepeatableContent content = source.stagedContent().openContent(sourceReference);
                InputStream input = content.openStream();
                ContentSink sink = target.stagedContent().beginContent(sourceReference.encoding(),
                        DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            byte[] buffer = new byte[TRANSFER_BUFFER_BYTES];
            try {
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    if (read > 0) {
                        output.write(buffer, 0, read);
                    }
                }
                DurableContentReference transferred = sink.complete();
                if (transferred.length() != sourceReference.length() || !transferred.sha256().equals(sourceReference.sha256())) {
                    IOException failure = new IOException("Snapshot content commitment differs");
                    try { target.stagedContent().retireUnownedContent(transferred); }
                    catch (IOException cleanup) { failure.addSuppressed(cleanup); }
                    throw failure;
                }
                return transferred;
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
        }
    }

    private static Credential withContent(Credential source, DurableContentReference content) {
        return new Credential(source.credentialId(), source.formatId(), source.issuerRef(), source.subjectRef(),
                source.validity(), source.serialOrUniqueId(), source.publicKeyId(), source.profileBinding(),
                source.status(), content, source.attributes());
    }

    private static void requireNewTarget(Path targetRoot) {
        if (Files.exists(targetRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalStateException("Snapshot target already exists");
        }
    }

    /** Builds the validated logical credential and selected-CA export plan. */
    private static final class AuthorityPlanner {
        private final FilesystemPkiStore source;
        private final FsPkiStoreOptions options;
        private final MetadataSnapshot snapshot;

        private AuthorityPlanner(FilesystemPkiStore source, FsPkiStoreOptions options, MetadataSnapshot snapshot) {
            this.source = source;
            this.options = options;
            this.snapshot = snapshot;
        }

        // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
        @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
        private SnapshotAuthority plan(Instant at) throws IOException {
            AuthorityMetadataStore.validateAll(snapshot);
            CredentialInventory inventory = inventoryCredentials();
            List<CaRecord> cas = selectCas(at, inventory.credentials());
            Map<PkiId, IssuerGeneration> generations = new LinkedHashMap<>();
            for (CaRecord ca : cas) {
                for (PkiId issuerId : ca.issuerIds()) { includeGeneration(generations, issuerId); }
            }
            Map<PkiId, IssuerChainPath> paths = new LinkedHashMap<>();
            AuthorityMetadataStore.visit(snapshot, AuthorityMetadataCodec.ISSUER_PATH, AuthorityMetadataCodec::path,
                    path -> {
                        if (generations.containsKey(path.issuerId())) { paths.put(path.pathId(), path); }
                    });
            source.visitSnapshotSigningWorkflows(snapshot, workflow -> includeSigningDependencies(workflow, generations, paths));
            // A standalone self-signed credential does not publish its CA authority.
            // Non-root credentials still need their exact frozen issuer dependencies.
            for (Credential credential : inventory.credentials().values()) {
                if (BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                        && !credential.issuerRef().issuerId().equals(IssuerGeneration.idFor(
                                credential.issuerRef().caId(), credential.credentialId()))) {
                    PkiId pathId = credential.issuerRef().chainPathId();
                    IssuerChainPath path = AuthorityMetadataStore.find(snapshot,
                            AuthorityMetadataCodec.pathKey(pathId), AuthorityMetadataCodec::path)
                            .orElseThrow(() -> new SnapshotAuthorityFailure("Snapshot credential issuer authority is missing"));
                    paths.put(pathId, path);
                }
            }
            for (IssuerChainPath path : paths.values()) {
                includeGeneration(generations, path.issuerId());
                for (int index = 0; index + 1 < path.orderedCredentialIds().size(); index++) {
                    Credential credential = inventory.credentials().get(path.orderedCredentialIds().get(index));
                    if (credential == null) { throw new SnapshotAuthorityFailure("Snapshot issuer credential is missing"); }
                    includeGeneration(generations, credential.issuerRef().issuerId());
                    includeGeneration(generations, IssuerGeneration.idFor(credential.issuerRef().caId(),
                            path.orderedCredentialIds().get(index + 1)));
                }
            }
            List<StatusObject> statuses = source.snapshotStatusObjects(snapshot);
            Set<String> remintedContentIds = new HashSet<>(inventory.contentIds());
            for (StatusObject status : statuses) {
                remintedContentIds.add(status.content().contentId());
            }
            return new SnapshotAuthority(cas, List.copyOf(generations.values()), List.copyOf(paths.values()), inventory.credentials(), statuses,
                    remintedContentIds);
        }

        private void includeGeneration(Map<PkiId, IssuerGeneration> generations, PkiId issuerId) throws IOException {
            if (!generations.containsKey(issuerId)) {
                generations.put(issuerId, AuthorityMetadataStore.find(snapshot,
                        AuthorityMetadataCodec.generationKey(issuerId), AuthorityMetadataCodec::generation)
                        .orElseThrow(() -> new SnapshotAuthorityFailure("Snapshot issuer generation is missing")));
            }
        }

        private void includeSigningDependencies(SignWorkflowStore.Workflow workflow,
                Map<PkiId, IssuerGeneration> generations, Map<PkiId, IssuerChainPath> paths) throws IOException {
            if (workflow.envelope().outer().isEmpty()) { return; }
            SignWorkflowStore.OuterCommand outer = workflow.envelope().outer().orElseThrow();
            DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
            switch (outer.kind()) {
                case ISSUANCE -> {
                    includeGeneration(generations, new PkiId(command.field(1)));
                    includePath(paths, new PkiId(command.field(2)));
                }
                case CA -> {
                    if (!"CREATE_ROOT".equals(command.operation()) && !"ROLLOVER_ROOT".equals(command.operation())) {
                        includeGeneration(generations, new PkiId(command.field(3)));
                        includePath(paths, new PkiId(command.field(4)));
                    }
                }
                case STATUS -> {
                    if (FullCrlSigningCommand.supports(command.operation())) {
                        includeGeneration(generations, new PkiId(command.field(6)));
                    }
                }
                case KEY_PROOF -> { /* Proofs reference no persisted issuer generation or path. */ }
            }
        }

        private void includePath(Map<PkiId, IssuerChainPath> paths, PkiId pathId) throws IOException {
            if (!paths.containsKey(pathId)) {
                paths.put(pathId, AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.pathKey(pathId), AuthorityMetadataCodec::path)
                        .orElseThrow(() -> new SnapshotAuthorityFailure("Snapshot signing issuer path is missing")));
            }
        }

        private CredentialInventory inventoryCredentials() throws IOException {
            Map<PkiId, Credential> credentials = new LinkedHashMap<>();
            Set<String> contentIds = new HashSet<>();
            new CredentialMetadataAuthority(source.metadataStore(), source.stagedContent()).validateAll(snapshot, credential -> {
                credentials.put(credential.credentialId(), credential);
                contentIds.add(credential.content().contentId());
            });
            return new CredentialInventory(credentials, contentIds);
        }

        private List<CaRecord> selectCas(Instant at, Map<PkiId, Credential> credentials) throws IOException {
            List<CaRecord> selected = new ArrayList<>();
            for (AuthorityMetadataCodec.Head current : AuthorityMetadataStore.list(snapshot, AuthorityMetadataCodec.CA_CURRENT, AuthorityMetadataCodec::head)) {
                CaRecord ca = AuthorityMetadataStore.caAt(snapshot, current.caId(), at, options.caHistoryPolicy(), options.strictSnapshotExport()).orElse(null);
                if (ca != null && validCa(ca, credentials)) {
                    selected.add(ca);
                } else if (ca != null) {
                    rejectCa();
                }
            }
            return List.copyOf(selected);
        }

        private boolean validCa(CaRecord ca, Map<PkiId, Credential> credentials) throws IOException {
            try {
                for (PkiId issuerId : ca.issuerIds()) {
                    IssuerGeneration generation = AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.generationKey(issuerId), AuthorityMetadataCodec::generation).orElseThrow();
                    if (!ca.caId().equals(generation.authorityId())
                            || !credentials.containsKey(generation.credentialId())) {
                        return false;
                    }
                }
                IssuerChainPath path = AuthorityMetadataStore.find(snapshot, AuthorityMetadataCodec.pathKey(ca.issuanceChainPathId()), AuthorityMetadataCodec::path).orElseThrow();
                return ca.caId().equals(path.authorityId())
                        && ca.currentIssuanceIssuerId().equals(path.issuerId())
                        && path.orderedCredentialIds().stream().allMatch(credentials::containsKey);
            } catch (IllegalStateException | java.util.NoSuchElementException failure) {
                return false;
            }
        }

        private void rejectCa() {
            if (options.strictSnapshotExport()) {
                throw new SnapshotAuthorityFailure("Snapshot CA dependency preflight failed");
            }
        }
    }

    /** Owns the sibling temporary root until one atomic target publication. */
    private static final class SnapshotPublisher {
        private final FilesystemPkiStore source;
        private final FsPkiStoreOptions options;
        private final SnapshotPlan plan;
        private final MetadataSnapshot snapshot;

        private SnapshotPublisher(FilesystemPkiStore source, FsPkiStoreOptions options, SnapshotPlan plan, MetadataSnapshot snapshot) {
            this.source = source;
            this.options = options;
            this.plan = plan;
            this.snapshot = snapshot;
        }

        private void publish(Path targetRoot, Instant at) throws IOException {
            Path absoluteTarget = targetRoot.toAbsolutePath();
            Path parent = absoluteTarget.getParent();
            if (parent == null) {
                throw new IOException("Snapshot target has no parent");
            }
            FsOperations.ensureDir(parent);
            Path temporaryRoot = Files.createTempDirectory(parent, ".zeroecho-snapshot-");
            boolean published = false;
            try {
                build(temporaryRoot, at);
                Files.move(temporaryRoot, absoluteTarget, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
                published = true;
            } catch (IOException | IllegalStateException failure) {
                if (!published) {
                    addCleanupFailure(failure, temporaryRoot);
                }
                throw failure;
            }
        }

        private void build(Path targetRoot, Instant at) throws IOException {
            try (PublicationCursor publications = source.openPublicationRecords(snapshot)) {
                Path sourceRoot = source.snapshotRoot();
                Path stagedRevocationPrefix = targetRoot.resolve(REVOCATION_PREFIX_STAGE);
                FilesystemRevocationLog.RecoveryTarget captured =
                        source.copyRevocationPrefix(stagedRevocationPrefix);
                copyFile(sourceRoot.resolve("SIGNING_NAMESPACE"), targetRoot.resolve("SIGNING_NAMESPACE"));
                copyTreeIfExists(sourceRoot.resolve("requests"), targetRoot.resolve("requests"));
                copyTreeIfExists(sourceRoot.resolve("policy"), targetRoot.resolve("policy"));
                copyTreeIfExists(sourceRoot.resolve("sign-workflows"), targetRoot.resolve("sign-workflows"));
                copyStagedContent(sourceRoot.resolve("staged-content"), targetRoot.resolve("staged-content"),
                        plan.authority().remintedContentIds(), plan.nonCredentialContentIds());
                copyImportedProfilesAsOf(plan.profiles(), targetRoot.resolve("profiles"));
                reconstructMutableTree(sourceRoot.resolve("workflows"), targetRoot.resolve("workflows"), at,
                        options.workflowHistoryPolicy(), options.strictSnapshotExport());
                new AuthorityRestorer(source, options, plan.authority(), snapshot).restore(targetRoot);
                installRevocationAuthority(targetRoot, stagedRevocationPrefix);
                try (FilesystemPkiStore target = FilesystemPkiStore.openSnapshotAssembly(
                        targetRoot, options)) {
                    // Opening validates the restored authority and rebuilds its derived index.
                    restorePublicationMetadata(publications, target);
                    target.validateRecoveredCrlAuthority();
                }
                writeSnapshotBoundary(targetRoot, captured.boundary());
            }
        }

        @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
        private static void restorePublicationMetadata(PublicationCursor cursor, FilesystemPkiStore target)
                throws IOException {
            Optional<PublicationRecord> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                PublicationRecord record = next.orElseThrow();
                DurableContentReference targetContent = record.sourceType() == PublicationSourceType.CREDENTIAL
                        ? target.getCredential(record.sourceId()).map(Credential::content).orElseThrow(
                                () -> new IOException("Snapshot publication credential is missing"))
                        : target.getStatusObject(record.sourceId()).map(StatusObject::content).orElseThrow(
                                () -> new IOException("Snapshot publication status object is missing"));
                PublicationRecord restored = new PublicationRecord(record.publicationId(), record.sourceType(),
                        record.sourceId(), targetContent, record.target(), record.status(), record.attemptNumber(),
                        record.attemptToken(), record.createdAt(), record.updatedAt(), record.failure(),
                        record.evidence());
                target.createPublicationRecord(restored);
            }
        }

        private static void writeSnapshotBoundary(Path targetRoot, long boundary) throws IOException {
            Path marker = new FsPaths(targetRoot).revocationSnapshotBoundary();
            Files.writeString(marker, Long.toString(boundary), StandardCharsets.US_ASCII,
                    java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE);
            try (java.nio.channels.FileChannel channel = java.nio.channels.FileChannel.open(
                    marker, java.nio.file.StandardOpenOption.WRITE)) {
                channel.force(true);
            }
            PlatformFs.forceDirectory(targetRoot);
        }

        private static void installRevocationAuthority(Path targetRoot, Path stagedPrefix) throws IOException {
            FsPaths paths = new FsPaths(targetRoot);
            Files.deleteIfExists(paths.revocationCurrentIndex());
            Files.createDirectories(paths.revocationTransitionLog().getParent());
            try {
                Files.move(stagedPrefix, paths.revocationTransitionLog(),
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException unsupported) {
                throw new IOException("Atomic revocation snapshot restoration is unsupported", unsupported);
            }
            PlatformFs.forceDirectory(paths.revocationTransitionLog().getParent());
        }

        private static void addCleanupFailure(Exception primary, Path temporaryRoot) {
            try {
                deleteOwnedTree(temporaryRoot);
            } catch (IOException cleanupFailure) {
                primary.addSuppressed(new IOException("Snapshot temporary cleanup failed"));
            }
        }
    }

    /** Reconstructs target credential authority before publishing selected CAs. */
    private static final class AuthorityRestorer {
        private final FilesystemPkiStore source;
        private final FsPkiStoreOptions options;
        private final SnapshotAuthority authority;
        private final MetadataSnapshot snapshot;
        private final Map<PkiId, IssuerGeneration> generations = new LinkedHashMap<>();
        private final Map<PkiId, IssuerChainPath> paths = new LinkedHashMap<>();

        private AuthorityRestorer(FilesystemPkiStore source, FsPkiStoreOptions options,
                SnapshotAuthority authority, MetadataSnapshot snapshot) {
            this.source = source;
            this.options = options;
            this.authority = authority;
            this.snapshot = snapshot;
            for (IssuerGeneration generation : authority.generations()) {
                generations.put(generation.issuerId(), generation);
            }
            for (IssuerChainPath path : authority.paths()) {
                paths.put(path.pathId(), path);
            }
        }

        // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
        @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
        private void restore(Path targetRoot) throws IOException {
            Set<PkiId> transferred = new HashSet<>();
            source.copySnapshotMetadataTo(snapshot, targetRoot);
            try (FilesystemPkiStore target = FilesystemPkiStore.openSnapshotAssembly(targetRoot, options)) {
                for (Map.Entry<PkiId, Credential> entry : authority.credentials().entrySet()) {
                    persistCredentialWithIssuer(target, entry.getValue(), transferred, new HashSet<>());
                }
                for (IssuerGeneration generation : authority.generations()) {
                    if (transferred.contains(generation.credentialId())
                            && target.getIssuerGeneration(generation.issuerId()).isEmpty()) {
                        target.putIssuerGeneration(generation);
                    }
                }
                for (IssuerChainPath path : authority.paths()) {
                    if (transferred.containsAll(path.orderedCredentialIds())
                            && target.getIssuerChainPath(path.pathId()).isEmpty()) {
                        target.putIssuerChainPath(path);
                    }
                }
                for (CaRecord ca : authority.cas()) {
                    if (ca.issuerIds().stream().allMatch(id -> target.getIssuerGeneration(id).isPresent())
                            && target.getIssuerChainPath(ca.issuanceChainPathId()).isPresent()) {
                        persistCa(target, ca);
                    }
                }
                for (StatusObject status : authority.statuses()) {
                    persistStatus(target, status);
                }
            }
        }

        // Each issuer dependency is visited once; recursion is bounded by the
        // existing maximum chain depth. This is transfer ordering, not recovery
        // reconstruction of scope ownership or consumed serial reservations.
        private boolean persistCredentialWithIssuer(FilesystemPkiStore target, Credential credential,
                Set<PkiId> transferred, Set<PkiId> visiting) throws IOException {
            if (transferred.contains(credential.credentialId())) { return true; }
            if (!visiting.add(credential.credentialId()) || visiting.size() > IssuerChainPath.MAX_CERTIFICATES + 1) {
                throw new IOException("Snapshot credential issuer dependency is cyclic or too deep");
            }
            try {
                boolean root = credential.issuerRef().issuerId().equals(
                        IssuerGeneration.idFor(credential.issuerRef().caId(), credential.credentialId()));
                if (BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                        && !root) {
                    IssuerGeneration generation = generations.get(credential.issuerRef().issuerId());
                    IssuerChainPath path = paths.get(credential.issuerRef().chainPathId());
                    if (generation == null || path == null) {
                        throw new IOException("Snapshot credential issuer authority is missing");
                    }
                    for (PkiId parentId : path.orderedCredentialIds()) {
                        Credential parent = authority.credentials().get(parentId);
                        if (parent == null || !persistCredentialWithIssuer(target, parent, transferred, visiting)) {
                            throw new IOException("Snapshot credential issuer content is missing");
                        }
                    }
                    if (target.getIssuerGeneration(generation.issuerId()).isEmpty()) {
                        target.putIssuerGeneration(generation);
                    }
                    if (target.getIssuerChainPath(path.pathId()).isEmpty()) {
                        target.putIssuerChainPath(path);
                    }
                }
                if (persistCredential(target, credential)) {
                    transferred.add(credential.credentialId());
                    return true;
                }
                return false;
            } finally {
                visiting.remove(credential.credentialId());
            }
        }

        private boolean persistCredential(FilesystemPkiStore target, Credential sourceCredential)
                throws IOException {
            if (options.strictSnapshotExport()) {
                return persistCredentialStrict(target, sourceCredential);
            }
            try (CredentialTransfer transfer = new CredentialTransfer(source, target, sourceCredential, snapshot)) {
                transfer.persist();
                return true;
            } catch (FilesystemPkiStore.SnapshotCredentialAuthorityException failure) {
                throw failure;
            } catch (IOException | IllegalArgumentException | IllegalStateException failure) {
                return false;
            }
        }

        private boolean persistCredentialStrict(FilesystemPkiStore target, Credential sourceCredential)
                throws IOException {
            try (CredentialTransfer transfer = new CredentialTransfer(source, target, sourceCredential, snapshot)) {
                transfer.persist();
                return true;
            }
        }

        private boolean persistCa(FilesystemPkiStore target, CaRecord ca) throws IOException {
            if (options.strictSnapshotExport()) {
                target.restoreSnapshotCa(ca);
                return true;
            }
            try {
                target.restoreSnapshotCa(ca);
                return true;
            } catch (IllegalArgumentException | IllegalStateException failure) {
                return false;
            }
        }

        private void persistStatus(FilesystemPkiStore target, StatusObject sourceStatus) throws IOException {
            try (StatusTransfer transfer = new StatusTransfer(source, target, sourceStatus)) {
                transfer.persist();
            }
        }
    }

    /** Owns a completed target reference until its credential is persisted. */
    private static final class CredentialTransfer implements AutoCloseable {
        private final FilesystemPkiStore target;
        private final Credential sourceCredential;
        private final DurableContentReference targetReference;
        private final Optional<FilesystemPkiStore.SnapshotCredentialAuthority> credentialAuthority;
        private boolean persisted;

        private CredentialTransfer(FilesystemPkiStore source, FilesystemPkiStore target,
                Credential sourceCredential, MetadataSnapshot snapshot) throws IOException {
            this.target = target;
            this.sourceCredential = sourceCredential;
            this.credentialAuthority = source.credentialSnapshotAuthority(snapshot, sourceCredential);
            this.targetReference = transferContent(source, target, sourceCredential.content());
        }

        private void persist() throws IOException {
            target.putSnapshotCredential(withContent(sourceCredential, targetReference), credentialAuthority);
            persisted = true;
        }

        @Override
        public void close() throws IOException {
            if (!persisted) {
                target.stagedContent().retireUnownedContent(targetReference);
            }
        }
    }

    /** Owns reminted target content until its status authority is committed. */
    private static final class StatusTransfer implements AutoCloseable {
        private final FilesystemPkiStore target;
        private final StatusObject sourceStatus;
        private final DurableContentReference targetReference;
        private boolean persisted;

        private StatusTransfer(FilesystemPkiStore source, FilesystemPkiStore target, StatusObject sourceStatus)
                throws IOException {
            this.target = target;
            this.sourceStatus = sourceStatus;
            this.targetReference = transferContent(source, target, sourceStatus.content());
        }

        private void persist() {
            target.putStatusObject(new StatusObject(sourceStatus.statusObjectId(), sourceStatus.formatId(),
                    sourceStatus.issuerCaId(), sourceStatus.type(), sourceStatus.thisUpdate(),
                    sourceStatus.nextUpdate(), targetReference, sourceStatus.attributes()));
            persisted = true;
        }

        @Override
        public void close() throws IOException {
            if (!persisted) {
                target.stagedContent().retireUnownedContent(targetReference);
            }
        }
    }

    private static void deleteOwnedTree(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            List<Path> ordered = paths.sorted(Comparator.reverseOrder()).toList();
            for (Path path : ordered) {
                Files.delete(path);
            }
        }
    }

    /*
     * Strict codec and filesystem traversal can produce several runtime failure
     * types; all are normalized without their untrusted causes.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    private static List<SnapshotProfileArtifact> preflightImportedProfiles(Path profilesRoot, Instant at)
            throws IOException {
        if (!requireProfileRoot(profilesRoot)) {
            return List.of();
        }
        List<SnapshotProfileArtifact> selected = new ArrayList<>();
        try (java.util.stream.Stream<Path> files = Files.walk(profilesRoot)) {
            for (Path path : files.filter(Files::isRegularFile).sorted(Comparator.comparing(Path::toString)).toList()) {
                collectProfileArtifact(profilesRoot, path, at, selected);
            }
        } catch (SnapshotProfileFailure failure) {
            throw failure;
        } catch (ProfileLifecycleFailure failure) {
            throw SnapshotProfileFailure.of(failure.code());
        } catch (IOException failure) {
            throw SnapshotProfileFailure.of(Code.PROFILE_STORE_FAILURE);
        } catch (RuntimeException failure) {
            throw SnapshotProfileFailure.of(Code.PROFILE_VERSION_CORRUPT);
        }
        return List.copyOf(selected);
    }

    private static boolean requireProfileRoot(Path profilesRoot) {
        if (!Files.exists(profilesRoot, LinkOption.NOFOLLOW_LINKS)) {
            return false;
        }
        if (!Files.isDirectory(profilesRoot, LinkOption.NOFOLLOW_LINKS) || !Files.isReadable(profilesRoot)) {
            throw SnapshotProfileFailure.of(Code.PROFILE_STORE_FAILURE);
        }
        return true;
    }

    private static void collectProfileArtifact(Path profilesRoot, Path path, Instant at,
            List<SnapshotProfileArtifact> selected) throws IOException {
        String fileName = path.getFileName().toString();
        if (ACTIVE_POINTER_FILE.equals(fileName)) {
            throw SnapshotProfileFailure.of(Code.PROFILE_ACTIVATION_HISTORY_UNAVAILABLE);
        }
        if (!fileName.endsWith(BINARY_EXTENSION)) {
            throw SnapshotProfileFailure.of(Code.PROFILE_VERSION_CORRUPT);
        }
        byte[] artifact = Files.readAllBytes(path);
        ValidatedImportedProfile validated = ValidatedImportedProfile.decode(artifact);
        if (!expectedProfileVersionPath(profilesRoot, validated).equals(path)) {
            throw SnapshotProfileFailure.of(Code.PROFILE_VERSION_CORRUPT);
        }
        if (!validated.version().importedAt().isAfter(at)) {
            selected.add(new SnapshotProfileArtifact(profilesRoot.relativize(path), artifact));
        }
    }

    private static Path expectedProfileVersionPath(Path profilesRoot, ValidatedImportedProfile validated) {
        String profileId = validated.version().reference().profileId();
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(profileId.getBytes(StandardCharsets.UTF_8));
        return profilesRoot.resolve("by-id").resolve("id-" + encoded).resolve("versions")
                .resolve(validated.version().reference().profileVersion() + BINARY_EXTENSION);
    }

    private static void copyImportedProfilesAsOf(List<SnapshotProfileArtifact> profiles, Path target)
            throws IOException {
        for (SnapshotProfileArtifact profile : profiles) {
            Path output = target.resolve(profile.relativePath());
            FsOperations.ensureDir(output.getParent());
            FsOperations.writeAtomic(output, profile.bytes());
        }
    }

    private static void reconstructMutableTree(final Path srcTree, final Path dstTree, final Instant at,
            final FsHistoryPolicy policy, final boolean strict) throws IOException {

        if (!Files.exists(srcTree)) {
            return;
        }
        try (java.util.stream.Stream<Path> tree = Files.walk(srcTree)) {
        tree.filter(Files::isRegularFile).sorted(Comparator.comparing(Path::toString)).forEach(p -> {
            // only process current.bin; replace it based on history
            if (!FsPaths.CURRENT_FILE.equals(p.getFileName().toString())) {
                return;
            }

            Path entityDir = p.getParent();
            Path historyDir = entityDir.resolve(FsPaths.HISTORY_DIR);

            Path selected = null;
            if (policy.enabled() && Files.isDirectory(historyDir)) {
                selected = selectHistoryEntry(historyDir, at);
            }

            if (selected == null) {
                if (strict && policy.enabled()) {
                    throw new IllegalStateException(
                            "no history entry available for snapshot at " + at + " for " + entityDir);
                }
                selected = p;
            }

            try {
                Path relative = srcTree.relativize(entityDir);
                Path dstEntityDir = dstTree.resolve(relative);
                FsOperations.ensureDir(dstEntityDir);
                byte[] data = Files.readAllBytes(selected);
                FsOperations.writeAtomic(dstEntityDir.resolve(FsPaths.CURRENT_FILE), data);
            } catch (IOException e) {
                throw new IllegalStateException("snapshot reconstruction failed for " + entityDir, e);
            }
        });
        }
    }

    private static Path selectHistoryEntry(final Path historyDir, final Instant at) {
        try (java.util.stream.Stream<Path> entries = Files.list(historyDir)) {
            return entries.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::getFileName).reversed()).filter(p -> {
                        String name = p.getFileName().toString();
                        // format: <tsMicros>-<seq>.bin
                        int dash = name.indexOf('-');
                        int dot = name.lastIndexOf('.');
                        if (dash <= 0 || dot <= dash) {
                            return false;
                        }
                        String tsPart = name.substring(0, dash);
                        try {
                            long tsMicros = Long.parseLong(tsPart);
                            Instant entryTime = Instant.ofEpochSecond(tsMicros / 1_000_000L,
                                    (tsMicros % 1_000_000L) * 1_000L); // NOPMD
                            return !entryTime.isAfter(at);
                        } catch (NumberFormatException e) {
                            return false;
                        }
                    }).findFirst().orElse(null);
        } catch (IOException e) {
            LOG.log(Level.FINE, "history scan failed: {0}", historyDir);
            return null;
        }
    }

    private static void copyTreeIfExists(final Path src, final Path dst) throws IOException {
        if (!Files.exists(src)) {
            return;
        }
        try (java.util.stream.Stream<Path> tree = Files.walk(src)) {
        tree.sorted(Comparator.comparing(Path::toString)).forEach(p -> {
            try {
                Path rel = src.relativize(p);
                Path out = dst.resolve(rel);
                if (Files.isDirectory(p)) {
                    FsOperations.ensureDir(out);
                } else if (Files.isRegularFile(p)) {
                    FsOperations.ensureDir(out.getParent());
                    FsOperations.writeAtomic(out, Files.readAllBytes(p));
                }
            } catch (IOException e) {
                throw new IllegalStateException("copy failed: " + p, e);
            }
        });
        }
    }

    private static void copyStagedContent(Path src, Path dst, Set<String> credentialContentIds,
            Set<String> nonCredentialContentIds) throws IOException {
        if (!Files.exists(src)) {
            return;
        }
        try (java.util.stream.Stream<Path> paths = Files.walk(src)) {
            for (Path path : paths.sorted(Comparator.comparing(Path::toString)).toList()) {
                Path relative = src.relativize(path);
                Path output = dst.resolve(relative);
                if (Files.isDirectory(path)) {
                    FsOperations.ensureDir(output);
                } else if (Files.isRegularFile(path)
                        && shouldCopyStagedArtifact(path, credentialContentIds, nonCredentialContentIds)) {
                    FsOperations.ensureDir(output.getParent());
                    FsOperations.copyAtomic(path, output, TRANSFER_BUFFER_BYTES);
                }
            }
        }
    }

    private static boolean shouldCopyStagedArtifact(Path path, Set<String> credentialContentIds,
            Set<String> nonCredentialContentIds) {
        String fileName = path.getFileName().toString();
        int separator = fileName.lastIndexOf('.');
        if (separator <= 0) {
            return true;
        }
        String extension = fileName.substring(separator);
        if (!".content".equals(extension) && !".meta".equals(extension) && !".owners".equals(extension)) {
            return true;
        }
        String contentId = fileName.substring(0, separator);
        return !credentialContentIds.contains(contentId)
                || nonCredentialContentIds.contains(contentId) && !".owners".equals(extension);
    }

    private static void copyFile(final Path source, final Path target) throws IOException {
        if (!Files.isRegularFile(source)) {
            throw new IllegalStateException("Required snapshot metadata is missing: " + source.getFileName());
        }
        FsOperations.writeAtomic(target, Files.readAllBytes(source));
    }

    private record SnapshotProfileArtifact(Path relativePath, byte[] bytes) {
        private SnapshotProfileArtifact {
            bytes = bytes.clone();
        }

        @Override
        public byte[] bytes() {
            return bytes.clone();
        }
    }

    private record CredentialInventory(Map<PkiId, Credential> credentials, Set<String> contentIds) {
        private CredentialInventory {
            credentials = Collections.unmodifiableMap(new LinkedHashMap<>(credentials));
            contentIds = Set.copyOf(contentIds);
        }
    }

    private record SnapshotAuthority(List<CaRecord> cas, List<IssuerGeneration> generations,
            List<IssuerChainPath> paths, Map<PkiId, Credential> credentials,
            List<StatusObject> statuses, Set<String> remintedContentIds) {
        private SnapshotAuthority {
            cas = List.copyOf(cas);
            generations = List.copyOf(generations);
            paths = List.copyOf(paths);
            credentials = Collections.unmodifiableMap(new LinkedHashMap<>(credentials));
            statuses = List.copyOf(statuses);
            remintedContentIds = Set.copyOf(remintedContentIds);
        }
    }

    private record SnapshotPlan(List<SnapshotProfileArtifact> profiles, SnapshotAuthority authority,
            Set<String> nonCredentialContentIds) {
        private SnapshotPlan {
            profiles = List.copyOf(profiles);
            Objects.requireNonNull(authority, "authority");
            nonCredentialContentIds = Set.copyOf(nonCredentialContentIds);
        }
    }

    /** Cause-free marker for invalid source credential or CA authority. */
    private static final class SnapshotAuthorityFailure extends IllegalStateException {
        private static final long serialVersionUID = -8051398945014616477L;

        private SnapshotAuthorityFailure(String message) {
            super(message);
        }
    }

    /** Cause-free internal marker for profile preflight rejection. */
    private static final class SnapshotProfileFailure extends RuntimeException {
        private static final long serialVersionUID = -4451876406166515230L;

        private SnapshotProfileFailure(String message) {
            super(message);
        }

        private static SnapshotProfileFailure of(Code code) {
            String prefix = code == Code.PROFILE_ACTIVATION_HISTORY_UNAVAILABLE
                    ? "Historical snapshot unavailable: code="
                    : "Historical snapshot failed: code=";
            return new SnapshotProfileFailure(prefix + code);
        }
    }
}
