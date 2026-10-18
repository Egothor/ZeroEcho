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
package zeroecho.pki.impl.fs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.logging.Level;
import java.util.logging.Logger;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.backup.BackupLimits;
import zeroecho.pki.api.backup.BackupPreparation;
import zeroecho.pki.api.backup.RestoreStatus;

/** External lifetime fencing and cold activation; all roots are on one filesystem. */
final class FsRestoreCoordinator implements AutoCloseable { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    private static final String ROLLBACK_PREFIX = "rollback-";
    private static final String INVALID_ROOT_LAYOUT = "RESTORE_ROOT_LAYOUT_INVALID";
    private static final String TEXT_CANDIDATE = "candidate";
    private static final String TEXT_ORIGINAL = "original";
    private static final String JOURNAL_NAME = "journal";
    private static final int JOURNAL_VERSION = 1;

    private static final int JOURNAL_LIMIT = 65_536;
    private static final Logger LOG = Logger.getLogger(FsRestoreCoordinator.class.getName());
    private static final String MARKER = ".restore-role-";
    private final Path live;
    private final Path parent;
    private final Path control;
    private final BackupLimits limits;
    private final FilesystemPkiStore.StoreOwnership processLock;
    private final Map<Path, FilesystemPkiStore.StoreOwnership> roots = new HashMap<>();
    private Journal journal;
    private boolean uncertain;
    private static final ThreadLocal<Observer> OBSERVER = new ThreadLocal<>();

    /** Durable restore progress states recognized on restart. */
    /* default */ enum State { PREPARED, LIVE_MOVED, STAGING_PROMOTED, NEW_ROOT_VERIFIED, COMPLETE, ROLLED_BACK }
    /** Observable transition points for crash and filesystem fault injection. */
    /* default */ enum Phase { JOURNAL, BEFORE_LIVE_MOVE, AFTER_LIVE_MOVE, BEFORE_PROMOTION, AFTER_PROMOTION,
        RECOVERY_STARTED, BEFORE_RECOVERY, AFTER_RECOVERY, BEFORE_ROLLBACK, AFTER_ROLLBACK, DIRECTORY_FORCE,
        BEFORE_RECORD_FORCE, AFTER_JOURNAL_RENAME, BEFORE_RECORD_WRITE, AFTER_RECORD_WRITE, AFTER_RECORD_FORCE,
        BEFORE_RECORD_RENAME, AFTER_RECORD_DIRECTORY_FORCE, BEFORE_ATOMIC_MOVE, AFTER_ATOMIC_MOVE,
        BEFORE_RECOVERY_CLOSE, BEFORE_PARENT_FORCE, AFTER_STAGE_MOVE, AFTER_CANDIDATE_MARKER, AFTER_ORIGINAL_MARKER }
    /** Receives deterministic restore transition notifications. */
    /* default */ @FunctionalInterface interface Observer {
        /** Observes one restore transition.
         * @param phase current transition point
         * @throws IOException injected failure
         */
        void accept(Phase phase) throws IOException;
    }
    /* default */ static void observeWith(Observer observer) { if (observer == null) { OBSERVER.remove(); } else { OBSERVER.set(observer); } }
    private static void observe(Phase phase) throws IOException {
        Observer observer = OBSERVER.get();
        if (observer != null) { observer.accept(phase); }
    }

    private record Journal(long revision, String id, String source, String manifest, String inventory,
            String live, String stage, String rollback, State state) {
        /* default */ Journal next(State next) { return new Journal(Math.incrementExact(revision), id, source, manifest,
                inventory, live, stage, rollback, next); }
    }

    /* default */ static FsRestoreCoordinator open(Path root, BackupLimits limits, FsPkiStoreOptions options, Clock clock)
            throws IOException {
        FsRestoreCoordinator result = new FsRestoreCoordinator(root, limits);
        try {
            result.reconcile(options, clock);
            result.cleanupAbandonedPreparation();
            return result;
        } catch (IOException | RuntimeException | Error failure) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
            try { result.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private FsRestoreCoordinator(Path root, BackupLimits limits) throws IOException {
        live = root.toAbsolutePath().normalize();
        parent = live.getParent();
        if (parent == null) { throw new IOException("RESTORE_ROOT_INVALID"); }
        this.limits = limits;
        Files.createDirectories(parent);
        control = parent.resolve("." + live.getFileName() + ".restore-control");
        Files.createDirectories(control);
        PlatformFs.requireOwnerOnlyCapable(control);
        PlatformFs.ops().restrictToOwner(control);
        processLock = FilesystemPkiStore.StoreOwnership.acquire(control.resolve("process.lock"));
        try { journal = readJournal(); }
        catch (IOException | RuntimeException failure) { processLock.closeSilently(); throw failure; } // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
    }

    /* default */ void lockRoot(Path root) throws IOException {
        Path canonical = root.toAbsolutePath().normalize();
        if (roots.containsKey(canonical)) { return; }
        Files.createDirectories(canonical.resolve(".lock"));
        roots.put(canonical, FilesystemPkiStore.StoreOwnership.acquire(canonical.resolve(".lock/store.lock")));
    }

    /* default */ Path work() throws IOException {
        Path directory = control.resolve("work");
        Files.createDirectories(directory);
        PlatformFs.ops().restrictToOwner(directory);
        return directory;
    }

    /* default */ Optional<RestoreStatus> status() {
        if (journal == null) { return Optional.empty(); }
        RestoreStatus.State state = uncertain ? RestoreStatus.State.UNCERTAIN : switch (journal.state()) {
            case COMPLETE -> RestoreStatus.State.ACTIVATED;
            case ROLLED_BACK -> RestoreStatus.State.FAILED;
            default -> RestoreStatus.State.STAGED;
        };
        return Optional.of(new RestoreStatus(new PkiId(journal.id()), state,
                uncertain ? List.of("RESTORE_OUTCOME_UNCERTAIN") : state == RestoreStatus.State.STAGED ? List.of("RESTORE_RESTART_REQUIRED")
                        : state == RestoreStatus.State.FAILED ? List.of("RESTORE_ACTIVATION_REJECTED") : List.of()));
    }

    /* default */ Optional<zeroecho.pki.api.backup.RestoreIdentity> identity() {
        return status().map(value -> new zeroecho.pki.api.backup.RestoreIdentity(
                new PkiId(journal.source()), journal.manifest(), value));
    }

    /* default */ RestoreStatus stage(BackupPreparation prepared, Path baseline, PkiId restoreId) throws IOException {
        Journal next;
        try { next = prepareJournal(prepared, baseline, restoreId); }
        catch (IOException rejection) { throw new zeroecho.pki.api.backup.RestoreRejectedException(rejection); }
        Path stage = parent.resolve(next.stage());
        atomicMove(prepared.directory(), stage);
        observe(Phase.AFTER_STAGE_MOVE);
        lockRoot(stage);
        writeMarker(stage, TEXT_CANDIDATE, next);
        observe(Phase.AFTER_CANDIDATE_MARKER);
        writeMarker(live, TEXT_ORIGINAL, next);
        observe(Phase.AFTER_ORIGINAL_MARKER);
        forceParent();
        publish(next);
        return status().orElseThrow();
    }

    /* default */ void discardUnpublished(PkiId restoreId, Optional<PkiId> previousRestoreId,
            String manifest) throws IOException {
        String id = restoreId.value();
        if (!UUID.fromString(id).toString().equals(id) || !manifest.matches("[0-9a-f]{64}")
                || previousRestoreId.map(restoreId::equals).orElse(false)) {
            throw new IllegalArgumentException("Invalid unpublished restore identity");
        }
        Optional<PkiId> current = journal == null ? Optional.empty() : Optional.of(new PkiId(journal.id()));
        if (uncertain || !current.equals(previousRestoreId)
                || journal != null && journal.state() != State.COMPLETE && journal.state() != State.ROLLED_BACK) {
            throw new IOException("RESTORE_OUTCOME_UNCERTAIN");
        }
        for (Path conflict : List.of(parent.resolve("." + live.getFileName() + ".restore-old-" + id),
                parent.resolve("." + live.getFileName() + ".restore-failed-" + id),
                control.resolve(ROLLBACK_PREFIX + id), control.resolve("recovery-" + id))) {
            if (Files.exists(conflict, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException(INVALID_ROOT_LAYOUT);
            }
        }
        Path stage = parent.resolve("." + live.getFileName() + ".restore-stage-" + id);
        Path original = live.resolve(MARKER + id);
        requireOptionalMarker(stage.resolve(MARKER + id), TEXT_CANDIDATE, id, manifest);
        requireOptionalMarker(original, TEXT_ORIGINAL, id, manifest);
        discardStage(stage);
        Files.deleteIfExists(original);
        FsBackupFiles.forceDirectory(live);
        forceParent();
    }

    private static void discardStage(Path stage) throws IOException {
        if (Files.exists(stage, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isDirectory(stage, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException(INVALID_ROOT_LAYOUT);
            }
            FsBackupFiles.deleteTree(stage);
        }
    }

    private static void requireOptionalMarker(Path path, String role, String id, String manifest) throws IOException {
        if (Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            requireBytes(path, ("1\n" + role + "\n" + id + "\n" + manifest + "\n")
                    .getBytes(StandardCharsets.US_ASCII));
        }
    }

    /** Called only during cold open, before any preparation can be admitted. */
    private void cleanupAbandonedPreparation() throws IOException {
        Path directory = control.resolve("work");
        if (!Files.exists(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        if (!Files.isDirectory(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(INVALID_ROOT_LAYOUT);
        }
        try (java.nio.file.DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                if (!(name.startsWith(".verification-") || name.startsWith(".baseline-"))
                        || !Files.isDirectory(entry, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("RESTORE_WORKSPACE_INVALID");
                }
                FsBackupFiles.deleteTree(entry);
            }
        }
        FsBackupFiles.forceDirectory(directory);
    }

    private Journal prepareJournal(BackupPreparation prepared, Path baseline, PkiId restoreId) throws IOException {
        if (uncertain || journal != null && journal.state() != State.COMPLETE && journal.state() != State.ROLLED_BACK) {
            throw new IOException("RESTORE_ALREADY_STAGED");
        }
        FsRestoreSafety.requireCompatible(baseline, prepared.directory(), limits);
        FsRestoreInventory.validate(live, limits);
        String id = restoreId.value();
        if (!UUID.fromString(id).toString().equals(id)) {
            throw new IllegalArgumentException("Restore identifier must be a canonical UUID");
        }
        requireUnusedRestoreId(id);
        Path stage = parent.resolve("." + live.getFileName() + ".restore-stage-" + id);
        Path rollback = parent.resolve("." + live.getFileName() + ".restore-old-" + id);
        String inventory = inventory(prepared.directory());
        Journal next = new Journal(journal == null ? 1L : Math.incrementExact(journal.revision()), id,
                prepared.backupId().value(), prepared.manifestSha256(), inventory, live.getFileName().toString(),
                stage.getFileName().toString(), rollback.getFileName().toString(), State.PREPARED);
        // Validate representation before creating durable intent or moving any root.
        encode(next);
        return next;
    }

    private void requireUnusedRestoreId(String id) throws IOException {
        if (journal != null && journal.id().equals(id)
                || Files.exists(parent.resolve("." + live.getFileName() + ".restore-stage-" + id))
                || Files.exists(parent.resolve("." + live.getFileName() + ".restore-old-" + id))
                || Files.exists(parent.resolve("." + live.getFileName() + ".restore-failed-" + id))
                || Files.exists(control.resolve(ROLLBACK_PREFIX + id))
                || Files.exists(control.resolve("recovery-" + id))
                || Files.exists(live.resolve(MARKER + id))) {
            throw new IOException("RESTORE_IDENTIFIER_ALREADY_USED");
        }
    }

    private void reconcile(FsPkiStoreOptions options, Clock clock) throws IOException {
        if (journal == null) { return; }
        if (journal.state() == State.COMPLETE || journal.state() == State.ROLLED_BACK) {
            if (!Files.isDirectory(live)) { throw new IOException(INVALID_ROOT_LAYOUT); }
            lockRoot(live);
            requireMarker(live, journal.state() == State.COMPLETE ? TEXT_CANDIDATE : TEXT_ORIGINAL);
            return;
        }
        Path stage = parent.resolve(journal.stage());
        Path old = parent.resolve(journal.rollback());
        Path failed = failed();
        for (Path root : List.of(live, stage, old, failed)) {
            if (Files.exists(root)) { lockRoot(root); }
        }
        if (Files.exists(control.resolve(ROLLBACK_PREFIX + journal.id()))) {
            rollback();
            return;
        }
        if (journal.state() == State.PREPARED && !advancePrepared(stage, old)) { return; }
        if (journal.state() == State.LIVE_MOVED && !promoteStaging(stage, old)) { return; }
        if (journal.state() == State.STAGING_PROMOTED && !recoverPromoted(old, options, clock)) { return; }
        if (journal.state() == State.NEW_ROOT_VERIFIED) {
            requireMarker(live, TEXT_CANDIDATE);
            requireMarker(old, TEXT_ORIGINAL);
            publish(journal.next(State.COMPLETE));
        }
    }

    private boolean advancePrepared(Path stage, Path old) throws IOException {
        if (Files.exists(live) && !Files.exists(old)) {
            requireMarker(live, TEXT_ORIGINAL);
            try {
                requireMarker(stage, TEXT_CANDIDATE);
                FsRestoreInventory.validate(live, limits);
                FsRestoreSafety.requireCompatible(live, stage, limits);
                requireInventory(stage);
            } catch (IOException | RuntimeException rejected) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
                publish(journal.next(State.ROLLED_BACK));
                return false;
            }
            observe(Phase.BEFORE_LIVE_MOVE);
            atomicMove(live, old);
            observe(Phase.AFTER_LIVE_MOVE);
            forceParent();
        } else if (Files.exists(live) || !Files.exists(old)) {
            throw new IOException(INVALID_ROOT_LAYOUT);
        }
        requireMarker(old, TEXT_ORIGINAL);
        // A rename observed after a crash may never have reached its parent's durable boundary.
        forceParent();
        publish(journal.next(State.LIVE_MOVED));
        return true;
    }

    private boolean promoteStaging(Path stage, Path old) throws IOException {
        requireMarker(old, TEXT_ORIGINAL);
        if (Files.exists(live)) {
            if (!Files.exists(live) || Files.exists(stage)) { throw new IOException(INVALID_ROOT_LAYOUT); }
        } else {
            try {
                requireMarker(stage, TEXT_CANDIDATE);
                requireInventory(stage);
                FsRestoreSafety.requireCompatible(old, stage, limits);
                observe(Phase.BEFORE_PROMOTION);
                atomicMove(stage, live);
                observe(Phase.AFTER_PROMOTION);
                forceParent();
            } catch (IOException | RuntimeException rejected) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
                durable(control.resolve(ROLLBACK_PREFIX + journal.id()), marker("rollback", journal));
                rollback();
                return false;
            }
        }
        requireMarker(live, TEXT_CANDIDATE);
        forceParent();
        publish(journal.next(State.STAGING_PROMOTED));
        return true;
    }

    private boolean recoverPromoted(Path old, FsPkiStoreOptions options, Clock clock) throws IOException {
        requireMarker(old, TEXT_ORIGINAL);
        requireMarker(live, TEXT_CANDIDATE);
        try {
            Path recovery = control.resolve("recovery-" + journal.id());
            if (Files.exists(recovery)) {
                requireBytes(recovery, marker("recovery", journal));
            } else {
                requireInventory(live);
                FsRestoreSafety.requireCompatible(old, live, limits);
                forceParent();
                durable(recovery, marker("recovery", journal));
            }
            observe(Phase.RECOVERY_STARTED);
            observe(Phase.BEFORE_RECOVERY);
            try (FilesystemPkiStore recovered = FilesystemPkiStore.openRestoreBorrowed(live, options, clock, limits)) {
                recovered.validateBackupDomainFiles();
                observe(Phase.BEFORE_RECOVERY_CLOSE);
            }
            observe(Phase.AFTER_RECOVERY);
            FsBackupFiles.forceTree(live);
            forceParent();
            publish(journal.next(State.NEW_ROOT_VERIFIED));
        } catch (IOException | RuntimeException rejected) { // NOPMD AvoidCatchingGenericException - Isolate an external/decoding failure at the existing recovery boundary while preserving cleanup and causes.
            durable(control.resolve(ROLLBACK_PREFIX + journal.id()), marker("rollback", journal));
            rollback();
            return false;
        }
        return true;
    }

    private void rollback() throws IOException {
        requireBytes(control.resolve(ROLLBACK_PREFIX + journal.id()), marker("rollback", journal));
        Path old = parent.resolve(journal.rollback());
        Path failed = failed();
        observe(Phase.BEFORE_ROLLBACK);
        if (Files.exists(old)) {
            requireMarker(old, TEXT_ORIGINAL);
            moveFailedCandidate(failed);
            atomicMove(old, live);
            forceParent();
        } else {
            requireMarker(live, TEXT_ORIGINAL);
            if (Files.exists(failed)) { requireMarker(failed, TEXT_CANDIDATE); }
        }
        forceParent();
        observe(Phase.AFTER_ROLLBACK);
        publish(journal.next(State.ROLLED_BACK));
    }

    private void moveFailedCandidate(Path failed) throws IOException {
        if (Files.exists(live)) {
            requireMarker(live, TEXT_CANDIDATE);
            if (Files.exists(failed)) { throw new IOException(INVALID_ROOT_LAYOUT); }
            atomicMove(live, failed);
            forceParent();
        }
    }

    private Path failed() { return parent.resolve("." + live.getFileName() + ".restore-failed-" + journal.id()); }

    private void atomicMove(Path from, Path to) throws IOException {
        if (Files.exists(to)) { throw new IOException(INVALID_ROOT_LAYOUT); }
        observe(Phase.BEFORE_ATOMIC_MOVE);
        Files.move(from, to, StandardCopyOption.ATOMIC_MOVE);
        FilesystemPkiStore.StoreOwnership owner = roots.remove(from); // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
        if (owner != null) { roots.put(to, owner); }
        observe(Phase.AFTER_ATOMIC_MOVE);
    }

    private void forceParent() throws IOException {
        observe(Phase.BEFORE_PARENT_FORCE);
        FsBackupFiles.forceDirectory(parent);
        observe(Phase.DIRECTORY_FORCE);
    }

    private void requireInventory(Path root) throws IOException {
        if (!journal.inventory().equals(inventory(root))) { throw new IOException("RESTORE_CANDIDATE_CHANGED"); }
    }

    private String inventory(Path root) throws IOException {
        List<Path> ordered = inventoryPaths(root);
        MessageDigest digest = FsBackupFiles.digest();
        byte[] buffer = new byte[FsBackupFiles.BUFFER_BYTES];
        long total = 0;
        for (Path path : ordered) {
            long length = Files.size(path);
            if (length > limits.entryBytes() || length > limits.expandedBytes() - total) {
                throw new IOException("RESTORE_CANDIDATE_LIMIT");
            }
            total += length;
            digest.update((root.relativize(path).toString().replace(java.io.File.separatorChar, '/') + "\n" + length + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            try (InputStream input = Files.newInputStream(path)) {
                long remaining = length;
                int count;
                while ((count = input.read(buffer)) != -1) {
                    if (count == 0 || count > remaining) { throw new IOException("RESTORE_CANDIDATE_CHANGED"); }
                    digest.update(buffer, 0, count);
                    remaining -= count;
                }
                if (remaining != 0) { throw new IOException("RESTORE_CANDIDATE_CHANGED"); }
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private List<Path> inventoryPaths(Path root) throws IOException {
        List<Path> ordered = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(root, 8)) {
            java.util.Iterator<Path> iterator = paths.iterator();
            int visited = 0;
            while (iterator.hasNext()) {
                Path path = iterator.next();
                if (++visited > limits.entryCount()) { throw new IOException("RESTORE_CANDIDATE_LIMIT"); }
                if (Files.isSymbolicLink(path)) { throw new IOException("RESTORE_CANDIDATE_INVENTORY"); }
                if (Files.isDirectory(path) && root.relativize(path).getNameCount() < 8) { continue; }
                if (!Files.isRegularFile(path)) { throw new IOException("RESTORE_CANDIDATE_INVENTORY"); }
                String relative = root.relativize(path).toString().replace(java.io.File.separatorChar, '/');
                if (relative.matches("\\.restore-role-[0-9a-f-]{36}") || ".lock/store.lock".equals(relative)) { continue; }
                FsBackupFiles.validatePath(relative, limits);
                if (!FsBackupFiles.allowed(relative) || ordered.size() >= limits.entryCount()) {
                    throw new IOException("RESTORE_CANDIDATE_INVENTORY");
                }
                ordered.add(path);
            }
        }
        ordered.sort(Path::compareTo);
        return ordered;
    }

    private void publish(Journal next) throws IOException {
        try { durable(control.resolve("journal"), encode(next)); }
        catch (IOException failure) {
            journal = next;
            uncertain = true;
            throw new IOException("RESTORE_OUTCOME_UNCERTAIN", failure);
        }
        journal = next;
        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "Restore coordinator transition: restoreId={0}, state={1}, revision={2}",
                    new Object[] {next.id(), next.state(), next.revision()});
        }
        try { observe(Phase.JOURNAL); }
        catch (IOException failure) {
            uncertain = true;
            throw new IOException("RESTORE_OUTCOME_UNCERTAIN", failure);
        }
    }

    private void durable(Path target, byte[] bytes) throws IOException {
        Path temporary = Files.createTempFile(control, ".record-", ".tmp");
        try {
            observe(Phase.BEFORE_RECORD_WRITE);
            Files.write(temporary, bytes, StandardOpenOption.TRUNCATE_EXISTING);
            observe(Phase.AFTER_RECORD_WRITE);
            observe(Phase.BEFORE_RECORD_FORCE);
            FsBackupFiles.force(temporary);
            observe(Phase.AFTER_RECORD_FORCE);
            observe(Phase.BEFORE_RECORD_RENAME);
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            if (JOURNAL_NAME.equals(target.getFileName().toString())) { observe(Phase.AFTER_JOURNAL_RENAME); }
            FsBackupFiles.forceDirectory(control);
            observe(Phase.AFTER_RECORD_DIRECTORY_FORCE);
        } finally { Files.deleteIfExists(temporary); }
    }

    private static byte[] encode(Journal value) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bytes)) {
            output.writeInt(JOURNAL_VERSION);
            output.writeLong(value.revision());
            for (String field : List.of(value.id(), value.source(), value.manifest(), value.inventory(),
                    value.live(), value.stage(), value.rollback(), value.state().name())) {
                output.writeUTF(field);
            }
        }
        byte[] payload = bytes.toByteArray();
        if (payload.length > JOURNAL_LIMIT - 32) { throw new IOException("RESTORE_JOURNAL_LIMIT"); }
        bytes.write(FsBackupFiles.digest().digest(payload));
        return bytes.toByteArray();
    }

    private void validateJournal(Journal value) throws IOException {
        String prefix = "." + live.getFileName();
        if (value.revision() <= 0 || !UUID.fromString(value.id()).toString().equals(value.id())
                || value.source().isBlank() || !value.manifest().matches("[0-9a-f]{64}")
                || !value.inventory().matches("[0-9a-f]{64}") || !value.live().equals(live.getFileName().toString())
                || !value.stage().equals(prefix + ".restore-stage-" + value.id())
                || !value.rollback().equals(prefix + ".restore-old-" + value.id())) {
            throw new IOException("RESTORE_JOURNAL_INVALID");
        }
    }

    private Journal readJournal() throws IOException {
        Path path = control.resolve("journal");
        if (!Files.exists(path)) { return null; }
        long length = Files.size(path);
        if (length < 44 || length > JOURNAL_LIMIT) { throw new IOException("RESTORE_JOURNAL_INVALID"); }
        byte[] bytes = boundedRead(path, JOURNAL_LIMIT);
        int boundary = bytes.length - 32;
        if (!MessageDigest.isEqual(FsBackupFiles.digest().digest(Arrays.copyOf(bytes, boundary)),
                Arrays.copyOfRange(bytes, boundary, bytes.length))) { throw new IOException("RESTORE_JOURNAL_INVALID"); }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes, 0, boundary))) {
            if (input.readInt() != JOURNAL_VERSION) { throw new IOException("RESTORE_JOURNAL_VERSION"); }
            Journal value = new Journal(input.readLong(), input.readUTF(), input.readUTF(), input.readUTF(),
                    input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF(), State.valueOf(input.readUTF()));
            if (input.read() != -1) { throw new IOException("RESTORE_JOURNAL_INVALID"); }
            validateJournal(value);
            return value;
        } catch (IllegalArgumentException invalid) { throw new IOException("RESTORE_JOURNAL_INVALID", invalid); }
    }

    private static byte[] marker(String role, Journal value) {
        return ("1\n" + role + "\n" + value.id() + "\n" + value.manifest() + "\n").getBytes(StandardCharsets.US_ASCII);
    }

    private void writeMarker(Path root, String role, Journal value) throws IOException {
        Path temporary = Files.createTempFile(root, ".restore-marker-", ".tmp");
        try {
            Files.write(temporary, marker(role, value), StandardOpenOption.TRUNCATE_EXISTING);
            FsBackupFiles.force(temporary);
            Files.move(temporary, root.resolve(MARKER + value.id()), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            FsBackupFiles.forceDirectory(root);
        } finally { Files.deleteIfExists(temporary); }
    }

    private void requireMarker(Path root, String role) throws IOException { requireBytes(root.resolve(MARKER + journal.id()), marker(role, journal)); }
    private static void requireBytes(Path path, byte[] expected) throws IOException {
        if (Files.size(path) != expected.length || !MessageDigest.isEqual(boundedRead(path, expected.length), expected)) {
            throw new IOException("RESTORE_MARKER_INVALID");
        }
    }

    /* default */ static byte[] boundedRead(Path path, int maximum) throws IOException {
        if (!Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.size(path) > maximum) {
            throw new IOException("RESTORE_RECORD_INVALID");
        }
        try (InputStream input = Files.newInputStream(path)) {
            byte[] bytes = input.readNBytes(maximum + 1);
            if (bytes.length > maximum) { throw new IOException("RESTORE_RECORD_INVALID"); }
            return bytes;
        }
    }

    @Override public void close() throws IOException {
        IOException failure = null;
        for (FilesystemPkiStore.StoreOwnership lock : roots.values()) { // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
            try { lock.close(); } catch (IOException exception) {
                if (failure == null) { failure = exception; } else { failure.addSuppressed(exception); }
            }
        }
        roots.clear();
        try { processLock.close(); } catch (IOException exception) {
            if (failure == null) { failure = exception; } else { failure.addSuppressed(exception); }
        }
        if (failure != null) { throw failure; }
    }
}
