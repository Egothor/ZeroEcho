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

import java.nio.CharBuffer;
import java.nio.file.attribute.PosixFilePermission;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.HexFormat;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Logger;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.spi.store.MetadataStoreId;

/**
 * Exclusive-writer durable append-only revocation transition log.
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
final class FilesystemRevocationLog implements AutoCloseable {

    private static final Logger LOGGER = Logger.getLogger(FilesystemRevocationLog.class.getName());
    private static final String CAPABILITY_WARNING =
            "Durable revocation-log creation durability is limited; continuing in best-effort mode";
    private static final String INDEX_DIRECTORY_WARNING =
            "Revocation current-index directory durability is limited; continuing in best-effort mode";
    private static final byte[] INDEX_KEY_DOMAIN =
            "ZeroEcho revocation current index key v1".getBytes(StandardCharsets.US_ASCII);
    private static final HexFormat HEX = HexFormat.of();
    private static final Set<String> LOCAL_FILE_SYSTEMS =
            Set.of("apfs", "btrfs", "ext2", "ext3", "ext4", "tmpfs", "ufs", "xfs", "zfs");
    private static final Set<PosixFilePermission> OWNER_ONLY =
            PosixFilePermissions.fromString("rw-------");

    private final FileChannel channel;
    private final FileLock writerLock;
    private final MetadataStoreId storeId;
    private final CredentialAuthority credentialAuthority;
    private final FaultInjector faults;
    private final ReentrantLock appendLock = new ReentrantLock();
    private final RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
    private final Map<PkiId, LatestState> latest;
    private long globalRevision;
    private OptionalLong finalRecordStart;
    private long lastCompleteRecordBoundary;
    private RevocationTransitionFrameCodec.Commitment globalCommitment;
    private long scanInvocations;
    private State state = State.OPEN;

    private FilesystemRevocationLog(
            FileChannel channel,
            FileLock writerLock,
            MetadataStoreId storeId,
            CredentialAuthority credentialAuthority,
            FaultInjector faults,
            RecoveryResult recovery,
            boolean retainCurrentState) {
        this.channel = channel;
        this.writerLock = writerLock;
        this.storeId = storeId;
        this.credentialAuthority = credentialAuthority;
        this.faults = faults;
        latest = retainCurrentState ? new HashMap<>(recovery.latestStates()) : null;
        globalRevision = recovery.globalRevision();
        finalRecordStart = recovery.finalRecordStart();
        lastCompleteRecordBoundary = recovery.lastCompleteRecordBoundary();
        globalCommitment = recovery.globalCommitment();
        scanInvocations = 1L;
    }

    /**
     * Creates an authoritative revocation log retaining an in-memory per-credential predecessor map.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param storeId stable store identity written into the new log; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog create(
            Path logPath, MetadataStoreId storeId, CredentialAuthority credentialAuthority) throws IOException {
        return create(logPath, storeId, credentialAuthority,
                DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /**
     * Creates an authoritative production log whose callers supply exact predecessor records.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param storeId stable store identity written into the new log; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog createProduction(
            Path logPath, MetadataStoreId storeId, CredentialAuthority credentialAuthority) throws IOException {
        return Lifecycle.create(logPath, storeId, credentialAuthority,
                DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE, false);
    }

    /**
     * Opens an authoritative production log without retaining a per-credential predecessor map.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param expectedStoreId exact required metadata store identity; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog openProduction(
            Path logPath, MetadataStoreId expectedStoreId, CredentialAuthority credentialAuthority)
            throws IOException {
        return Lifecycle.open(logPath, expectedStoreId, credentialAuthority,
                DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE, false);
    }

    /**
     * Opens and replays an authoritative revocation log retaining per-credential predecessor state.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param expectedStoreId exact required metadata store identity; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog open(
            Path logPath, MetadataStoreId expectedStoreId, CredentialAuthority credentialAuthority)
            throws IOException {
        return open(logPath, expectedStoreId, credentialAuthority,
                DefaultCapabilityProfile.INSTANCE, FaultInjector.NONE);
    }

    /**
     * Creates an authoritative revocation log retaining an in-memory per-credential predecessor map.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param storeId stable store identity written into the new log; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @param capabilities filesystem durability capability profile; must not be null
     * @param faults deterministic fault callback; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog create(
            Path logPath,
            MetadataStoreId storeId,
            CredentialAuthority credentialAuthority,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.create(logPath, storeId, credentialAuthority, capabilities, faults, true);
    }

    /**
     * Opens and replays an authoritative revocation log retaining per-credential predecessor state.
     *
     * <p>The returned log owns its writer lock and channel. The caller must close it;
     * partial initialization closes acquired resources on failure.</p>
     *
     * @param logPath authoritative revocation transition log path; must not be null
     * @param expectedStoreId exact required metadata store identity; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @param capabilities filesystem durability capability profile; must not be null
     * @param faults deterministic fault callback; must not be null
     * @return open exclusively owned authoritative revocation log
     * @throws IOException if format validation, replay, filesystem capability, or writer ownership fails
     * @throws NullPointerException if a required argument is null
     */
    /* default */ static FilesystemRevocationLog open(
            Path logPath,
            MetadataStoreId expectedStoreId,
            CredentialAuthority credentialAuthority,
            CapabilityProfile capabilities,
            FaultInjector faults) throws IOException {
        return Lifecycle.open(logPath, expectedStoreId, credentialAuthority, capabilities, faults, true);
    }

    /**
     * Returns the exact authoritative revocation log store identity.
     *
     * @return exact authoritative revocation log store identity
     */
    /* default */ MetadataStoreId storeId() {
        return storeId;
    }

    /**
     * Validates and force-appends one legal credential transition before advancing the in-memory endpoint.
     *
     * <p>The overload without a predecessor requires map-tracking mode; production mode
     * uses the overload carrying the exact predecessor. Uncertain append/force completion
     * fences further appends until close and recovery.</p>
     *
     * @param credentialId exact store-local credential identity; must not be null
     * @param transition legal next transition bound to this credential; must not be null
     * @return complete authoritative record after its file force succeeds
     * @throws IOException if credential authority or writer authority cannot be established
     * @throws NullPointerException if credentialId or transition is null, or map-mode append is used
     * without a predecessor map
     * @throws IllegalArgumentException if the transition is illegal for its predecessor
     * @throws IllegalStateException if the log is closed
     * @throws OutcomeUnknownException if append or file-force completion is uncertain
     */
    /* default */ RevocationTransitionFrameCodec.CompleteRecord append(
            PkiId credentialId, RevocationTransition transition) throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(transition, "transition");
        // Credential authority validation performs no log I/O and is intentionally
        // outside the global append/force critical section.
        credentialAuthority.requireCredential(credentialId);
        appendLock.lock();
        try {
            requireOperational();
            RevocationTransitionFrameCodec.TransitionData data = nextData(credentialId, transition);
            TransitionRules.validate(data, latest.get(credentialId));
            try {
                channel.position(channel.size());
                faults.fail(FaultPoint.APPEND);
                RevocationTransitionFrameCodec.CompleteRecord record = codec.write(channel, data);
                faults.fail(FaultPoint.FILE_FORCE);
                channel.force(true);
                LatestState next = latestState(record);
                latest.put(credentialId, next);
                globalRevision = data.globalRevision();
                finalRecordStart = OptionalLong.of(record.recordOffset());
                lastCompleteRecordBoundary = record.recordEnd();
                globalCommitment = record.commitment();
                return record;
            } catch (IOException failure) {
                state = State.RECOVERY_REQUIRED;
                throw new OutcomeUnknownException(failure);
            }
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Validates and force-appends one legal credential transition before advancing the in-memory endpoint.
     *
     * <p>The overload without a predecessor requires map-tracking mode; production mode
     * uses the overload carrying the exact predecessor. Uncertain append/force completion
     * fences further appends until close and recovery.</p>
     *
     * @param credentialId exact store-local credential identity; must not be null
     * @param transition legal next transition bound to this credential; must not be null
     * @param previous exact prior credential transition, or null for the first transition
     * @return complete authoritative record after its file force succeeds
     * @throws IOException if credential/writer authority, predecessor identity, transition legality, or
     * the next revision cannot be established
     * @throws NullPointerException if credentialId or transition is null
     * @throws IllegalStateException if closed or the predecessor overload is used outside production mode
     * @throws OutcomeUnknownException if append or file-force completion is uncertain
     */
    /* default */ RevocationTransitionFrameCodec.CompleteRecord append(
            PkiId credentialId, RevocationTransition transition,
            RevocationTransitionFrameCodec.CompleteRecord previous) throws IOException {
        Objects.requireNonNull(credentialId, "credentialId");
        Objects.requireNonNull(transition, "transition");
        if (latest != null) {
            throw new IllegalStateException("External predecessor append requires production log mode");
        }
        credentialAuthority.requireCredential(credentialId);
        appendLock.lock();
        try {
            requireOperational();
            RevocationTransitionFrameCodec.TransitionData data = nextData(
                    credentialId, transition, previous);
            validateTransition(data, previous);
            try {
                channel.position(channel.size());
                faults.fail(FaultPoint.APPEND);
                RevocationTransitionFrameCodec.CompleteRecord record = codec.write(channel, data);
                faults.fail(FaultPoint.FILE_FORCE);
                channel.force(true);
                globalRevision = data.globalRevision();
                finalRecordStart = OptionalLong.of(record.recordOffset());
                lastCompleteRecordBoundary = record.recordEnd();
                globalCommitment = record.commitment();
                return record;
            } catch (IOException failure) {
                state = State.RECOVERY_REQUIRED;
                throw new OutcomeUnknownException(failure);
            }
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Sequentially validates the authoritative log and provisionally replays records to the supplied sink.
     *
     * <p>The no-argument overload validates without an external replay sink. A successful
     * scan completes the sink; a failed scan aborts its provisional state.</p>
     *
     * @param sink borrowed provisional replay sink; must not be null
     * @return validated complete-prefix recovery result
     * @throws IOException if log framing, credential authority, writer authority, or replay fails
     * @throws IllegalStateException if the log is closed
     */
    /* default */ RecoveryResult scan(RecoverySink sink) throws IOException {
        appendLock.lock();
        try {
            requireOpenAuthority();
            scanInvocations++;
            return scanChannel(channel, storeId, credentialAuthority, sink);
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Sequentially validates the authoritative log and provisionally replays records to the supplied sink.
     *
     * <p>The no-argument overload validates without an external replay sink. A successful
     * scan completes the sink; a failed scan aborts its provisional state.</p>
     *
     * @return validated complete-prefix recovery result
     * @throws IOException if log framing, credential authority, writer authority, or replay fails
     * @throws IllegalStateException if the log is closed
     */
    /* default */ RecoveryResult scan() throws IOException {
        return scan(RecoverySink.NONE);
    }

    /**
     * Returns the number of credential identities retained in map-tracking mode.
     *
     * @return size of the latest-state map, including terminal revoked states
     * @throws IOException if writer authority is no longer valid
     * @throws IllegalStateException if closed or production mode does not retain a current-state map
     */
    /* default */ int activeCredentialCount() throws IOException {
        appendLock.lock();
        try {
            requireOpenAuthority();
            if (latest == null) {
                throw new IllegalStateException("Production log does not retain current credential state");
            }
            return latest.size();
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Observes completed or attempted full-log scans under the append lock.
     *
     * @return lifetime scan invocation count, including opening replay
     */
    /* default */ long scanInvocationCount() {
        appendLock.lock();
        try {
            return scanInvocations;
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Observes the current authoritative log revision under writer authority.
     *
     * @return last force-acknowledged global revision
     * @throws IOException if writer authority is invalid
     * @throws IllegalStateException if the log is closed
     */
    /* default */ long currentGlobalRevision() throws IOException {
        appendLock.lock();
        try {
            requireOpenAuthority();
            return globalRevision;
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Captures one immutable authoritative prefix without retaining the append lock.
     *
     * <p>Records appended after this method returns belong to a later prefix and do
     * not change the returned target.</p>
     * @return immutable exact authoritative prefix endpoint
     * @throws IOException if writer authority is invalid or the log requires recovery
     * @throws IllegalStateException if the log is closed
     */
    /* default */ RecoveryTarget recoveryTarget() throws IOException {
        appendLock.lock();
        try {
            requireOperational();
            return new RecoveryTarget(
                    storeId, globalRevision, finalRecordStart,
                    lastCompleteRecordBoundary, globalCommitment);
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Tests whether uncertain append or writer ownership has fenced this log instance.
     *
     * @return true if close and recovery are required before further appends
     */
    /* default */ boolean recoveryRequired() {
        appendLock.lock();
        try {
            return state == State.RECOVERY_REQUIRED;
        } finally {
            appendLock.unlock();
        }
    }

    /**
     * Validates a borrowed log channel and replays its complete authoritative prefix.
     *
     * @param channel borrowed channel; remains owned by the caller
     * @param expectedStoreId exact required metadata store identity; must not be null
     * @param credentialAuthority borrowed credential ownership validator; must not be null
     * @param sink borrowed provisional replay sink; must not be null
     * @return validated complete-prefix recovery result
     * @throws IOException if framing, commitments, credential authority, or sink callbacks fail
     */
    /* default */ static RecoveryResult scanChannel(
            FileChannel channel,
            MetadataStoreId expectedStoreId,
            CredentialAuthority credentialAuthority,
            RecoverySink sink) throws IOException {
        return Scanner.scan(channel, expectedStoreId, credentialAuthority, sink);
    }

    /**
     * Validates one decoded transition against the exact optional prior credential record.
     *
     * @param data decoded candidate transition; must not be null
     * @param previous exact prior credential transition, or null for the first transition
     * @throws IOException if the transition is illegal for its predecessor
     * @throws NullPointerException if data is null
     */
    /* default */ static void validateTransition(
            RevocationTransitionFrameCodec.TransitionData data,
            RevocationTransitionFrameCodec.CompleteRecord previous) throws IOException {
        Objects.requireNonNull(data, "data");
        LatestState prior = previous == null ? null : latestState(previous);
        try {
            TransitionRules.validate(data, prior);
        } catch (IllegalArgumentException invalid) {
            throw new IOException("Revocation transition is not legal", invalid);
        }
    }

    /**
     * Logs the advisory derived-index directory durability warning without changing authority state.
     */
    /* default */ static void warnIndexDirectoryDurability() {
        try {
            LOGGER.warning(INDEX_DIRECTORY_WARNING);
        } catch (IllegalStateException ignored) {
            // Advisory logging cannot alter derived-index publication.
        }
    }

    /**
     * Derives a domain-separated SHA-256 index key from a bounded strict-UTF-8 credential identity.
     *
     * @param credentialId exact store-local credential identity; must not be null
     * @return lowercase 64-character hexadecimal index-key digest
     * @throws IOException if the identity is empty, malformed UTF-8, or exceeds the technical byte bound
     * @throws NullPointerException if credentialId is null
     */
    /* default */ static String indexKeyDigest(PkiId credentialId) throws IOException {
        byte[] identity = strictUtf8(credentialId.value());
        if (identity.length == 0
                || identity.length > RevocationTransitionFrameCodec.MAX_COMPONENT_BYTES) {
            throw new IOException(
                    "Revocation credential identity exceeds its technical bound");
        }
        MessageDigest digest = sha256();
        digest.update(INDEX_KEY_DOMAIN);
        digest.update(ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.BIG_ENDIAN)
                .putInt(identity.length).array());
        digest.update(identity);
        return HEX.formatHex(digest.digest());
    }

    private static byte[] strictUtf8(String value) throws IOException {
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            return result;
        } catch (CharacterCodingException malformed) {
            throw new IOException(
                    "Revocation credential identity is not strict UTF-8", malformed);
        }
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }

    private RevocationTransitionFrameCodec.TransitionData nextData(
            PkiId credentialId, RevocationTransition transition) throws IOException {
        LatestState previous = latest.get(credentialId);
        final long nextGlobal;
        try {
            nextGlobal = Math.addExact(globalRevision, 1L);
        } catch (ArithmeticException exhausted) {
            throw new IOException("Global revocation revision is exhausted", exhausted);
        }
        if (previous == null) {
            return new RevocationTransitionFrameCodec.TransitionData(
                    nextGlobal, globalCommitment, credentialId,
                    OptionalLong.empty(), Optional.empty(), transition);
        }
        return new RevocationTransitionFrameCodec.TransitionData(
                nextGlobal, globalCommitment, credentialId,
                OptionalLong.of(previous.globalRevision()),
                Optional.of(previous.commitment()), transition);
    }

    private RevocationTransitionFrameCodec.TransitionData nextData(
            PkiId credentialId, RevocationTransition transition,
            RevocationTransitionFrameCodec.CompleteRecord previous) throws IOException {
        final long nextGlobal;
        try {
            nextGlobal = Math.addExact(globalRevision, 1L);
        } catch (ArithmeticException exhausted) {
            throw new IOException("Global revocation revision is exhausted", exhausted);
        }
        if (previous == null) {
            return new RevocationTransitionFrameCodec.TransitionData(
                    nextGlobal, globalCommitment, credentialId,
                    OptionalLong.empty(), Optional.empty(), transition);
        }
        if (!previous.data().credentialId().equals(credentialId)) {
            throw new IOException("Revocation predecessor identity is invalid");
        }
        return new RevocationTransitionFrameCodec.TransitionData(
                nextGlobal, globalCommitment, credentialId,
                OptionalLong.of(previous.data().globalRevision()),
                Optional.of(previous.commitment()), transition);
    }

    private static void validateGlobal(
            RevocationTransitionFrameCodec.CompleteRecord record,
            long currentRevision,
            RevocationTransitionFrameCodec.Commitment currentCommitment) throws CorruptLogException {
        final long expected;
        try {
            expected = Math.addExact(currentRevision, 1L);
        } catch (ArithmeticException exhausted) {
            throw new CorruptLogException("Global revocation revision is exhausted", exhausted);
        }
        if (record.data().globalRevision() != expected
                || !record.data().previousGlobalCommitment().equals(currentCommitment)) {
            throw new CorruptLogException("Revocation global history chain is invalid");
        }
    }

    private static LatestState latestState(RevocationTransitionFrameCodec.CompleteRecord record) {
        return new LatestState(
                record.data().globalRevision(), record.commitment(),
                record.data().transition(), record.recordOffset());
    }

    private static void repairTail(FileChannel channel, long boundary, FaultInjector faults) throws IOException {
        faults.fail(FaultPoint.TAIL_TRUNCATE);
        channel.truncate(boundary);
        faults.fail(FaultPoint.TAIL_FORCE);
        channel.force(true);
        faults.fail(FaultPoint.TAIL_VERIFY);
        if (channel.size() != boundary) {
            throw new IOException("Revocation log tail repair verification failed");
        }
        channel.position(boundary);
    }

    private static Path requireParent(Path logPath) throws IOException {
        Objects.requireNonNull(logPath, "logPath");
        Path parent = logPath.getParent();
        if (parent == null || logPath.getFileName() == null
                || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(parent)) {
            throw new IOException("Revocation log target has no trusted regular parent directory");
        }
        return parent;
    }

    private static CapabilityObservation observeCapabilities(
            Path parent, CapabilityProfile capabilities) {
        boolean posix = false;
        boolean local = false;
        boolean limited = false;
        try {
            posix = capabilities.posixAvailable(parent);
            if (!posix) {
                limited = true;
            }
        } catch (IOException unavailable) {
            limited = true;
        }
        try {
            local = capabilities.localFileSystem(parent);
            if (!local) {
                limited = true;
            }
        } catch (IOException unavailable) {
            limited = true;
        }
        return new CapabilityObservation(posix, local, limited);
    }

    private void requireOperational() throws IOException {
        requireOpenAuthority();
        if (state == State.RECOVERY_REQUIRED) {
            throw new IOException("Revocation log requires close and recovery");
        }
    }

    private void requireOpenAuthority() throws IOException {
        if (state == State.CLOSED || !channel.isOpen()) {
            throw new IllegalStateException("Revocation log is closed");
        }
        if (!writerLock.isValid()) {
            state = State.RECOVERY_REQUIRED;
            throw new IOException("Revocation log writer authority is invalid");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        appendLock.lock();
        try {
            if (state == State.CLOSED) {
                return;
            }
            IOException failure = null;
            try {
                if (writerLock.isValid()) {
                    writerLock.release();
                }
            } catch (IOException releaseFailure) {
                failure = releaseFailure;
            }
            try {
                channel.close();
            } catch (IOException closeFailure) {
                failure = appendFailure(failure, closeFailure);
            }
            if (latest != null) {
                latest.clear();
            }
            state = State.CLOSED;
            if (failure != null) {
                throw failure;
            }
        } finally {
            appendLock.unlock();
        }
    }

    private static IOException appendFailure(IOException first, IOException later) {
        if (first == null) {
            return later;
        }
        first.addSuppressed(later);
        return first;
    }

    /**
     * Isolates create and reopen mechanics from the retained writer authority.
     */
    private static final class Lifecycle {
        private static FilesystemRevocationLog create(
                Path logPath,
                MetadataStoreId storeId,
                CredentialAuthority credentialAuthority,
                CapabilityProfile capabilities,
                FaultInjector faults,
                boolean retainCurrentState) throws IOException {
            requireLifecycleArguments(storeId, credentialAuthority, capabilities, faults);
            Path parent = requireParent(logPath);
            CapabilityObservation observation = observeCapabilities(parent, capabilities);
            Resources resources = Resources.acquire(logPath, true, observation.posix());
            try {
                writeNewPreamble(resources.channel, storeId, faults);
                boolean parentForced = forceParent(capabilities, parent);
                boolean limited = observation.limited() || !parentForced;
                if (limited) {
                    warnLimitedDurability();
                }
                RecoveryResult empty = RecoveryResult.empty(storeId);
                FilesystemRevocationLog log = new FilesystemRevocationLog(
                        resources.channel, resources.writerLock, storeId,
                        credentialAuthority, faults, empty, retainCurrentState);
                log.scanInvocations = 0L;
                return log;
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static FilesystemRevocationLog open(
                Path logPath,
                MetadataStoreId expectedStoreId,
                CredentialAuthority credentialAuthority,
                CapabilityProfile capabilities,
                FaultInjector faults,
                boolean retainCurrentState) throws IOException {
            requireLifecycleArguments(expectedStoreId, credentialAuthority, capabilities, faults);
            Path parent = requireParent(logPath);
            CapabilityObservation observation = observeCapabilities(parent, capabilities);
            Resources resources = Resources.acquire(logPath, false, observation.posix());
            try {
                ProvisionalRecovery provisional = retainCurrentState
                        ? Scanner.scanProvisional(resources.channel, expectedStoreId,
                                credentialAuthority, RecoverySink.NONE)
                        : ScalarScanner.scanProvisional(resources.channel, expectedStoreId,
                                credentialAuthority);
                boolean completed = false;
                try {
                    RecoveryResult recovered = repairIfNecessary(
                            resources.channel, provisional.result(), faults);
                    resources.channel.position(recovered.lastCompleteRecordBoundary());
                    faults.fail(FaultPoint.OPEN_FORCE);
                    resources.channel.force(true);
                    provisional.sink().complete();
                    completed = true;
                    if (observation.limited()) {
                        warnLimitedDurability();
                    }
                    return new FilesystemRevocationLog(
                            resources.channel, resources.writerLock, expectedStoreId,
                            credentialAuthority, faults, recovered, retainCurrentState);
                } finally {
                    if (!completed) {
                        provisional.sink().abort();
                    }
                }
            } catch (IOException failure) {
                resources.closeAfterFailure(failure);
                throw failure;
            }
        }

        private static void requireLifecycleArguments(
                MetadataStoreId storeId,
                CredentialAuthority credentialAuthority,
                CapabilityProfile capabilities,
                FaultInjector faults) {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(credentialAuthority, "credentialAuthority");
            Objects.requireNonNull(capabilities, "capabilities");
            Objects.requireNonNull(faults, "faults");
        }

        private static void writeNewPreamble(
                FileChannel channel, MetadataStoreId storeId, FaultInjector faults) throws IOException {
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            channel.position(0L);
            codec.writePreamble(channel, storeId);
            faults.fail(FaultPoint.FILE_FORCE);
            channel.force(true);
        }

        private static boolean forceParent(CapabilityProfile capabilities, Path parent) {
            try {
                capabilities.forceParent(parent);
                return true;
            } catch (IOException | UnsupportedOperationException unavailable) {
                return false;
            }
        }

        private static void warnLimitedDurability() {
            try {
                LOGGER.warning(CAPABILITY_WARNING);
            } catch (IllegalStateException ignored) {
                // Advisory logging failure cannot invalidate an otherwise usable log.
            }
        }

        private static RecoveryResult repairIfNecessary(
                FileChannel channel, RecoveryResult recovered, FaultInjector faults) throws IOException {
            if (!recovered.incompleteTail()) {
                return recovered;
            }
            repairTail(channel, recovered.lastCompleteRecordBoundary(), faults);
            return recovered.afterTailRepair();
        }
    }

    /**
     * One-pass scanner retaining only the latest finite state per credential.
     */
    private static final class Scanner {
        private static RecoveryResult scan(
                FileChannel channel,
                MetadataStoreId expectedStoreId,
                CredentialAuthority credentialAuthority,
                RecoverySink sink) throws IOException {
            ProvisionalRecovery provisional = scanProvisional(
                    channel, expectedStoreId, credentialAuthority, sink);
            boolean completed = false;
            try {
                provisional.sink().complete();
                completed = true;
                return provisional.result();
            } finally {
                if (!completed) {
                    provisional.sink().abort();
                }
            }
        }

        private static ProvisionalRecovery scanProvisional(
                FileChannel channel,
                MetadataStoreId expectedStoreId,
                CredentialAuthority credentialAuthority,
                RecoverySink sink) throws IOException {
            Objects.requireNonNull(channel, "channel");
            Objects.requireNonNull(expectedStoreId, "expectedStoreId");
            Objects.requireNonNull(credentialAuthority, "credentialAuthority");
            Objects.requireNonNull(sink, "sink");
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            MetadataStoreId actualStoreId = codec.readPreamble(channel);
            if (!expectedStoreId.equals(actualStoreId)) {
                throw corrupt("Revocation log belongs to another store");
            }
            ScanState state = new ScanState(actualStoreId, channel.size());
            boolean scanned = false;
            try {
                RecoveryResult result = scanRecords(channel, credentialAuthority, sink, codec, state);
                scanned = true;
                return new ProvisionalRecovery(result, sink);
            } finally {
                if (!scanned) {
                    sink.abort();
                }
            }
        }

        private static RecoveryResult scanRecords(
                FileChannel channel,
                CredentialAuthority credentialAuthority,
                RecoverySink sink,
                RevocationTransitionFrameCodec codec,
                ScanState state) throws IOException {
            while (true) {
                RevocationTransitionFrameCodec.ReadResult result = codec.read(channel, state.boundary);
                switch (result.classification()) {
                    case END_OF_INPUT:
                        return finish(state, false);
                    case INCOMPLETE_TAIL:
                        return finish(state, true);
                    case CORRUPT_RECORD:
                        throw corrupt("Revocation transition log contains a corrupt record");
                    case COMPLETE_RECORD:
                        accept(result.record().orElseThrow(), credentialAuthority, sink, state);
                        break;
                }
            }
        }

        private static void accept(
                RevocationTransitionFrameCodec.CompleteRecord record,
                CredentialAuthority credentialAuthority,
                RecoverySink sink,
                ScanState state) throws IOException {
            LatestState previous = state.states.get(record.data().credentialId());
            try {
                validateGlobal(record, state.globalRevision, state.globalCommitment);
                TransitionRules.validate(record.data(), previous);
            } catch (IllegalArgumentException failure) {
                throw new CorruptLogException(
                        "Revocation transition log violates semantic invariants", failure);
            }
            if (previous == null) {
                credentialAuthority.requireCredential(record.data().credentialId());
            }
            sink.accept(record);
            state.states.put(record.data().credentialId(), latestState(record));
            state.globalRevision = record.data().globalRevision();
            state.finalRecordStart = OptionalLong.of(record.recordOffset());
            state.globalCommitment = record.commitment();
            state.boundary = record.recordEnd();
        }

        private static RecoveryResult finish(ScanState state, boolean incomplete) {
            return new RecoveryResult(
                    state.storeId, state.boundary, state.physicalEnd, incomplete,
                    state.globalRevision, state.finalRecordStart,
                    state.globalCommitment, state.states);
        }

        private static CorruptLogException corrupt(String message) {
            return new CorruptLogException(message);
        }
    }

    /**
     * Production scalar scan; credential-local state is rebuilt only in the disk index.
     */
    private static final class ScalarScanner {
        private static ProvisionalRecovery scanProvisional(
                FileChannel channel,
                MetadataStoreId expectedStoreId,
                CredentialAuthority credentialAuthority) throws IOException {
            RevocationTransitionFrameCodec codec = new RevocationTransitionFrameCodec();
            MetadataStoreId actualStoreId = codec.readPreamble(channel);
            if (!expectedStoreId.equals(actualStoreId)) {
                throw new CorruptLogException("Revocation log belongs to another store");
            }
            long physicalEnd = channel.size();
            long boundary = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
            long globalRevision = 0L;
            OptionalLong finalRecordStart = OptionalLong.empty();
            RevocationTransitionFrameCodec.Commitment commitment =
                    RevocationTransitionFrameCodec.initialCommitment(actualStoreId);
            boolean incomplete = false;
            while (true) {
                RevocationTransitionFrameCodec.ReadResult result = codec.read(channel, boundary);
                if (result.classification() == RevocationTransitionFrameCodec.Classification.END_OF_INPUT) {
                    break;
                }
                if (result.classification() == RevocationTransitionFrameCodec.Classification.INCOMPLETE_TAIL) {
                    incomplete = true;
                    break;
                }
                if (result.classification() != RevocationTransitionFrameCodec.Classification.COMPLETE_RECORD) {
                    throw new CorruptLogException("Revocation transition log contains a corrupt record");
                }
                RevocationTransitionFrameCodec.CompleteRecord record = result.record().orElseThrow();
                validateGlobal(record, globalRevision, commitment);
                credentialAuthority.requireCredential(record.data().credentialId());
                globalRevision = record.data().globalRevision();
                finalRecordStart = OptionalLong.of(record.recordOffset());
                commitment = record.commitment();
                boundary = record.recordEnd();
            }
            RecoveryResult recovered = new RecoveryResult(
                    actualStoreId, boundary, physicalEnd, incomplete, globalRevision,
                    finalRecordStart, commitment, Map.of());
            return new ProvisionalRecovery(recovered, RecoverySink.NONE);
        }
    }

    /**
     * Successful scan whose sink publication remains provisional until its owner completes it.
     */
    private record ProvisionalRecovery(RecoveryResult result, RecoverySink sink) {
        private ProvisionalRecovery {
            Objects.requireNonNull(result, "result");
            Objects.requireNonNull(sink, "sink");
        }
    }

    /**
     * Exact existing revocation state-machine rules without synthetic history allocation.
     */
    private static final class TransitionRules {
        private static void validate(
                RevocationTransitionFrameCodec.TransitionData data, LatestState previous) {
            RevocationTransition transition = data.transition();
            if (previous == null) {
                validateFirst(data, transition);
                return;
            }
            long expectedLocal = nextLocalRevision(previous.transition().revision());
            if (transition.revision() != expectedLocal
                    || data.previousCredentialGlobalRevision().isEmpty()
                    || data.previousCredentialGlobalRevision().getAsLong() != previous.globalRevision()
                    || data.previousCredentialCommitment().isEmpty()
                    || !data.previousCredentialCommitment().orElseThrow().equals(previous.commitment())) {
                throw new IllegalArgumentException("Credential revocation history chain is invalid");
            }
            validateSuccessor(previous.transition(), transition);
        }

        private static void validateFirst(
                RevocationTransitionFrameCodec.TransitionData data,
                RevocationTransition transition) {
            if (transition.revision() != 1L
                    || data.previousCredentialGlobalRevision().isPresent()
                    || data.previousCredentialCommitment().isPresent()
                    || !hasValidReason(transition)
                    || transition.state() != RevocationState.HELD
                            && transition.state() != RevocationState.PERMANENTLY_REVOKED) {
                throw new IllegalArgumentException(
                        "First credential revocation transition is not canonical");
            }
        }

        private static long nextLocalRevision(long current) {
            try {
                return Math.addExact(current, 1L);
            } catch (ArithmeticException exhausted) {
                throw new IllegalArgumentException(
                        "Credential revocation revision is exhausted", exhausted);
            }
        }

        private static void validateSuccessor(
                RevocationTransition previous, RevocationTransition current) {
            if (current.time().isBefore(previous.time()) || !hasValidReason(current)) {
                throw new IllegalArgumentException("Revocation transition is not legal");
            }
            boolean legal = switch (previous.state()) {
                case CLEAR -> current.state() == RevocationState.HELD
                        || current.state() == RevocationState.PERMANENTLY_REVOKED;
                case HELD -> current.state() == RevocationState.CLEAR
                        || current.state() == RevocationState.PERMANENTLY_REVOKED;
                case PERMANENTLY_REVOKED -> false;
            };
            if (!legal) {
                throw new IllegalArgumentException("Revocation transition is not legal");
            }
        }

        private static boolean hasValidReason(RevocationTransition transition) {
            if (transition.state() != RevocationState.PERMANENTLY_REVOKED) {
                return transition.permanentReason().isEmpty();
            }
            return transition.permanentReason()
                    .filter(reason -> reason != RevocationReason.CERTIFICATE_HOLD
                            && reason != RevocationReason.REMOVE_FROM_CRL)
                    .isPresent();
        }
    }

    /**
     * Mutable startup-only scalar state used by the single sequential scan.
     */
    private static final class ScanState {
        private final MetadataStoreId storeId;
        private final long physicalEnd;
        private final Map<PkiId, LatestState> states = new HashMap<>();
        private long boundary = RevocationTransitionFrameCodec.PREAMBLE_BYTES;
        private long globalRevision;
        private OptionalLong finalRecordStart = OptionalLong.empty();
        private RevocationTransitionFrameCodec.Commitment globalCommitment;

        private ScanState(MetadataStoreId storeId, long physicalEnd) {
            this.storeId = storeId;
            this.physicalEnd = physicalEnd;
            globalCommitment = RevocationTransitionFrameCodec.initialCommitment(storeId);
        }
    }

    /**
     * Latest finite state retained for one credential, never its history.
     * @param globalRevision authoritative global revocation revision
     * @param commitment integrity commitment of the exact encoded artifact
     * @param transition immutable revocation transition retained for the credential
     * @param recordOffset zero-based byte offset of the encoded record
     */
    /* default */ record LatestState(
            long globalRevision,
            RevocationTransitionFrameCodec.Commitment commitment,
            RevocationTransition transition,
            long recordOffset) {
        /**
         * Creates the latest finite state retained for one credential, never its history.
         *
         * @param globalRevision authoritative global revocation revision
         * @param commitment integrity commitment of the exact encoded artifact
         * @param transition immutable revocation transition retained for the credential
         * @param recordOffset zero-based byte offset of the encoded record
         * @throws NullPointerException if {@code commitment} is null; or if {@code transition} is null
         * @throws IllegalArgumentException if {@code (globalRevision <= 0L || recordOffset <
         * RevocationTransitionFrameCodec.PREAMBLE_BYTES)}
         */
        LatestState {
            Objects.requireNonNull(commitment, "commitment");
            Objects.requireNonNull(transition, "transition");
            if (globalRevision <= 0L || recordOffset < RevocationTransitionFrameCodec.PREAMBLE_BYTES) {
                throw new IllegalArgumentException("Invalid latest revocation state");
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean equals(Object candidate) {
            if (this == candidate) {
                return true;
            }
            if (!(candidate instanceof LatestState other)) {
                return false;
            }
            return globalRevision == other.globalRevision
                    && recordOffset == other.recordOffset
                    && commitment.equals(other.commitment)
                    && RevocationTransitionFrameCodec.transitionsEqual(transition, other.transition);
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public int hashCode() {
            return Objects.hash(globalRevision, commitment,
                    RevocationTransitionFrameCodec.transitionHash(transition), recordOffset);
        }
    }

    /**
     * Immutable result of one bounded-memory sequential recovery pass.
     * @param storeId exact authoritative metadata store identity
     * @param lastCompleteRecordBoundary exclusive byte boundary after the last complete revocation record
     * @param physicalEnd observed physical file length in bytes
     * @param incompleteTail whether an incomplete record remains after the complete prefix
     * @param globalRevision authoritative global revocation revision
     * @param finalRecordStart byte offset of the final covered log record, or empty for an empty log
     * @param globalCommitment global revocation commitment at the captured boundary
     * @param latestStates latest finite revocation state for each credential identity
     */
    /* default */ record RecoveryResult(
            MetadataStoreId storeId,
            long lastCompleteRecordBoundary,
            long physicalEnd,
            boolean incompleteTail,
            long globalRevision,
            OptionalLong finalRecordStart,
            RevocationTransitionFrameCodec.Commitment globalCommitment,
            Map<PkiId, LatestState> latestStates) {
        /**
         * Creates an immutable result of one bounded-memory sequential recovery pass.
         *
         * @param storeId exact authoritative metadata store identity
         * @param lastCompleteRecordBoundary exclusive byte boundary after the last complete revocation record
         * @param physicalEnd observed physical file length in bytes
         * @param incompleteTail whether an incomplete record remains after the complete prefix
         * @param globalRevision authoritative global revocation revision
         * @param finalRecordStart byte offset of the final covered log record, or empty for an empty log
         * @param globalCommitment global revocation commitment at the captured boundary
         * @param latestStates latest finite revocation state for each credential identity
         * @throws NullPointerException if {@code storeId} is null; or if {@code finalRecordStart} is
         * null; or if {@code globalCommitment} is null
         * @throws IllegalArgumentException if {@code (lastCompleteRecordBoundary <
         * RevocationTransitionFrameCodec.PREAMBLE_BYTES || physicalEnd < lastCompleteRecordBoundary
         * || globalRevision < 0L || globalRevision == 0L != finalRecordStart.isEmpty())}
         */
        RecoveryResult {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(finalRecordStart, "finalRecordStart");
            Objects.requireNonNull(globalCommitment, "globalCommitment");
            latestStates = Map.copyOf(latestStates);
            if (lastCompleteRecordBoundary < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || physicalEnd < lastCompleteRecordBoundary || globalRevision < 0L
                    || globalRevision == 0L != finalRecordStart.isEmpty()) {
                throw new IllegalArgumentException("Invalid revocation recovery boundaries");
            }
        }

        private static RecoveryResult empty(MetadataStoreId storeId) {
            return new RecoveryResult(
                    storeId, RevocationTransitionFrameCodec.PREAMBLE_BYTES,
                    RevocationTransitionFrameCodec.PREAMBLE_BYTES, false, 0L,
                    OptionalLong.empty(),
                    RevocationTransitionFrameCodec.initialCommitment(storeId), Map.of());
        }

        private RecoveryResult afterTailRepair() {
            return new RecoveryResult(
                    storeId, lastCompleteRecordBoundary, lastCompleteRecordBoundary,
                    false, globalRevision, finalRecordStart,
                    globalCommitment, latestStates);
        }
    }

    /**
     * Immutable scalar boundary used by bounded derived-state recovery.
     * @param storeId exact authoritative metadata store identity
     * @param globalRevision authoritative global revocation revision
     * @param finalRecordStart byte offset of the final covered log record, or empty for an empty log
     * @param boundary exclusive byte boundary of the captured authoritative log prefix
     * @param globalCommitment global revocation commitment at the captured boundary
     */
    /* default */ record RecoveryTarget(
            MetadataStoreId storeId,
            long globalRevision,
            OptionalLong finalRecordStart,
            long boundary,
            RevocationTransitionFrameCodec.Commitment globalCommitment)
            implements FilesystemRevocationCurrentIndex.RecoveryBoundary {
        /**
         * Creates an immutable scalar boundary used by bounded derived-state recovery.
         *
         * @param storeId exact authoritative metadata store identity
         * @param globalRevision authoritative global revocation revision
         * @param finalRecordStart byte offset of the final covered log record, or empty for an empty log
         * @param boundary exclusive byte boundary of the captured authoritative log prefix
         * @param globalCommitment global revocation commitment at the captured boundary
         * @throws NullPointerException if {@code storeId} is null; or if {@code finalRecordStart} is
         * null; or if {@code globalCommitment} is null
         * @throws IllegalArgumentException if {@code (globalRevision < 0L || boundary <
         * RevocationTransitionFrameCodec.PREAMBLE_BYTES || globalRevision == 0L !=
         * finalRecordStart.isEmpty())}; or if {@code (globalRevision == 0L && (boundary !=
         * RevocationTransitionFrameCodec.PREAMBLE_BYTES ||
         * !globalCommitment.equals(RevocationTransitionFrameCodec.initialCommitment(storeId))))}; or
         * if {@code (finalRecordStart.isPresent() && (finalRecordStart.getAsLong() <
         * RevocationTransitionFrameCodec.PREAMBLE_BYTES || finalRecordStart.getAsLong() >=
         * boundary))}
         */
        RecoveryTarget {
            Objects.requireNonNull(storeId, "storeId");
            Objects.requireNonNull(finalRecordStart, "finalRecordStart");
            Objects.requireNonNull(globalCommitment, "globalCommitment");
            if (globalRevision < 0L
                    || boundary < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || globalRevision == 0L != finalRecordStart.isEmpty()) {
                throw new IllegalArgumentException("Invalid revocation recovery target");
            }
            if (globalRevision == 0L
                    && (boundary != RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || !globalCommitment.equals(
                            RevocationTransitionFrameCodec.initialCommitment(storeId)))) {
                throw new IllegalArgumentException("Invalid genesis revocation recovery target");
            }
            if (finalRecordStart.isPresent()
                    && (finalRecordStart.getAsLong() < RevocationTransitionFrameCodec.PREAMBLE_BYTES
                    || finalRecordStart.getAsLong() >= boundary)) {
                throw new IllegalArgumentException("Invalid final revocation record boundary");
            }
        }
    }

    /**
     * Provisional replay sink that can discard accepted records after later corruption.
     */
    /* default */ interface RecoverySink {
        /**
         * No-op recovery sink that retains no decoded records.
         */
        RecoverySink NONE = new RecoverySink() {
            /**
             * {@inheritDoc}
             */
            @Override
            public void accept(RevocationTransitionFrameCodec.CompleteRecord record) {
                // The default sink intentionally retains no historical record.
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public void complete() {
                // No provisional external state requires publication.
            }

            /**
             * {@inheritDoc}
             */
            @Override
            public void abort() {
                // No provisional external state requires rollback.
            }
        };

        /**
         * Accepts one validated record provisionally during sequential replay.
         * @param record validated complete record provisionally replayed in log order
         * @throws IOException if the sink cannot retain the provisional record
         */
        void accept(RevocationTransitionFrameCodec.CompleteRecord record) throws IOException;

        /**
         * Publishes all provisionally accepted records after a valid scan.
         * @throws IOException if the sink cannot publish its complete provisional replay
         */
        void complete() throws IOException;

        /**
         * Discards provisionally accepted records after a failed scan.
         */
        void abort();
    }

    /**
     * Store-local authority check performed once per distinct recovered credential.
     */
    /* default */
    @FunctionalInterface
    interface CredentialAuthority {
        /**
         * Requires the exact credential to belong to the owning filesystem store.
         * @param credentialId exact store-local credential identity; must not be null
         * @throws IOException if the exact credential is absent or does not belong to the store
         */
        void requireCredential(PkiId credentialId) throws IOException;
    }

    /**
     * Deterministic package-private append and durability fault boundaries.
     */
    /* default */ enum FaultPoint {
        /**
         * Fault injection point for appending a durable log frame.
         */
        APPEND,
        /**
         * Fault injection point for forcing file data and metadata.
         */
        FILE_FORCE,
        /**
         * Fault injection point for the file force performed while opening the log.
         */
        OPEN_FORCE,
        /**
         * Fault injection point for truncating an incomplete uncommitted tail.
         */
        TAIL_TRUNCATE,
        /**
         * Fault injection point for forcing the repaired tail.
         */
        TAIL_FORCE,
        /**
         * Fault injection point for verifying a repaired tail.
         */
        TAIL_VERIFY
    }

    /**
     * Deterministic fault injection seam; it is not a production extension point.
     */
    /* default */
    @FunctionalInterface
    interface FaultInjector {
        /**
         * No-op injector that never introduces a synthetic failure.
         */
        FaultInjector NONE = point -> { };

        /**
         * Fails one selected append, force, or recovery boundary.
         * @param point exact deterministic failure boundary being observed
         * @throws IOException to inject a deterministic failure at the selected persistence boundary
         */
        void fail(FaultPoint point) throws IOException;
    }

    /**
     * Package-private capability observations for advisory durability behavior.
     */
    /* default */ interface CapabilityProfile {
        /**
         * Reports whether owner-only POSIX creation attributes are available.
         * @param parent existing parent directory whose filesystem capabilities are inspected
         * @return true when POSIX attribute support is available for the directory
         * @throws IOException if filesystem capabilities cannot be inspected
         */
        boolean posixAvailable(Path parent) throws IOException;

        /**
         * Reports whether the parent uses a recognized local filesystem.
         * @param parent existing parent directory whose filesystem capabilities are inspected
         * @return true when the directory resides on an accepted local filesystem
         * @throws IOException if filesystem capabilities cannot be inspected
         */
        boolean localFileSystem(Path parent) throws IOException;

        /**
         * Attempts to force the parent directory after exclusive creation.
         * @param parent existing parent directory whose filesystem capabilities are inspected
         * @throws IOException if parent-directory durability cannot be confirmed
         */
        void forceParent(Path parent) throws IOException;
    }

    /**
     * Caller-visible append uncertainty requiring close and scanner recovery.
     */
    /* default */ static final class OutcomeUnknownException extends IOException {
        private static final long serialVersionUID = -1593021845236499276L;

        private OutcomeUnknownException(IOException cause) {
            super("Revocation transition append outcome requires recovery", cause);
        }
    }

    /**
     * Checked corruption result; corrupt complete bytes are never tail-repaired.
     */
    /* default */ static final class CorruptLogException extends IOException {
        private static final long serialVersionUID = -5000565696885871383L;

        private CorruptLogException(String message) {
            super(message);
        }

        private CorruptLogException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Live lifecycle of the retained writer authority.
     */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }

    /**
     * Default observations for the active Java filesystem provider.
     */
    private enum DefaultCapabilityProfile implements CapabilityProfile {
        INSTANCE;

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean posixAvailable(Path parent) throws IOException {
            return Files.getFileStore(parent).supportsFileAttributeView("posix");
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean localFileSystem(Path parent) throws IOException {
            FileStore store = Files.getFileStore(parent);
            return LOCAL_FILE_SYSTEMS.contains(store.type().toLowerCase(Locale.ROOT));
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void forceParent(Path parent) throws IOException {
            // POSIX directory fsync; a correct no-op on platforms that carry
            // directory durability through the write-through atomic publish.
            PlatformFs.forceDirectory(parent);
        }
    }

    /**
     * Immutable advisory capability observation.
     */
    private record CapabilityObservation(boolean posix, boolean local, boolean limited) {
    }

    /**
     * Owns the channel and lock until their authority transfers to an opened log.
     */
    private static final class Resources {
        private final FileChannel channel;
        private final FileLock writerLock;

        private Resources(FileChannel channel, FileLock writerLock) {
            this.channel = channel;
            this.writerLock = writerLock;
        }

        private static Resources acquire(Path logPath, boolean create, boolean posix) throws IOException {
            if (!create && (Files.isSymbolicLink(logPath)
                    || !Files.isRegularFile(logPath, LinkOption.NOFOLLOW_LINKS))) {
                throw new IOException("Revocation log entry is not a regular file");
            }
            Set<OpenOption> options = new HashSet<>();
            options.add(StandardOpenOption.READ);
            options.add(StandardOpenOption.WRITE);
            options.add(LinkOption.NOFOLLOW_LINKS);
            if (create) {
                options.add(StandardOpenOption.CREATE_NEW);
            }
            FileAttribute<?>[] attributes = posix
                    ? new FileAttribute<?>[] { PosixFilePermissions.asFileAttribute(OWNER_ONLY) }
                    : new FileAttribute<?>[0];
            FileChannel opened = FileChannel.open(logPath, options, attributes);
            try {
                return new Resources(opened, acquireLock(opened));
            } catch (IOException failure) {
                try {
                    opened.close();
                } catch (IOException closeFailure) {
                    failure.addSuppressed(closeFailure);
                }
                throw failure;
            }
        }

        private static FileLock acquireLock(FileChannel channel) throws IOException {
            final FileLock lock;
            try {
                lock = WriterExclusionLock.tryAcquire(channel);
            } catch (OverlappingFileLockException unavailable) {
                throw new IOException("Revocation log writer lock is unavailable", unavailable);
            }
            if (lock == null) {
                throw new IOException("Revocation log writer lock is unavailable");
            }
            return lock;
        }

        private void closeAfterFailure(IOException primary) {
            try {
                if (writerLock.isValid()) {
                    writerLock.release();
                }
            } catch (IOException releaseFailure) {
                primary.addSuppressed(releaseFailure);
            }
            try {
                channel.close();
            } catch (IOException closeFailure) {
                primary.addSuppressed(closeFailure);
            }
        }
    }
}
