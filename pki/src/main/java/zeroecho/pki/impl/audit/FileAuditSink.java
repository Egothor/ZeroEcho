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
package zeroecho.pki.impl.audit;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditChainHead;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditIntegrityReport;
import zeroecho.pki.api.audit.AuditQuery;
import zeroecho.pki.spi.audit.AuditSink;

/**
 * Persistent {@link AuditSink} provider storing audit events as daily gzip
 * files.
 *
 * <h2>ServiceLoader compatibility</h2>
 * <p>
 * This sink supports {@link java.util.ServiceLoader} by providing a public
 * no-arg constructor.
 * </p>
 *
 * <h2>Storage layout</h2> <pre>
 * baseDir/
 *   YYYY/
 *     MM/
 *       YYYY-MM-DD.audit.log.gz
 * </pre>
 *
 * <h2>Encoding</h2>
 * <p>
 * Each event is encoded as a single UTF-8 line and appended as its own gzip
 * member. Members are concatenated to enable append-only writes.
 * </p>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li>Best-effort permissions: directories 0700, files 0600 on POSIX.</li>
 * <li>No event payload is logged. Corrupted records are skipped without logging
 * the record content.</li>
 * </ul>
 */
// The audit verifier intentionally keeps all chain-state branches together so each failure returns its exact status.
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class FileAuditSink implements AuditSink, SearchableAuditSink,
        zeroecho.pki.api.audit.AuditService, zeroecho.pki.api.audit.AuditIntegrityService {

    private static final Logger LOG = Logger.getLogger(FileAuditSink.class.getName());
    private static final long FIRST_SEQUENCE = 0L;

    private final Path baseDir;

    /** Serializes chained appends and head recovery for one process. */
    private final Object writeLock = new Object();
    private boolean headRecovered;
    private long headSequence = -1L;
    private String headHash = AuditChainHead.GENESIS_RECORD_HASH;

    /**
     * Creates the sink with an explicit base directory.
     *
     * @param baseDir base directory
     */
    public FileAuditSink(Path baseDir) {
        this.baseDir = baseDir;

        LOG.log(Level.INFO, "FileAuditSink enabled; baseDir name={0}", baseDir);
    }

    // This per-sink monitor makes append plus in-memory head advancement one atomic operation.
    @SuppressWarnings("PMD.AvoidSynchronizedStatement")
    @Override
    public void record(AuditEvent event) {
        if (event == null) {
            throw new IllegalArgumentException("event must not be null");
        }

        synchronized (writeLock) {
            recoverHeadIfNeeded();
            long sequence = headSequence + 1L;
            String previousHash = headHash;

            Path file = dailyFile(baseDir, event.time());
            ensureSecurePath(file.getParent(), file);

            String line = AuditEventCodec.encodeChainedLine(event, sequence, previousHash);
            byte[] bytes = line.getBytes(StandardCharsets.UTF_8);

            OpenOption[] opts = { StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND };

            try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(file, opts));
                    GZIPOutputStream gzip = new GZIPOutputStream(os, true)) {
                gzip.write(bytes);
            } catch (IOException ex) {
                if (LOG.isLoggable(Level.SEVERE)) {
                    LOG.log(Level.SEVERE, "Failed to write audit record to file: " + file.getFileName(), ex);
                }
                throw new IllegalStateException("Failed to write audit event.", ex);
            }

            headSequence = sequence;
            headHash = AuditEventCodec.recordHash(sequence, previousHash, event);
        }
    }

    /**
     * Verifies the tamper-evident hash chain over the entire durable audit log.
     *
     * <p>
     * Records are recovered from every daily file and ordered by their global
     * sequence, so verification is independent of physical file placement. It
     * detects content mutation, deletion (a sequence gap), duplication, and broken
     * links; when an {@code expectedHead} anchor is supplied it additionally
     * detects whole-tail truncation. The returned report is payload-free.
     * </p>
     *
     * @param expectedHead optional independently-retained trusted head anchor
     * @return a safe integrity report
     */
    // Every accepted record advances an immutable observed-head snapshot used by early corruption returns.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    @Override
    public AuditIntegrityReport verifyIntegrity(Optional<AuditChainHead> expectedHead) {
        Optional<AuditChainHead> anchor = expectedHead == null ? Optional.empty() : expectedHead;
        ScanResult scan = scanChained();
        List<AuditEventCodec.ChainedRecord> records = new ArrayList<>();
        for (AuditEventCodec.ChainedRecord record : scan.records()) {
            if (record.chained()) {
                records.add(record);
            }
        }
        records.sort(Comparator.comparingLong(AuditEventCodec.ChainedRecord::sequence));

        long expectedSequence = 0L;
        String expectedPrevious = AuditChainHead.GENESIS_RECORD_HASH;
        long count = 0L;
        AuditChainHead observed = AuditChainHead.empty();
        for (AuditEventCodec.ChainedRecord record : records) {
            if (record.sequence() < expectedSequence) {
                return broken(AuditIntegrityReport.Status.DUPLICATE_SEQUENCE, record.sequence(), count, observed);
            }
            if (record.sequence() > expectedSequence) {
                return broken(AuditIntegrityReport.Status.SEQUENCE_GAP, expectedSequence, count, observed);
            }
            if (!record.previousHash().equals(expectedPrevious)) {
                return broken(AuditIntegrityReport.Status.CHAIN_BROKEN, record.sequence(), count, observed);
            }
            if (!AuditEventCodec.recomputeRecordHash(record).equals(record.recordHash())) {
                return broken(AuditIntegrityReport.Status.RECORD_MUTATED, record.sequence(), count, observed);
            }
            expectedPrevious = record.recordHash();
            observed = new AuditChainHead(record.sequence(), record.recordHash());
            expectedSequence = record.sequence() + 1L;
            count++;
        }
        if (scan.malformed()) {
            return broken(AuditIntegrityReport.Status.RECORD_MUTATED, expectedSequence, count, observed);
        }
        if (anchor.isPresent() && !anchor.orElseThrow().equals(observed)) {
            return new AuditIntegrityReport(AuditIntegrityReport.Status.HEAD_MISMATCH, count,
                    Optional.of(Math.max(0L, observed.sequence() + 1L)), observed);
        }
        return new AuditIntegrityReport(AuditIntegrityReport.Status.INTACT, count, Optional.empty(), observed);
    }

    // Every accepted record advances an immutable observed-head snapshot used by early corruption returns.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    @Override
    public AuditIntegrityReport verifyAnchoredPrefix(AuditChainHead anchor) {
        java.util.Objects.requireNonNull(anchor, "anchor");
        ScanResult scan = scanChained();
        List<AuditEventCodec.ChainedRecord> records = new ArrayList<>();
        for (AuditEventCodec.ChainedRecord record : scan.records()) {
            if (record.chained()) {
                records.add(record);
            }
        }
        records.sort(Comparator.comparingLong(AuditEventCodec.ChainedRecord::sequence));

        long expectedSequence = 0L;
        String expectedPrevious = AuditChainHead.GENESIS_RECORD_HASH;
        long count = 0L;
        AuditChainHead observed = AuditChainHead.empty();
        boolean anchorSeen = false;
        String hashAtAnchor = null;
        for (AuditEventCodec.ChainedRecord record : records) {
            if (record.sequence() < expectedSequence) {
                return broken(AuditIntegrityReport.Status.DUPLICATE_SEQUENCE, record.sequence(), count, observed);
            }
            if (record.sequence() > expectedSequence) {
                return broken(AuditIntegrityReport.Status.SEQUENCE_GAP, expectedSequence, count, observed);
            }
            if (!record.previousHash().equals(expectedPrevious)) {
                return broken(AuditIntegrityReport.Status.CHAIN_BROKEN, record.sequence(), count, observed);
            }
            if (!AuditEventCodec.recomputeRecordHash(record).equals(record.recordHash())) {
                return broken(AuditIntegrityReport.Status.RECORD_MUTATED, record.sequence(), count, observed);
            }
            if (record.sequence() == anchor.sequence()) {
                anchorSeen = true;
                hashAtAnchor = record.recordHash();
            }
            expectedPrevious = record.recordHash();
            observed = new AuditChainHead(record.sequence(), record.recordHash());
            expectedSequence = record.sequence() + 1L;
            count++;
        }
        if (scan.malformed()) {
            return broken(AuditIntegrityReport.Status.RECORD_MUTATED, expectedSequence, count, observed);
        }
        // A genesis (empty-log) anchor is a valid prefix of any consistent chain. Otherwise the anchored
        // sequence must still be present with the exact same record hash; records appended after it (for
        // example following a crash restart) are legitimate growth and do not fail the prefix check.
        if (anchor.sequence() >= FIRST_SEQUENCE) {
            if (!anchorSeen) {
                return new AuditIntegrityReport(AuditIntegrityReport.Status.HEAD_MISMATCH, count,
                        Optional.of(Math.max(0L, observed.sequence() + 1L)), observed);
            }
            if (!hashAtAnchor.equals(anchor.recordHash())) {
                return broken(AuditIntegrityReport.Status.RECORD_MUTATED, anchor.sequence(), count, observed);
            }
        }
        return new AuditIntegrityReport(AuditIntegrityReport.Status.INTACT, count, Optional.empty(), observed);
    }

    /**
     * Recovers and returns the current chain head, seeding it from disk if needed.
     *
     * @return the current tamper-evident head anchor
     */
    // The returned head must be read under the same monitor that serializes append and recovery.
    @SuppressWarnings("PMD.AvoidSynchronizedStatement")
    public AuditChainHead currentHead() {
        synchronized (writeLock) {
            recoverHeadIfNeeded();
            return new AuditChainHead(headSequence, headHash);
        }
    }

    private static AuditIntegrityReport broken(AuditIntegrityReport.Status status, long sequence, long count,
            AuditChainHead observed) {
        return new AuditIntegrityReport(status, count, Optional.of(sequence), observed);
    }

    private void recoverHeadIfNeeded() {
        if (headRecovered) {
            return;
        }
        long maxSequence = -1L;
        String maxHash = AuditChainHead.GENESIS_RECORD_HASH;
        for (AuditEventCodec.ChainedRecord record : scanChained().records()) {
            if (record.chained() && record.sequence() > maxSequence) {
                maxSequence = record.sequence();
                maxHash = record.recordHash();
            }
        }
        headSequence = maxSequence;
        headHash = maxHash;
        headRecovered = true;
    }

    // Each malformed persisted line can fail with a different decoder runtime subtype and is classified uniformly.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private ScanResult scanChained() {
        List<AuditEventCodec.ChainedRecord> records = new ArrayList<>();
        boolean[] malformed = { false };
        for (Path file : FileAuditSinkFiles.listDailyFiles(baseDir)) {
            readMembers(file, line -> {
                try {
                    records.add(AuditEventCodec.decodeChainedLine(line));
                } catch (RuntimeException corrupt) {
                    malformed[0] = true;
                }
            });
        }
        return new ScanResult(records, malformed[0]);
    }

    private record ScanResult(List<AuditEventCodec.ChainedRecord> records, boolean malformed) {
    }

    @Override
    public List<AuditEvent> search(AuditQuery query) {
        if (query == null) {
            throw new IllegalArgumentException("query must not be null");
        }

        List<Path> files = FileAuditSinkFiles.listDailyFiles(baseDir);
        if (files.isEmpty()) {
            return List.of();
        }

        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "FileAuditSink search scanning {0} file(s).", files.size());
        }

        List<AuditEvent> out = new ArrayList<>();
        for (Path f : files) {
            readMembers(f, line -> {
                AuditEvent event = decodeEventOrNull(line);
                if (event != null && event.matches(query)) {
                    out.add(event);
                }
            });
        }

        out.sort(AuditEvent.auditOrder());
        return List.copyOf(out.subList(0, Math.min(out.size(), query.limit())));
    }

    @Override
    public Optional<AuditEvent> get(PkiId eventId) {
        return getById(eventId);
    }

    @Override
    public Optional<AuditEvent> getById(PkiId eventId) {
        if (eventId == null) {
            throw new IllegalArgumentException("eventId must not be null");
        }

        List<AuditEvent> found = new ArrayList<>();
        for (Path f : FileAuditSinkFiles.listDailyFiles(baseDir)) {
            readMembers(f, line -> {
                if (found.isEmpty()) {
                    AuditEvent event = decodeEventOrNull(line);
                    if (event != null && AuditEventCodec.eventId(event).equals(eventId)) {
                        found.add(event);
                    }
                }
            });
            if (!found.isEmpty()) {
                return Optional.of(found.get(0));
            }
        }
        return Optional.empty();
    }

    private void readMembers(Path file, Consumer<String> consumer) {
        if (!Files.isRegularFile(file)) {
            return;
        }

        try (InputStream fis = new BufferedInputStream(Files.newInputStream(file));
                PushbackInputStream pb = new PushbackInputStream(fis, 1)) {

            while (true) {
                int peek = pb.read();
                if (peek == -1) {
                    break;
                }
                pb.unread(peek);

                try (GZIPInputStream gzip = new GZIPInputStream(new CloseShieldInputStream(pb))) { // NOPMD
                    readLinesFromMember(gzip, consumer);
                }
            }

        } catch (IOException ex) {
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, "Failed to read audit file: " + file.getFileName(), ex);
            }
            throw new IllegalStateException("Failed to read audit file: " + file, ex);
        }
    }

    private static void readLinesFromMember(InputStream gzip, Consumer<String> consumer) throws IOException {
        StringBuilder sb = new StringBuilder(256);
        int b;
        while ((b = gzip.read()) != -1) {
            if (b == '\n') { // NOPMD
                emit(sb.toString(), consumer);
                sb.setLength(0);
            } else {
                sb.append((char) b);
            }
        }

        if (sb.length() > 0) {
            emit(sb.toString(), consumer);
        }
    }

    private static void emit(String line, Consumer<String> consumer) {
        if (line != null && !line.isBlank()) {
            consumer.accept(line);
        }
    }

    private static AuditEvent decodeEventOrNull(String line) {
        try {
            return AuditEventCodec.decodeChainedLine(line).event();
        } catch (RuntimeException ex) { // NOPMD
            LOG.log(Level.WARNING, "Corrupted audit record encountered; skipping.", ex);
            return null;
        }
    }

    private static Path dailyFile(Path baseDir, Instant time) {
        LocalDate date = LocalDate.ofInstant(time, ZoneOffset.UTC);
        String yyyy = String.format("%04d", date.getYear());
        String mm = String.format("%02d", date.getMonthValue());
        String filename = String.format("%04d-%02d-%02d.audit.log.gz", date.getYear(), date.getMonthValue(),
                date.getDayOfMonth());
        return baseDir.resolve(yyyy).resolve(mm).resolve(filename);
    }

    private void ensureSecurePath(Path dir, Path file) {
        try {
            Files.createDirectories(dir);
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "Failed to create audit directory.", ex);
            throw new IllegalStateException("Failed to create audit directory: " + dir, ex);
        }

        applyDirectoryPermissions(dir);

        if (!Files.exists(file)) {
            try {
                Files.createFile(file);
            } catch (FileAlreadyExistsException ignored) {
                // acceptable race
            } catch (IOException ex) {
                if (LOG.isLoggable(Level.SEVERE)) {
                    LOG.log(Level.SEVERE, "Failed to create audit file: " + file.getFileName(), ex);
                }
                throw new IllegalStateException("Failed to create audit file: " + file, ex);
            }
        }

        applyFilePermissions(file);
    }

    private void applyDirectoryPermissions(Path dir) {
        if (supportsPosix()) {
            try {
                Set<PosixFilePermission> dirPerms = PosixFilePermissions.fromString("rwx------");
                Files.setPosixFilePermissions(dir, dirPerms);
            } catch (IOException ex) {
                LOG.log(Level.WARNING, "Failed to apply POSIX permissions to audit directory.", ex);
            }
            return;
        }

        boolean r = dir.toFile().setReadable(true, true);
        boolean w = dir.toFile().setWritable(true, true);
        boolean x = dir.toFile().setExecutable(true, true);
        if (!r || !w || !x) {
            LOG.log(Level.WARNING, "Failed to apply basic permissions to audit directory (non-POSIX FS).");
        }
    }

    private void applyFilePermissions(Path file) {
        if (supportsPosix()) {
            try {
                Set<PosixFilePermission> filePerms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(file, filePerms);
            } catch (IOException ex) {
                LOG.log(Level.WARNING, "Failed to apply POSIX permissions to audit file.", ex);
            }
            return;
        }

        boolean r = file.toFile().setReadable(true, true);
        boolean w = file.toFile().setWritable(true, true);
        boolean x = file.toFile().setExecutable(false, true);
        if (!r || !w || !x) {
            LOG.log(Level.WARNING, "Failed to apply basic permissions to audit file (non-POSIX FS).");
        }
    }

    private static boolean supportsPosix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    /**
     * InputStream wrapper that prevents accidental closing of the underlying
     * stream.
     *
     * <p>
     * {@link java.util.zip.GZIPInputStream#close()} closes the wrapped stream. When
     * scanning concatenated gzip members, we must keep the outer stream open and
     * only close the inflater state of each member.
     * </p>
     */
    private static final class CloseShieldInputStream extends FilterInputStream {

        private CloseShieldInputStream(InputStream in) {
            super(in);
        }

        @Override
        public void close() throws IOException {
            // Intentionally do nothing.
        }
    }
}
