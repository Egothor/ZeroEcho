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
import java.nio.channels.FileChannel;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import zeroecho.pki.api.backup.BackupLimits;

/** Fixed-buffer operations and the exact version-1 logical state allow-list. */
final class FsBackupFiles {
    /* default */ static final ThreadLocal<Observer> OBSERVER = new ThreadLocal<>();
    /* default */ static final int BUFFER_BYTES = 64 * 1024;
    /* default */ static final String MANIFEST = "BACKUP-MANIFEST";
    private static final String ID = "[A-Za-z0-9_.-]+";
    private static final Pattern DOMAIN = Pattern.compile(
            "(requests/by-id/" + ID + "[.]bin|policy/by-decision/" + ID
            + "[.]bin|profiles/by-id/id-[A-Za-z0-9_-]+/(active[.]bin|versions/[0-9]+[.]bin)"
            + "|workflows/by-op/" + ID + "/(current[.]bin|history/[0-9]+-[0-9]+[.]bin))");
    private static final Pattern METADATA = Pattern.compile(
            "metadata/(FORMAT|manifest[.]zem|checkpoint-[0-9]{20}-[0-9]{20}[.]zec|wal-active-[0-9]{20}[.]zew)");
    private static final Pattern CONTENT = Pattern.compile("staged-content/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[.](content|meta|owners)");
    /** Observable filesystem steps used by deterministic backup fault injection. */
    /* default */ enum Phase { FROZEN, FORCE, DELETE }
    /** Fault-injection callback for a specific backup filesystem step. */
    /* default */ @FunctionalInterface interface Observer {
        /** Observes one filesystem step.
         * @param phase current step
         * @param path affected path
         * @throws IOException injected failure
         */
        void at(Phase phase, Path path) throws IOException;
    }
    /* default */ static void observe(Phase phase, Path path) throws IOException {
        Observer observer = OBSERVER.get();
        if (observer != null) { observer.at(phase, path); }
    }
    private FsBackupFiles() { }

    /* default */ static boolean domain(String path) { return DOMAIN.matcher(path).matches(); }
    /* default */ static boolean allowed(String path) {
        return "VERSION".equals(path) || "SIGNING_NAMESPACE".equals(path)
                || "revocations/transitions.log".equals(path) || domain(path)
                || METADATA.matcher(path).matches() || CONTENT.matcher(path).matches();
    }

    /* default */ static void validatePath(String path, BackupLimits limits) throws IOException {
        if (path.isEmpty() || path.getBytes(StandardCharsets.UTF_8).length > limits.pathBytes()
                || path.startsWith("/") || path.indexOf('\\') >= 0 || path.indexOf(':') >= 0
                || path.indexOf('\0') >= 0 || path.endsWith("/")) { throw invalid("BACKUP_PATH"); }
        for (String part : path.split("/", -1)) {
            validateComponent(part);
        }
        if (!MANIFEST.equals(path) && !allowed(path)) { throw invalid("BACKUP_INVENTORY"); }
    }

    private static void validateComponent(String part) throws IOException {
        String stem = part.split("[.]", 2)[0].toUpperCase(Locale.ROOT);
        if (part.isEmpty() || ".".equals(part) || "..".equals(part) || part.endsWith(".")
                || part.endsWith(" ") || part.chars().anyMatch(value -> value < 32 || value == 127)
                || stem.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]")) { throw invalid("BACKUP_PATH"); }
    }

    /** Rejects duplicate names and file/directory collisions under portable case folding. */
    /* default */ static final class Inventory {
        private final Set<String> names = new HashSet<>();
        private final Set<String> directories = new HashSet<>();
        /* default */ void add(String path, BackupLimits limits) throws IOException {
            validatePath(path, limits);
            String folded = path.toLowerCase(Locale.ROOT);
            if (names.size() >= limits.entryCount() || !names.add(folded) || directories.contains(folded)) {
                throw invalid("BACKUP_DUPLICATE_OR_COUNT");
            }
            int slash = folded.indexOf('/');
            while (slash >= 0) {
                String parent = folded.substring(0, slash);
                if (names.contains(parent)) { throw invalid("BACKUP_PATH_COLLISION"); }
                directories.add(parent);
                slash = folded.indexOf('/', slash + 1);
            }
        }
    }

    /** Accumulates bounded entry counts and expanded snapshot bytes. */
    /* default */ static final class Budget {
        private final BackupLimits limits;
        private long total;
        private int entries;
        /* default */ Budget(BackupLimits limits) { this.limits = limits; }
        /* default */ void add(long bytes) throws IOException {
            if (bytes < 0 || bytes > limits.entryBytes() || bytes > limits.expandedBytes() - total
                    || entries >= limits.entryCount() - 1) { throw invalid("BACKUP_SNAPSHOT_LIMIT"); }
            total += bytes;
            entries++;
        }
    }

    /* default */ static void copy(Path source, Path destination, Budget budget) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(source, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile()) { throw invalid("BACKUP_SOURCE_TYPE"); }
        long length = attributes.size();
        budget.add(length);
        Files.createDirectories(destination.getParent());
        // Legacy domain writers use best-effort force; the backup boundary is strict.
        try (FileChannel file = FileChannel.open(source, StandardOpenOption.WRITE)) { file.force(true); }
        forceDirectory(source.getParent());
        try (InputStream input = Files.newInputStream(source);
                OutputStream output = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
            copyExact(input, output, length);
        }
        Files.setLastModifiedTime(destination, attributes.lastModifiedTime());
        force(destination);
    }

    /* default */ static void copyExact(InputStream input, OutputStream output, long length) throws IOException {
        byte[] buffer = new byte[BUFFER_BYTES];
        long copied = 0;
        while (copied < length) {
            int count = input.read(buffer, 0, (int) Math.min(buffer.length, length - copied));
            if (count < 0) { throw invalid("BACKUP_TRUNCATED"); }
            if (count == 0) { throw invalid("BACKUP_NO_PROGRESS"); }
            output.write(buffer, 0, count);
            copied += count;
        }
        if (input.read() != -1) { throw invalid("BACKUP_LENGTH"); }
    }

    /* default */ static void force(Path file) throws IOException {
        observe(Phase.FORCE, file);
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) { channel.force(true); }
    }
    /* default */ static void forceDirectory(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) { channel.force(true); }
    }
    /* default */ static void forceTree(Path root) throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                if (!attributes.isRegularFile()) { throw invalid("BACKUP_SOURCE_TYPE"); }
                force(file);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(Path directory, IOException failure) throws IOException {
                if (failure != null) { throw failure; }
                forceDirectory(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }
    /* default */ static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) { return; }
        try {
            observe(Phase.DELETE, root);
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }
                @Override public FileVisitResult postVisitDirectory(Path directory, IOException failure) throws IOException {
                    if (failure != null) { throw failure; }
                    Files.delete(directory);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException failure) { throw new IOException("BACKUP_CLEANUP_FAILED", failure); }
    }
    /* default */ static MessageDigest digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    /* default */ static IOException invalid(String code) { return new IOException(code); }
}
