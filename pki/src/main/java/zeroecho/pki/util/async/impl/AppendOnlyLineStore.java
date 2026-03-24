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
package zeroecho.pki.util.async.impl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Append-only UTF-8 line store with best-effort POSIX permissions.
 *
 * <p>
 * This is a minimal durability helper for the async bus. It does not interpret
 * content; it only appends and replays lines.
 * </p>
 */
public final class AppendOnlyLineStore {

    private static final Logger LOG = Logger.getLogger(AppendOnlyLineStore.class.getName());

    private final Path file;

    /**
     * Creates a store backed by the provided file path.
     *
     * @param file store file (never {@code null})
     */
    public AppendOnlyLineStore(Path file) {
        Objects.requireNonNull(file, "file");
        this.file = file;
        ensureSecureFile(file);
    }

    /**
     * Appends a single line (with trailing '\n') to the store.
     *
     * @param line line (never {@code null}, may be empty but not null)
     */
    public void appendLine(String line) {
        Objects.requireNonNull(line, "line");

        OpenOption[] opts = { StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND };

        try (BufferedWriter w = Files.newBufferedWriter(file, StandardCharsets.UTF_8, opts)) {
            w.write(line);
            w.write('\n');
        } catch (IOException ex) {
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, "Failed to append async store line to file: " + file.getFileName(), ex);
            }
            throw new IllegalStateException("Failed to append async store line.", ex);
        }
    }

    /**
     * Reads all lines from the store.
     *
     * @return list of lines (never {@code null})
     */
    public List<String> readAllLines() {
        if (!Files.exists(file)) {
            return List.of();
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            return r.lines().toList();
        } catch (IOException ex) {
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, "Failed to read async store file: " + file.getFileName(), ex);
            }
            throw new IllegalStateException("Failed to read async store file.", ex);
        }
    }

    private static void ensureSecureFile(Path file) {
        Path dir = file.getParent();
        if (dir != null) {
            ensureSecureDirectory(dir);
        }

        if (!Files.exists(file)) {
            try {
                Files.createFile(file);
            } catch (FileAlreadyExistsException ex) {
                // ignore
                LOG.log(Level.FINE, "File {0} already exists, using it", file);
            } catch (IOException ex) {
                throw new IllegalStateException("Failed to create async store file: " + file, ex);
            }
        }

        applyFilePermissions(file);
    }

    private static void ensureSecureDirectory(Path dir) {
        try {
            Files.createDirectories(dir);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to create async store directory: " + dir, ex);
        }
        applyDirectoryPermissions(dir);
    }

    private static void applyDirectoryPermissions(Path dir) {
        if (!supportsPosix(dir)) {
            return;
        }
        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE);
        try {
            Files.setPosixFilePermissions(dir, perms);
        } catch (IOException ex) {
            // best-effort, do not fail startup
            LOG.log(Level.WARNING, "Failed to set POSIX permissions on async directory.", ex);
        }
    }

    private static void applyFilePermissions(Path file) {
        if (!supportsPosix(file)) {
            return;
        }
        Set<PosixFilePermission> perms = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
        try {
            Files.setPosixFilePermissions(file, perms);
        } catch (IOException ex) {
            // best-effort, do not fail startup
            LOG.log(Level.WARNING, "Failed to set POSIX permissions on async file.", ex);
        }
    }

    private static boolean supportsPosix(Path path) {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix") && path != null;
    }
}
