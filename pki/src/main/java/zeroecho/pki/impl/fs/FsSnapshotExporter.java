/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

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
 * to {@code current.bin} only when strict mode is disabled.</li>
 * <li>Write-once objects are copied as-is (they are immutable). This exporter
 * does not attempt to prune them by time unless an upstream index exists.</li>
 * </ul>
 */
final class FsSnapshotExporter {

    private static final Logger LOG = Logger.getLogger(FsSnapshotExporter.class.getName());

    private final FsPkiStoreOptions options;

    /* default */ FsSnapshotExporter(final FsPkiStoreOptions options) {
        this.options = Objects.requireNonNull(options, "options");
    }

    /* default */ void exportSnapshot(final Path sourceRoot, final Path targetRoot, final Instant at) {
        Objects.requireNonNull(sourceRoot, "sourceRoot");
        Objects.requireNonNull(targetRoot, "targetRoot");
        Objects.requireNonNull(at, "at");

        try {
            FsOperations.ensureDir(targetRoot);
            FsPaths dst = new FsPaths(targetRoot);

            Files.writeString(dst.versionFile(), "v1");

            // copy write-once trees as-is (best-effort, deterministic order)
            copyTreeIfExists(sourceRoot.resolve("credentials"), targetRoot.resolve("credentials"));
            copyTreeIfExists(sourceRoot.resolve("requests"), targetRoot.resolve("requests"));
            copyTreeIfExists(sourceRoot.resolve("status"), targetRoot.resolve("status"));
            copyTreeIfExists(sourceRoot.resolve("policy"), targetRoot.resolve("policy"));
            copyTreeIfExists(sourceRoot.resolve("publications"), targetRoot.resolve("publications"));

            // reconstruct mutable entities from history (CAS, PROFILES, REVOCATIONS)
            reconstructMutableTree(sourceRoot.resolve("cas"), targetRoot.resolve("cas"), at,
                    this.options.caHistoryPolicy(), this.options.strictSnapshotExport());
            reconstructMutableTree(sourceRoot.resolve("profiles"), targetRoot.resolve("profiles"), at,
                    this.options.profileHistoryPolicy(), this.options.strictSnapshotExport());
            reconstructMutableTree(sourceRoot.resolve("revocations"), targetRoot.resolve("revocations"), at,
                    this.options.revocationHistoryPolicy(), this.options.strictSnapshotExport());
            // reconstruct workflow continuation state from history
            reconstructMutableTree(sourceRoot.resolve("workflows"), targetRoot.resolve("workflows"), at,
                    this.options.workflowHistoryPolicy(), this.options.strictSnapshotExport());

        } catch (IOException e) {
            throw new IllegalStateException("snapshot export failed", e);
        }
    }

    private static void reconstructMutableTree(final Path srcTree, final Path dstTree, final Instant at,
            final FsHistoryPolicy policy, final boolean strict) throws IOException {

        if (!Files.exists(srcTree)) {
            return;
        }
        Files.walk(srcTree).filter(Files::isRegularFile).sorted(Comparator.comparing(Path::toString)).forEach(p -> {
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

    private static Path selectHistoryEntry(final Path historyDir, final Instant at) {
        try {
            return Files.list(historyDir).filter(Files::isRegularFile)
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
        Files.walk(src).sorted(Comparator.comparing(Path::toString)).forEach(p -> {
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
