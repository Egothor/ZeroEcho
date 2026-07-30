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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;

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
 * <li>Signing namespace, signing-time watermark, and authoritative
 * {@code sign-workflows} records are current safety metadata copied at export
 * time. They are intentionally not reconstructed at {@code at}: rolling them
 * back could make a stable identifier reusable or discard a completed signing
 * result.</li>
 * </ul>
 */
final class FsSnapshotExporter {

    private static final Logger LOG = Logger.getLogger(FsSnapshotExporter.class.getName());
    private static final String ACTIVE_POINTER_FILE = "active.bin";
    private static final String BINARY_EXTENSION = ".bin";

    private final FsPkiStoreOptions options;

    /* default */ FsSnapshotExporter(final FsPkiStoreOptions options) {
        this.options = Objects.requireNonNull(options, "options");
    }

    /*
     * Snapshot/profile failures deliberately cross this boundary without input-
     * bearing causes or filesystem paths.
     */
    @SuppressWarnings("PMD.PreserveStackTrace")
    /* default */ void exportSnapshot(final Path sourceRoot, final Path targetRoot, final Instant at) {
        Objects.requireNonNull(sourceRoot, "sourceRoot");
        Objects.requireNonNull(targetRoot, "targetRoot");
        Objects.requireNonNull(at, "at");

        try {
            List<SnapshotProfileArtifact> profiles = preflightImportedProfiles(sourceRoot.resolve("profiles"), at);
            FsOperations.ensureDir(targetRoot);
            FsPaths dst = new FsPaths(targetRoot);

            Files.writeString(dst.versionFile(), FilesystemPkiStore.CURRENT_STORE_VERSION);
            copyFile(sourceRoot.resolve("SIGNING_NAMESPACE"), targetRoot.resolve("SIGNING_NAMESPACE"));
            copyFile(sourceRoot.resolve("SIGNING_TIME_WATERMARK"), targetRoot.resolve("SIGNING_TIME_WATERMARK"));

            // copy write-once trees as-is (best-effort, deterministic order)
            copyTreeIfExists(sourceRoot.resolve("credentials"), targetRoot.resolve("credentials"));
            copyTreeIfExists(sourceRoot.resolve("requests"), targetRoot.resolve("requests"));
            copyTreeIfExists(sourceRoot.resolve("status"), targetRoot.resolve("status"));
            copyTreeIfExists(sourceRoot.resolve("policy"), targetRoot.resolve("policy"));
            copyTreeIfExists(sourceRoot.resolve("publications"), targetRoot.resolve("publications"));
            copyTreeIfExists(sourceRoot.resolve("sign-workflows"), targetRoot.resolve("sign-workflows"));
            copyTreeIfExists(sourceRoot.resolve("revocations"), targetRoot.resolve("revocations"));
            copyImportedProfilesAsOf(profiles, targetRoot.resolve("profiles"));

            // reconstruct mutable entities from history (CAS and profiles)
            reconstructMutableTree(sourceRoot.resolve("cas"), targetRoot.resolve("cas"), at,
                    this.options.caHistoryPolicy(), this.options.strictSnapshotExport());
            // reconstruct workflow continuation state from history
            reconstructMutableTree(sourceRoot.resolve("workflows"), targetRoot.resolve("workflows"), at,
                    this.options.workflowHistoryPolicy(), this.options.strictSnapshotExport());

        } catch (SnapshotProfileFailure failure) {
            throw new IllegalStateException(failure.getMessage());
        } catch (IOException e) {
            throw new IllegalStateException("Snapshot export failed: code=SNAPSHOT_EXPORT_FAILED");
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
