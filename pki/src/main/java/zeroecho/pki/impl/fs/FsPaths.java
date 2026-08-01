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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Deterministic path mapping for the filesystem PKI store.
 *
 * <p>
 * This class is internal to the filesystem store implementation. It centralizes
 * the on-disk layout so that path conventions remain stable and consistent
 * across all entities and snapshot/export logic.
 * </p>
 *
 * <p>
 * The layout supports "mutable but auditable" entities by storing the latest
 * version in {@link #CURRENT_FILE} and keeping immutable historical versions in
 * a {@link #HISTORY_DIR} directory. This is required for snapshot export and
 * forensic reconstruction.
 * </p>
 */
final class FsPaths {
    private static final String BINARY_EXTENSION = ".bin";

    private static final String BY_ID = "by-id";

    /* default */ static final String VERSION_FILE = "VERSION";
    /* default */ static final String LOCK_DIR = ".lock";
    /* default */ static final String STORE_LOCK = "store.lock";

    /* default */ static final String CURRENT_FILE = "current.bin";
    /* default */ static final String HISTORY_DIR = "history";

    /* default */ final Path root;

    /* default */ FsPaths(final Path root) {
        this.root = Objects.requireNonNull(root, "root");
    }

    /* default */ Path root() {
        return this.root;
    }

    /* default */ Path versionFile() {
        return this.root.resolve(VERSION_FILE);
    }

    /* default */ Path signingNamespaceFile() {
        return this.root.resolve("SIGNING_NAMESPACE");
    }

    /* default */ Path signingTimeWatermarkFile() {
        return this.root.resolve("SIGNING_TIME_WATERMARK");
    }

    /* default */ Path stagedContentRoot() {
        return this.root.resolve("staged-content");
    }

    /* default */ Path transactionalMetadataLog() {
        return this.root.resolve("metadata").resolve("transactions.log");
    }

    /* default */ Path lockFile() {
        return this.root.resolve(LOCK_DIR).resolve(STORE_LOCK);
    }

    // -------------------------------------------------------------------------
    // CA (mutable with history)
    // -------------------------------------------------------------------------

    /* default */ Path caDir(final PkiId caId) {
        Objects.requireNonNull(caId, "caId");
        return this.root.resolve("cas").resolve(BY_ID).resolve(FsUtil.safeId(caId));
    }

    /* default */ Path caCurrent(final PkiId caId) {
        return caDir(caId).resolve(CURRENT_FILE);
    }

    /* default */ Path caHistoryDir(final PkiId caId) {
        return caDir(caId).resolve(HISTORY_DIR);
    }

    // -------------------------------------------------------------------------
    // Profiles (immutable versions plus one active pointer)
    // -------------------------------------------------------------------------

    /* default */ Path profileDir(final String profileId) {
        Objects.requireNonNull(profileId, "profileId");
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(profileId.getBytes(StandardCharsets.UTF_8));
        return this.root.resolve("profiles").resolve(BY_ID).resolve("id-" + encoded);
    }

    /* default */ Path profileVersion(final String profileId, final long profileVersion) {
        return profileDir(profileId).resolve("versions").resolve(profileVersion + BINARY_EXTENSION);
    }

    /* default */ Path profileVersionsDir(final String profileId) {
        return profileDir(profileId).resolve("versions");
    }

    /* default */ Path profileActive(final String profileId) {
        return profileDir(profileId).resolve("active" + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Credentials (immutable .bin)
    // -------------------------------------------------------------------------

    /* default */ Path credentialPath(final PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return this.root.resolve("credentials").resolve(BY_ID).resolve(FsUtil.safeId(credentialId) + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Requests (immutable .bin)
    // -------------------------------------------------------------------------

    /* default */ Path requestPath(final PkiId requestId) {
        Objects.requireNonNull(requestId, "requestId");
        return this.root.resolve("requests").resolve(BY_ID).resolve(FsUtil.safeId(requestId) + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Revocations (single authoritative journal)
    // -------------------------------------------------------------------------

    /* default */ Path revocationDir(final PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return this.root.resolve("revocations").resolve("by-credential").resolve(FsUtil.safeId(credentialId));
    }

    /* default */ Path revocationJournal(final PkiId credentialId) {
        return revocationDir(credentialId).resolve("journal.bin");
    }

    /* default */ Path revocationSnapshotRoot() {
        return this.root.resolve("revocation-snapshots");
    }

    // -------------------------------------------------------------------------
    // Policy traces (immutable .bin)
    // -------------------------------------------------------------------------

    /* default */ Path policyTracePath(final PkiId decisionId) {
        Objects.requireNonNull(decisionId, "decisionId");
        return this.root.resolve("policy").resolve("by-decision").resolve(FsUtil.safeId(decisionId) + ".bin");
    }

    // -------------------------------------------------------------------------
    // Publications (immutable .bin)
    // -------------------------------------------------------------------------

    /* default */ Path publicationPath(final PkiId publicationId) {
        Objects.requireNonNull(publicationId, "publicationId");
        return this.root.resolve("publications").resolve(BY_ID).resolve(FsUtil.safeId(publicationId) + ".bin");
    }

    // -------------------------------------------------------------------------
    // Workflow state (mutable with history)
    // -------------------------------------------------------------------------

    /**
     * Root directory for orchestrator workflow state records.
     *
     * <p>
     * Workflow state is updated over time (progression of a long-running
     * operation). Therefore, it follows the same "mutable but auditable" pattern as
     * CA records and profiles: {@code current.bin} and {@code history/}.
     * </p>
     *
     * @return workflows root directory (never {@code null})
     */
    /* default */ Path workflowRoot() {
        return this.root.resolve("workflows").resolve("by-op");
    }

    /* default */ Path workflowDir(final PkiId opId) {
        Objects.requireNonNull(opId, "opId");
        return workflowRoot().resolve(FsUtil.safeId(opId));
    }

    /* default */ Path workflowCurrent(final PkiId opId) {
        return workflowDir(opId).resolve(CURRENT_FILE);
    }

    /* default */ Path workflowHistoryDir(final PkiId opId) {
        return workflowDir(opId).resolve(HISTORY_DIR);
    }
}
