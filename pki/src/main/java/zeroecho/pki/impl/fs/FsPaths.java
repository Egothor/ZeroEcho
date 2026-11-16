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
    private static final String REVOCATIONS_DIRECTORY = "revocations";

    /**
     * File name of the store version marker.
     */
    /* default */ static final String VERSION_FILE = "VERSION";
    /**
     * File name retaining the revocation snapshot boundary.
     */
    /* default */ static final String REVOCATION_BOUNDARY_FILE = ".revocation-snapshot-boundary";
    /**
     * Directory name reserved for store lock state.
     */
    /* default */ static final String LOCK_DIR = ".lock";
    /**
     * File name of the process-owned store lock.
     */
    /* default */ static final String STORE_LOCK = "store.lock";

    /**
     * File name of the current mutable entity representation.
     */
    /* default */ static final String CURRENT_FILE = "current.bin";
    /**
     * Directory name containing immutable historical entity representations.
     */
    /* default */ static final String HISTORY_DIR = "history";

    /**
     * Store root supplied by the owner; retained without path normalization.
     */
    /* default */ final Path root;

    /**
     * Captures the store root used for deterministic path resolution.
     *
     * @param root supplied store root, retained without normalization
     * @throws NullPointerException if the root is null
     */
    /* default */ FsPaths(final Path root) {
        this.root = Objects.requireNonNull(root, "root");
    }

    /**
     * Returns the exact store root supplied by the owner.
     *
     * @return exact retained root path; existence is not checked
     */
    /* default */ Path root() {
        return this.root;
    }

    /**
     * Resolves the store version marker.
     *
     * @return path to the store version marker; existence is not checked
     */
    /* default */ Path versionFile() {
        return this.root.resolve(VERSION_FILE);
    }

    /**
     * Resolves the captured revocation boundary marker.
     *
     * @return path to the snapshot boundary marker; existence is not checked
     */
    /* default */ Path revocationSnapshotBoundary() {
        return this.root.resolve(REVOCATION_BOUNDARY_FILE);
    }

    /**
     * Resolves the durable signing namespace marker.
     *
     * @return path to the exact signing namespace marker; existence is not checked
     */
    /* default */ Path signingNamespaceFile() {
        return this.root.resolve("SIGNING_NAMESPACE");
    }

    /**
     * Resolves the durable signing-time watermark marker.
     *
     * @return path to the signing-time watermark marker; existence is not checked
     */
    /* default */ Path signingTimeWatermarkFile() {
        return this.root.resolve("SIGNING_TIME_WATERMARK");
    }

    /**
     * Resolves the store-owned staged content directory.
     *
     * @return staged content root directory path; existence is not checked
     */
    /* default */ Path stagedContentRoot() {
        return this.root.resolve("staged-content");
    }

    /**
     * Resolves the legacy structural transaction log location.
     *
     * @return metadata transaction log path; existence is not checked
     */
    /* default */ Path transactionalMetadataLog() {
        return this.root.resolve("metadata").resolve("transactions.log");
    }

    /**
     * Resolves the authoritative transactional metadata directory.
     *
     * @return transactional metadata root directory path; existence is not checked
     */
    /* default */ Path transactionalMetadataRoot() {
        return this.root.resolve("metadata");
    }

    /**
     * Resolves the process-owned store lock file.
     *
     * @return store lock file path within the reserved lock directory; existence is not checked
     */
    /* default */ Path lockFile() {
        return this.root.resolve(LOCK_DIR).resolve(STORE_LOCK);
    }

    // -------------------------------------------------------------------------
    // CA (mutable with history)
    // -------------------------------------------------------------------------

    /**
     * Resolves one authority directory using its path-safe encoded identity.
     *
     * @param caId exact logical authority identity
     * @return authority directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path caDir(final PkiId caId) {
        Objects.requireNonNull(caId, "caId");
        return this.root.resolve("cas").resolve(BY_ID).resolve(FsUtil.safeId(caId));
    }

    /**
     * Resolves the current mutable authority representation.
     *
     * @param caId exact logical authority identity
     * @return current authority metadata file path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path caCurrent(final PkiId caId) {
        return caDir(caId).resolve(CURRENT_FILE);
    }

    /**
     * Resolves the immutable history directory of one authority.
     *
     * @param caId exact logical authority identity
     * @return authority history directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path caHistoryDir(final PkiId caId) {
        return caDir(caId).resolve(HISTORY_DIR);
    }

    /**
     * Resolves an immutable issuer-generation metadata file.
     *
     * @param issuerId exact issuer generation identity
     * @return issuer-generation binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path issuerGenerationPath(final PkiId issuerId) {
        Objects.requireNonNull(issuerId, "issuerId");
        return root.resolve("issuer-generations").resolve(BY_ID).resolve(FsUtil.safeId(issuerId) + BINARY_EXTENSION);
    }

    /**
     * Resolves an immutable issuer chain-path metadata file.
     *
     * @param pathId exact issuer chain-path identity
     * @return issuer chain-path binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path issuerChainPath(final PkiId pathId) {
        Objects.requireNonNull(pathId, "pathId");
        return root.resolve("issuer-chain-paths").resolve(BY_ID).resolve(FsUtil.safeId(pathId) + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Profiles (immutable versions plus one active pointer)
    // -------------------------------------------------------------------------

    /**
     * Resolves one profile directory using unpadded base64url UTF-8 identity framing.
     *
     * @param profileId exact logical profile identifier
     * @return profile directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path profileDir(final String profileId) {
        Objects.requireNonNull(profileId, "profileId");
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(profileId.getBytes(StandardCharsets.UTF_8));
        return this.root.resolve("profiles").resolve(BY_ID).resolve("id-" + encoded);
    }

    /**
     * Resolves an immutable profile version using its decimal version coordinate.
     *
     * @param profileId exact logical profile identifier
     * @param profileVersion decimal version coordinate; the caller enforces semantic version bounds
     * @return profile-version binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path profileVersion(final String profileId, final long profileVersion) {
        return profileDir(profileId).resolve("versions").resolve(profileVersion + BINARY_EXTENSION);
    }

    /**
     * Resolves the immutable version directory for one logical profile.
     *
     * @param profileId exact logical profile identifier
     * @return profile versions directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path profileVersionsDir(final String profileId) {
        return profileDir(profileId).resolve("versions");
    }

    /**
     * Resolves the active-version pointer for one logical profile.
     *
     * @param profileId exact logical profile identifier
     * @return active profile pointer path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path profileActive(final String profileId) {
        return profileDir(profileId).resolve("active" + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Credentials (immutable .bin)
    // -------------------------------------------------------------------------

    /**
     * Resolves an immutable credential metadata file.
     *
     * @param credentialId exact credential identity
     * @return credential binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path credentialPath(final PkiId credentialId) {
        Objects.requireNonNull(credentialId, "credentialId");
        return this.root.resolve("credentials").resolve(BY_ID).resolve(FsUtil.safeId(credentialId) + BINARY_EXTENSION);
    }

    // -------------------------------------------------------------------------
    // Requests (immutable .bin)
    // -------------------------------------------------------------------------

    /**
     * Resolves an immutable parsed enrollment request file.
     *
     * @param requestId exact request identity
     * @return parsed request binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path requestPath(final PkiId requestId) {
        Objects.requireNonNull(requestId, "requestId");
        return this.root.resolve("requests").resolve(BY_ID).resolve(FsUtil.safeId(requestId) + BINARY_EXTENSION);
    }

    /**
     * Resolves the directory of immutable enrollment requests indexed by identity.
     *
     * @return request identity directory path; existence is not checked
     */
    /* default */ Path requestsById() {
        return this.root.resolve("requests").resolve(BY_ID);
    }

    // -------------------------------------------------------------------------
    // Revocations (global log authority and derived structures)
    // -------------------------------------------------------------------------

    /**
     * Resolves the authoritative global revocation transition log.
     *
     * @return revocation transition log path; existence is not checked
     */
    /* default */ Path revocationTransitionLog() {
        return this.root.resolve(REVOCATIONS_DIRECTORY).resolve("transitions.log");
    }

    /**
     * Resolves published derived revocation checkpoint generations.
     *
     * @return revocation checkpoint directory path; existence is not checked
     */
    /* default */ Path revocationCheckpointDirectory() {
        return this.root.resolve(REVOCATIONS_DIRECTORY).resolve("checkpoints");
    }

    /**
     * Resolves temporary workspace for bounded revocation checkpoint construction.
     *
     * @return revocation checkpoint work directory path; existence is not checked
     */
    /* default */ Path revocationCheckpointWorkDirectory() {
        return this.root.resolve(REVOCATIONS_DIRECTORY).resolve("checkpoint-work");
    }

    /**
     * Resolves the derived current revocation state index.
     *
     * @return current revocation index file path; existence is not checked
     */
    /* default */ Path revocationCurrentIndex() {
        return this.root.resolve(REVOCATIONS_DIRECTORY).resolve("current-state.idx");
    }

    /**
     * Resolves the process-owned derived revocation index lock.
     *
     * @return current revocation index lock file path; existence is not checked
     */
    /* default */ Path revocationCurrentIndexLock() {
        return this.root.resolve(REVOCATIONS_DIRECTORY).resolve("current-state.idx.lock");
    }

    // -------------------------------------------------------------------------
    // Policy traces (immutable .bin)
    // -------------------------------------------------------------------------

    /**
     * Resolves an immutable policy evaluation trace by decision identity.
     *
     * @param decisionId exact policy decision identity
     * @return policy trace binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path policyTracePath(final PkiId decisionId) {
        Objects.requireNonNull(decisionId, "decisionId");
        return this.root.resolve("policy").resolve("by-decision").resolve(FsUtil.safeId(decisionId) + ".bin");
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

    /**
     * Resolves the mutable workflow directory by operation identity.
     *
     * @param opId exact orchestrator operation identity
     * @return workflow directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path workflowDir(final PkiId opId) {
        Objects.requireNonNull(opId, "opId");
        return workflowRoot().resolve(FsUtil.safeId(opId));
    }

    /**
     * Resolves the current mutable workflow representation.
     *
     * @param opId exact orchestrator operation identity
     * @return current workflow binary metadata path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path workflowCurrent(final PkiId opId) {
        return workflowDir(opId).resolve(CURRENT_FILE);
    }

    /**
     * Resolves immutable historical representations of one workflow.
     *
     * @param opId exact orchestrator operation identity
     * @return workflow history directory path; existence is not checked
     * @throws NullPointerException if a required identity argument is null
     */
    /* default */ Path workflowHistoryDir(final PkiId opId) {
        return workflowDir(opId).resolve(HISTORY_DIR);
    }
}
