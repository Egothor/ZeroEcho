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

import java.nio.file.Path;
import java.util.Objects;

import zeroecho.pki.api.PkiId;

/**
 * Deterministic path mapping for the filesystem PKI store.
 *
 * <p>
 * This class is internal to the reference implementation. It defines the
 * on-disk layout and centralizes naming conventions.
 * </p>
 */
final class FsPaths {

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

    /* default */ Path lockFile() {
        return this.root.resolve(LOCK_DIR).resolve(STORE_LOCK);
    }

    /* default */ Path caDir(final PkiId caId) {
        return this.root.resolve("cas").resolve(BY_ID).resolve(FsUtil.safeId(caId));
    }

    /* default */ Path caCurrent(final PkiId caId) {
        return caDir(caId).resolve(CURRENT_FILE);
    }

    /* default */ Path caHistoryDir(final PkiId caId) {
        return caDir(caId).resolve(HISTORY_DIR);
    }

    /* default */ Path profileDir(final String profileId) {
        return this.root.resolve("profiles").resolve(BY_ID).resolve(FsUtil.safeSegment(profileId));
    }

    /* default */ Path profileCurrent(final String profileId) {
        return profileDir(profileId).resolve(CURRENT_FILE);
    }

    /* default */ Path profileHistoryDir(final String profileId) {
        return profileDir(profileId).resolve(HISTORY_DIR);
    }

    /* default */ Path credentialPath(final PkiId credentialId) {
        return this.root.resolve("credentials").resolve(BY_ID).resolve(FsUtil.safeId(credentialId) + ".bin");
    }

    /* default */ Path requestPath(final PkiId requestId) {
        return this.root.resolve("requests").resolve(BY_ID).resolve(FsUtil.safeId(requestId) + ".bin");
    }

    /* default */ Path revocationDir(final PkiId credentialId) {
        return this.root.resolve("revocations").resolve("by-credential").resolve(FsUtil.safeId(credentialId));
    }

    /* default */ Path revocationCurrent(final PkiId credentialId) {
        return revocationDir(credentialId).resolve(CURRENT_FILE);
    }

    /* default */ Path revocationHistoryDir(final PkiId credentialId) {
        return revocationDir(credentialId).resolve(HISTORY_DIR);
    }

    /* default */ Path statusObjectPath(final PkiId statusObjectId) {
        return this.root.resolve("status").resolve(BY_ID).resolve(FsUtil.safeId(statusObjectId) + ".bin");
    }

    /* default */ Path policyTracePath(final PkiId decisionId) {
        return this.root.resolve("policy").resolve("by-decision").resolve(FsUtil.safeId(decisionId) + ".bin");
    }

    /* default */ Path publicationPath(final PkiId publicationId) {
        return this.root.resolve("publications").resolve(BY_ID).resolve(FsUtil.safeId(publicationId) + ".bin");
    }
}
