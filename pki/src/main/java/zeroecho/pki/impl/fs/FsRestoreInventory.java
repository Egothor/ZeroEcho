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
import java.util.Iterator;
import java.util.stream.Stream;
import zeroecho.pki.api.backup.BackupLimits;

/** Rejects colocated external authority instead of silently leaving it in the rollback root. */
final class FsRestoreInventory {
    private static final String INPUT_ARCHIVE = "input.zip";
    private static final String UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final String METADATA = "(FORMAT|manifest[.]zem|checkpoint-[0-9]{20}-[0-9]{20}[.]zec"
            + "|wal-active-[0-9]{20}[.]zew|wal-[0-9]{20}-[0-9]{20}[.]zew)";
    private FsRestoreInventory() { }

    /* default */ static void validate(Path root, BackupLimits limits) throws IOException {
        SigningLedgerRecovery.validateExistingLayout(root.resolve("metadata"), SigningLedgerRecovery.Configuration.defaults());
        scan(root, limits, false);
    }

    private static void scan(Path root, BackupLimits limits, boolean partial) throws IOException {
        try (Stream<Path> paths = Files.walk(root, 10)) {
            Iterator<Path> iterator = paths.iterator();
            int count = 0;
            while (iterator.hasNext()) {
                Path path = iterator.next();
                if (path.equals(root)) { continue; }
                if (++count > limits.entryCount()) { throw new IOException("RESTORE_LIVE_INVENTORY_LIMIT"); }
                String name = root.relativize(path).toString().replace(java.io.File.separatorChar, '/');
                if (name.getBytes(StandardCharsets.UTF_8).length > limits.pathBytes() || Files.isSymbolicLink(path)) {
                    throw new IOException("RESTORE_EXTERNAL_AUTHORITY");
                }
                boolean directory = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS);
                if (!directory && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                        || !allowed(name, directory, partial)) { throw new IOException("RESTORE_EXTERNAL_AUTHORITY"); }
            }
        }
    }

    private static boolean allowed(String path, boolean directory, boolean partial) {
        if (path.startsWith(".backup-work/")) {
            return backupWorkAllowed(path, directory, partial);
        }
        if (directory) {
            return path.matches("[.]lock|metadata|staged-content|revocations|requests|requests/by-id|policy|policy/by-decision"
                    + "|profiles|profiles/by-id|profiles/by-id/id-[A-Za-z0-9_-]+(/versions)?"
                    + "|workflows|workflows/by-op|workflows/by-op/[A-Za-z0-9_.-]+(/history)?"
                    + "|staged-content/" + UUID + "[.]unique-index"
                    + "|revocations/(checkpoints|checkpoint-work)|revocations/checkpoint-work/[.]checkpoint-build-" + UUID)
                    || !partial && ".backup-work".equals(path);
        }
        if (FsBackupFiles.allowed(path) || ".lock/store.lock".equals(path)
                || ".revocation-snapshot-boundary".equals(path) || partial && FsBackupFiles.MANIFEST.equals(path)) { return true; }
        if (path.endsWith(".tmp") && FsBackupFiles.domain(path.substring(0, path.length() - 4))) { return true; }
        return path.matches("[.](restore-role-" + UUID + "|restore-marker-[^/]+[.]tmp|version-" + UUID
                + "[.]tmp|metadata-" + UUID + "[.]tmp)")
                || path.matches("metadata/(" + METADATA + "|[.]" + METADATA + "-" + UUID + "[.]tmp)")
                || path.matches("staged-content/(" + UUID + "[.](content|meta|owners|incomplete)|[.]metadata-" + UUID + "[.]tmp)")
                || path.matches("staged-content/" + UUID + "[.]unique-index/([0-9a-f]{64}|[.]metadata-" + UUID + "[.]tmp)")
                || path.matches("revocations/(transitions[.]log|current-state[.]idx([.]lock)?|[.]current-state[.]idx[.]"
                        + "(building|suffix|seed|recovering)-" + UUID + "([.]growing-" + UUID + ")?)")
                || path.matches("revocations/checkpoints/(g-[0-9]+-[0-9a-f]{64}[.]chk|[.]building-" + UUID + ")")
                || path.matches("revocations/checkpoint-work/[.]checkpoint-build-" + UUID
                        + "/(frozen-index|measurement|p-[0-9]+-r-[0-9]+[.]run)");
    }

    private static boolean backupWorkAllowed(String path, boolean directory, boolean partial) {
        if (partial) { return false; }
        String child = path.substring(".backup-work/".length());
        if (!directory && child.matches("[.]backup-[^/]+[.]incomplete([.]zip)?")) { return true; }
        int separator = child.indexOf('/');
        String first = separator < 0 ? child : child.substring(0, separator);
        if (!first.matches("[.](snapshot|verification)-[^/]+")) { return false; }
        if (separator < 0) { return directory; }
        String nested = child.substring(separator + 1);
        if (first.startsWith(".snapshot-")) { return allowed(nested, directory, true); }
        if (INPUT_ARCHIVE.equals(nested)) { return !directory; }
        if ("candidate".equals(nested) || "checking".equals(nested)) { return directory; }
        if (nested.startsWith("candidate/")) { return allowed(nested.substring(10), directory, true); }
        return nested.startsWith("checking/") && allowed(nested.substring(9), directory, true);
    }
}
