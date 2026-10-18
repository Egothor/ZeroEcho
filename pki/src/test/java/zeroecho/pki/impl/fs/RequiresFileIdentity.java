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

import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Declares that a test depends on the filesystem exposing a stable file identity
 * ({@link BasicFileAttributes#fileKey()}), and gates it accordingly.
 *
 * <h2>Why this exists (traceability rationale)</h2>
 * <p>
 * The annotated test asserts that temporary-file cleanup distinguishes a swapped
 * file by its stable filesystem identity (for example a POSIX inode) and therefore
 * refuses to delete a replacement placed at the same path. That identity is
 * exposed through {@code BasicFileAttributes.fileKey()}, which is {@code null} on
 * filesystems that have no stable identity — notably Windows/NTFS. There the store
 * legitimately falls back to a regular-file check with the owner-only directory as
 * the protection boundary, so the identity-based guarantee the test asserts is one
 * the platform cannot provide.
 * </p>
 *
 * <p>
 * This annotation therefore <strong>skips</strong> (never disables or weakens) the
 * test where {@code fileKey} is unavailable, via a JUnit {@link ExecutionCondition}
 * that reports a precise documented reason. The test runs and passes on POSIX. The
 * {@link Tag} value {@code requires-file-identity} makes it discoverable and
 * filterable for audit; a skipped result is reported as skipped, not passed.
 * </p>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Tag("requires-file-identity")
@ExtendWith(RequiresFileIdentity.FileIdentityCondition.class)
@interface RequiresFileIdentity {

    /** JUnit condition that gates a {@link RequiresFileIdentity} test on {@code fileKey} availability. */
    final class FileIdentityCondition implements ExecutionCondition {

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            Path probe = null;
            try {
                probe = Files.createTempFile("zeroecho-fileidentity-probe-", ".tmp");
                Object fileKey = Files.readAttributes(probe, BasicFileAttributes.class).fileKey();
                if (fileKey == null) {
                    return ConditionEvaluationResult.disabled(
                            "requires a stable filesystem file identity (fileKey), which this host "
                                    + "does not expose (e.g. Windows/NTFS reports null)");
                }
                return ConditionEvaluationResult.enabled("filesystem exposes a stable file identity");
            } catch (IOException unexpected) {
                return ConditionEvaluationResult.disabled(
                        "file identity support could not be determined: " + unexpected.getMessage());
            } finally {
                if (probe != null) {
                    try {
                        Files.deleteIfExists(probe);
                    } catch (IOException ignored) {
                        // Probe artefact lives in the OS temporary directory and is non-authoritative.
                    }
                }
            }
        }
    }
}
