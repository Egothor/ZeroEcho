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
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ConditionEvaluationResult;
import org.junit.jupiter.api.extension.ExecutionCondition;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Declares that a test can only be executed on a host permitted to create
 * symbolic links, and gates it accordingly.
 *
 * <h2>Why this exists (traceability rationale)</h2>
 * <p>
 * The annotated tests verify a security property of the store: that it refuses to
 * <em>follow</em> a symbolic link ({@link java.nio.file.LinkOption#NOFOLLOW_LINKS}
 * at every open). Exercising that property requires first planting a symbolic
 * link. Creating one is unconditional on POSIX, but on Windows it requires the
 * {@code SeCreateSymbolicLinkPrivilege}, granted only by elevation or Developer
 * Mode; a standard host raises {@code FileSystemException: A required privilege is
 * not held}. Where the host cannot create a link, the property is genuinely
 * <em>unobservable</em> — one cannot test the refusal to follow a link that cannot
 * be created.
 * </p>
 *
 * <p>
 * This annotation therefore <strong>skips</strong> (never disables or weakens) the
 * test on such hosts, via a JUnit {@link ExecutionCondition} that reports a precise
 * documented reason into the test report. The same test runs to completion and
 * passes on POSIX and on a privileged Windows host, so coverage of the security
 * property is preserved wherever it can be exercised. The {@link Tag} value
 * {@code requires-symlink-creation} makes every such test discoverable and
 * filterable for audit (for example {@code -DincludeTags=requires-symlink-creation}).
 * A skipped result is reported as skipped, not passed, so no false assurance is
 * produced.
 * </p>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Tag("requires-symlink-creation")
@ExtendWith(RequiresSymlinkCreation.SymlinkCreationCondition.class)
@interface RequiresSymlinkCreation {

    /** JUnit condition that gates a {@link RequiresSymlinkCreation} test on symbolic-link support. */
    final class SymlinkCreationCondition implements ExecutionCondition {

        private static final ConditionEvaluationResult ENABLED =
                ConditionEvaluationResult.enabled("symbolic-link creation is permitted on this host");

        @Override
        public ConditionEvaluationResult evaluateExecutionCondition(ExtensionContext context) {
            Path probeDirectory = null;
            Path probeLink = null;
            try {
                probeDirectory = Files.createTempDirectory("zeroecho-symlink-probe-");
                probeLink = probeDirectory.resolve("link");
                Files.createSymbolicLink(probeLink, probeDirectory.resolve("target"));
                return ENABLED;
            } catch (UnsupportedOperationException | FileSystemException unsupported) {
                return ConditionEvaluationResult.disabled(
                        "requires symbolic-link creation, which this host does not permit "
                                + "(e.g. Windows without SeCreateSymbolicLinkPrivilege): "
                                + unsupported.getMessage());
            } catch (IOException unexpected) {
                return ConditionEvaluationResult.disabled(
                        "symbolic-link support could not be determined: " + unexpected.getMessage());
            } finally {
                cleanup(probeLink);
                cleanup(probeDirectory);
            }
        }

        private static void cleanup(Path path) {
            if (path != null) {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // Probe artefacts live in the OS temporary directory and are non-authoritative.
                }
            }
        }
    }
}
