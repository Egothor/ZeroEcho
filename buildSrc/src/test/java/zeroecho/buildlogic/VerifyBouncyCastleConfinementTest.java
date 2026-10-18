/*
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

package zeroecho.buildlogic;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.nio.file.Files;
import java.nio.file.Path;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class VerifyBouncyCastleConfinementTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(strings = {
        "import org.bouncycastle.cert.X509CertificateHolder; class Example {}",
        "import org.bouncycastle.cert.*; class Example {}",
        "import static org.bouncycastle.util.Arrays.clone; class Example {}",
        "import static org.bouncycastle.util.Arrays.*; class Example {}",
        "class Example { org.bouncycastle.cert.X509CertificateHolder value; }",
        "class Example { Object value = org.bouncycastle.util.Arrays.clone(new byte[0]); }",
        "class Example { Object value = new org.bouncycastle.cert.X509CertificateHolder(null); }",
        "import org /* boundary */ . bouncycastle .cert.X509CertificateHolder; class Example {}"
    })
    void rejectsRealReferencesWithoutNeedingProviderClasspath(String source) throws Exception {
        VerifyBouncyCastleConfinement task = fixture("pki-server", source);
        GradleException error = assertThrows(GradleException.class, task::verify);
        assertTrue(error.getMessage().contains("must be confined to :lib"));
    }

    @Test
    void appliesUnicodeTranslationBeforeDetectingReferences() throws Exception {
        String escaped = "import org." + "\\" + "u0062ouncycastle.cert.X509CertificateHolder; class Example {}";
        assertThrows(GradleException.class, fixture("pki-server", escaped)::verify);
        String escapedNewline = "// harmless " + "\\" + "u000a" + escaped;
        assertThrows(GradleException.class, fixture("pki", escapedNewline)::verify);
    }

    @Test
    void ignoresCommentsJavadocStringsTextBlocksAndSimilarPackages() throws Exception {
        String source = """
                import example.org.bouncycastle.Reference;
                import org.bouncycastleExtra.Reference;
                /** See org.bouncycastle.cert.X509CertificateHolder. */
                class Example {
                    // import org.bouncycastle.cert.X509CertificateHolder;
                    /* org.bouncycastle.util.Arrays.clone(null); */
                    String name = "org.bouncycastle.cert.X509CertificateHolder";
                    String escaped = "\\\"org.bouncycastle";
                    char quote = '\"';
                    String block = %s
                        org.bouncycastle.cert.X509CertificateHolder
                        %s;
                }
                """.formatted("\"\"\"", "\"\"\"");
        VerifyBouncyCastleConfinement task = fixture("pki-server", source);
        assertDoesNotThrow(task::verify);
        assertTrue(Files.exists(task.getMarker().get().getAsFile().toPath()));
    }

    @Test
    void permitsProviderImplementationInLib() throws Exception {
        assertDoesNotThrow(fixture("lib", "import org.bouncycastle.cert.X509CertificateHolder; class Example {}")::verify);
    }

    @Test
    void failsClosedOnMalformedJava() throws Exception {
        GradleException error = assertThrows(GradleException.class,
                fixture("pki", "class Example { String unfinished = ")::verify);
        assertTrue(error.getMessage().contains("Cannot parse Java source"));
    }

    private VerifyBouncyCastleConfinement fixture(String module, String source) throws Exception {
        Path sourceFile = directory.resolve("Example.java");
        Files.writeString(sourceFile, source);
        Project project = ProjectBuilder.builder().withProjectDir(directory.toFile()).withName(module).build();
        VerifyBouncyCastleConfinement task = project.getTasks().register(
                "verifyBouncyCastleConfinement", VerifyBouncyCastleConfinement.class).get();
        task.getModuleName().set(module);
        task.getMainSources().from(sourceFile.toFile());
        task.getMarker().set(directory.resolve("confinement.ok").toFile());
        return task;
    }
}
