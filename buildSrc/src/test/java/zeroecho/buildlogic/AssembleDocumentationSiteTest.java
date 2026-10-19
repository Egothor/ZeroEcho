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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.gradle.api.GradleException;
import org.gradle.api.Project;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AssembleDocumentationSiteTest {
    @TempDir Path directory;

    @Test
    void assemblesEveryModuleAndReplacesOnlyTheCombinedOutput() throws Exception {
        AssembleDocumentationSite task = fixture();
        for (String name : List.of("api-spec", "app", "ext", "lib", "pki", "pki-server")) {
            module(task, name, true);
        }
        Path obsolete = directory.resolve("combined/obsolete.html");
        Files.createDirectories(obsolete.getParent());
        Files.writeString(obsolete, "stale");
        task.assemble();
        assertFalse(Files.exists(obsolete));
        assertEquals("MkDocs landing", Files.readString(directory.resolve("combined/index.html")));
        assertEquals("MkDocs landing", Files.readString(directory.resolve("mkdocs/index.html")));
        assertEquals("theme", Files.readString(directory.resolve("mkdocs/assets/theme.css")));
        assertEquals("theme", Files.readString(directory.resolve("combined/assets/theme.css")));
        for (String name : List.of("api-spec", "app", "ext", "lib", "pki", "pki-server")) {
            assertEquals(name, Files.readString(directory.resolve("combined/javadoc/" + name + "/index.html")));
            assertEquals("nested API", Files.readString(directory.resolve("combined/javadoc/" + name + "/api/Type.html")));
        }
        assertTrue(Files.isRegularFile(directory.resolve("combined/.nojekyll")));
        assertFalse(Files.exists(directory.resolve("mkdocs/javadoc")));
    }

    @Test
    void missingModuleIndexFailsBeforeTouchingAnExistingPublication() throws Exception {
        AssembleDocumentationSite task = fixture();
        module(task, "lib", true);
        module(task, "pki", false);
        Path previous = directory.resolve("combined/index.html");
        Files.createDirectories(previous.getParent());
        Files.writeString(previous, "previous publication");
        assertThrows(GradleException.class, task::assemble);
        assertEquals("previous publication", Files.readString(previous));
        assertEquals("MkDocs landing", Files.readString(directory.resolve("mkdocs/index.html")));
    }

    @ParameterizedTest
    @ValueSource(strings = { "javadoc", "CNAME" })
    void rejectsReservedMkDocsContentInsteadOfOverwritingIt(String collision) throws Exception {
        AssembleDocumentationSite task = fixture();
        module(task, "lib", true);
        Files.writeString(directory.resolve("mkdocs/" + collision), "owned by MkDocs");
        assertThrows(GradleException.class, task::assemble);
        assertEquals("owned by MkDocs", Files.readString(directory.resolve("mkdocs/" + collision)));
    }

    @Test
    void rejectsAnOutputInsideItsInput() throws Exception {
        AssembleDocumentationSite task = fixture();
        module(task, "lib", true);
        task.getDestinationDirectory().set(directory.resolve("mkdocs/combined").toFile());
        assertThrows(GradleException.class, task::assemble);
        assertFalse(Files.exists(directory.resolve("mkdocs/combined")));
    }

    @Test
    void rejectsPhysicalOverlapThroughASymlinkBeforeChangingInput() throws Exception {
        AssembleDocumentationSite task = fixture();
        module(task, "lib", true);
        Path alias = directory.resolve("alias");
        try {
            Files.createSymbolicLink(alias, directory.resolve("mkdocs"));
        } catch (UnsupportedOperationException | java.nio.file.AccessDeniedException unavailable) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false, "Filesystem does not permit symbolic links");
        }
        task.getDestinationDirectory().set(alias.resolve("combined").toFile());
        GradleException failure = assertThrows(GradleException.class, task::assemble);
        assertTrue(failure.getMessage().contains("must be separate"));
        assertEquals("MkDocs landing", Files.readString(directory.resolve("mkdocs/index.html")));
        assertFalse(Files.exists(directory.resolve("mkdocs/combined")));
    }

    @ParameterizedTest
    @ValueSource(strings = { "../lib", "", "with space", "/absolute" })
    void rejectsUnsafeModuleUrlSegments(String name) throws Exception {
        AssembleDocumentationSite task = fixture();
        AssembleDocumentationSite.ModuleJavadoc input = task.getProject().getObjects()
                .newInstance(AssembleDocumentationSite.ModuleJavadoc.class);
        input.getName().set(name);
        input.getDirectory().set(directory.resolve("mkdocs").toFile());
        task.getModules().add(input);
        assertThrows(GradleException.class, task::assemble);
    }

    private AssembleDocumentationSite fixture() throws Exception {
        Project project = ProjectBuilder.builder().withProjectDir(directory.toFile()).build();
        AssembleDocumentationSite task = project.getTasks().register(
                "assembleDocumentationSite", AssembleDocumentationSite.class).get();
        Path mkdocs = directory.resolve("mkdocs");
        Files.createDirectories(mkdocs.resolve("assets"));
        Files.writeString(mkdocs.resolve("index.html"), "MkDocs landing");
        Files.writeString(mkdocs.resolve("assets/theme.css"), "theme");
        task.getMkDocsDirectory().set(mkdocs.toFile());
        task.getDestinationDirectory().set(directory.resolve("combined").toFile());
        task.getModules().convention(List.of());
        return task;
    }

    private void module(AssembleDocumentationSite task, String name, boolean index) throws Exception {
        Path output = directory.resolve("module-" + name);
        Files.createDirectories(output.resolve("api"));
        if (index) { Files.writeString(output.resolve("index.html"), name); }
        Files.writeString(output.resolve("api/Type.html"), "nested API");
        AssembleDocumentationSite.ModuleJavadoc input = task.getProject().getObjects()
                .newInstance(AssembleDocumentationSite.ModuleJavadoc.class);
        input.getName().set(name);
        input.getDirectory().set(output.toFile());
        task.getModules().add(input);
    }
}
