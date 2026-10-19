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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.inject.Inject;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.FileSystemOperations;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.Nested;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.work.DisableCachingByDefault;

/** Combines an immutable MkDocs build with every configured module's Javadoc. */
@DisableCachingByDefault(because = "Assembles local documentation outputs for one Pages upload")
public abstract class AssembleDocumentationSite extends DefaultTask {
    /** @return the independently built MkDocs site, which is never modified */
    @InputDirectory
    @PathSensitive(PathSensitivity.RELATIVE)
    public abstract DirectoryProperty getMkDocsDirectory();

    /** @return the enabled Java modules and their actual Javadoc output directories */
    @Nested
    public abstract ListProperty<ModuleJavadoc> getModules();

    /** @return the separate, replaceable combined publication directory */
    @OutputDirectory
    public abstract DirectoryProperty getDestinationDirectory();

    /** @return Gradle's managed copy service */
    @Inject
    protected abstract FileSystemOperations getFileSystemOperations();

    /**
     * Validates every input before replacing only the combined output tree.
     * Publication remains atomic at the Pages artifact boundary: failed generation
     * or assembly cannot upload or deploy a partial site.
     * @throws IOException if physical paths cannot be resolved or the no-Jekyll marker cannot be written
     * @throws GradleException if an input is incomplete, colliding, or overlapping
     */
    @TaskAction
    public void assemble() throws IOException {
        Path source = getMkDocsDirectory().get().getAsFile().toPath().toAbsolutePath().normalize();
        Path destination = getDestinationDirectory().get().getAsFile().toPath().toAbsolutePath().normalize();
        requireSeparate(source.toRealPath(), physicalPath(destination));
        requireIndex(source, "MkDocs");
        if (Files.exists(source.resolve("javadoc")) || Files.exists(source.resolve("CNAME"))) {
            throw new GradleException("MkDocs must not contain the reserved javadoc subtree or a project CNAME");
        }
        List<ModuleJavadoc> modules = getModules().get();
        if (modules.isEmpty()) {
            throw new GradleException("No enabled Java module Javadoc was configured");
        }
        Set<String> names = new HashSet<>();
        for (ModuleJavadoc module : modules) {
            String name = module.getName().get();
            if (!name.matches("[A-Za-z0-9][A-Za-z0-9_-]*") || !names.add(name)) {
                throw new GradleException("Invalid or duplicate Javadoc module name: " + name);
            }
            Path directory = module.getDirectory().get().getAsFile().toPath().toAbsolutePath().normalize();
            requireSeparate(directory.toRealPath(), physicalPath(destination));
            requireIndex(directory, "Javadoc for " + name);
        }
        getFileSystemOperations().sync(copy -> {
            copy.into(destination);
            copy.from(source);
            for (ModuleJavadoc module : modules) {
                copy.from(module.getDirectory(), child -> child.into("javadoc/" + module.getName().get()));
            }
        });
        Files.writeString(destination.resolve(".nojekyll"), "");
    }

    /** Resolves existing symlinks even when the final output directory does not yet exist. */
    private static Path physicalPath(Path path) throws IOException {
        Path ancestor = path;
        List<Path> suffix = new ArrayList<>();
        while (!Files.exists(ancestor, LinkOption.NOFOLLOW_LINKS)) {
            suffix.add(ancestor.getFileName());
            ancestor = ancestor.getParent();
        }
        Path resolved = ancestor.toRealPath();
        for (int index = suffix.size() - 1; index >= 0; index--) {
            resolved = resolved.resolve(suffix.get(index));
        }
        return resolved.normalize();
    }

    private static void requireSeparate(Path input, Path output) {
        if (input.startsWith(output) || output.startsWith(input)) {
            throw new GradleException("Documentation input and combined output must be separate: " + input);
        }
    }

    private static void requireIndex(Path directory, String description) {
        if (!Files.isRegularFile(directory.resolve("index.html"))) {
            throw new GradleException(description + " is missing index.html: " + directory);
        }
    }

    /** One named module output, modeled as a nested Gradle input. */
    public abstract static class ModuleJavadoc {
        /** @return the Gradle module name used as its public URL segment */
        @Input
        public abstract Property<String> getName();

        /** @return the output directory supplied by the module's Javadoc task */
        @InputDirectory
        @PathSensitive(PathSensitivity.RELATIVE)
        public abstract DirectoryProperty getDirectory();
    }
}
