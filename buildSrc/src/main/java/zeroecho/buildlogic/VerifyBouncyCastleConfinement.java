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

package zeroecho.buildlogic;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreeScanner;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;

/** Checks Java syntax trees for provider references outside the owning lib module. */
public abstract class VerifyBouncyCastleConfinement extends DefaultTask {
    /** @return the owning Gradle project name */
    @Input
    public abstract Property<String> getModuleName();

    /** @return the production Java sources to inspect */
    @InputFiles
    @PathSensitive(PathSensitivity.RELATIVE)
    public abstract ConfigurableFileCollection getMainSources();

    /** @return the successful verification marker */
    @OutputFile
    public abstract RegularFileProperty getMarker();

    /**
     * Parses sources without resolving types or running annotation processors.
     * Comments and literals are ignored; Unicode escapes use javac's lexical rules.
     * Qualified names are checked syntactically, without type attribution.
     * Sources are parsed separately, retaining at most one syntax tree at a time.
     *
     * @throws IOException if a source or marker cannot be accessed
     * @throws GradleException if parsing fails or a forbidden reference is found
     */
    @TaskAction
    public void verify() throws IOException {
        if (!getModuleName().get().equals("lib")) {
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            if (compiler == null) {
                throw new GradleException("BouncyCastle confinement requires a JDK compiler");
            }
            List<File> sources = getMainSources().getFiles().stream()
                    .sorted(Comparator.comparing(File::getAbsolutePath)).toList();
            try (StandardJavaFileManager manager = compiler.getStandardFileManager(
                    null, Locale.ROOT, StandardCharsets.UTF_8)) {
                for (File source : sources) {
                    verifySource(compiler, manager, source);
                }
            }
        }
        File marker = getMarker().get().getAsFile();
        Files.createDirectories(marker.toPath().getParent());
        Files.writeString(marker.toPath(), "ok\n", StandardCharsets.UTF_8);
    }

    private void verifySource(JavaCompiler compiler, StandardJavaFileManager manager, File source)
            throws IOException {
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        JavacTask parser = (JavacTask) compiler.getTask(null, manager, diagnostics,
                List.of("-proc:none", "--release", "25"), null,
                manager.getJavaFileObjectsFromFiles(List.of(source)));
        boolean forbidden = false;
        for (CompilationUnitTree unit : parser.parse()) {
            forbidden |= Boolean.TRUE.equals(new ProviderReferenceScanner().scan(unit, null));
        }
        for (Diagnostic<? extends JavaFileObject> diagnostic : diagnostics.getDiagnostics()) {
            if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
                throw new GradleException("Cannot parse Java source for BouncyCastle confinement: "
                        + source + ":" + diagnostic.getLineNumber() + " (" + diagnostic.getCode() + ")");
            }
        }
        if (forbidden) {
            throw new GradleException("BouncyCastle must be confined to :lib, but "
                    + getModuleName().get() + " references org.bouncycastle in: " + source);
        }
    }

    private static final class ProviderReferenceScanner extends TreeScanner<Boolean, Void> {
        @Override
        public Boolean visitMemberSelect(MemberSelectTree node, Void ignored) {
            if (node.getIdentifier().contentEquals("bouncycastle")
                    && node.getExpression() instanceof IdentifierTree root
                    && root.getName().contentEquals("org")) {
                return true;
            }
            return super.visitMemberSelect(node, ignored);
        }

        @Override
        public Boolean reduce(Boolean first, Boolean second) {
            return Boolean.TRUE.equals(first) || Boolean.TRUE.equals(second);
        }
    }
}
