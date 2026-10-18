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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.gradle.api.Project;
import org.gradle.api.tasks.compile.JavaCompile;
import org.gradle.testfixtures.ProjectBuilder;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class StrictCompilationTest {
    @TempDir
    Path directory;

    @ParameterizedTest
    @ValueSource(strings = { "compileJava", "compileTestJava", "compileAuxiliaryJava" })
    void acceptsWarningFreeSourceForEveryJavaSourceSet(String taskName) throws Exception {
        assertTrue(compile(taskName, "final class Fixture { String value() { return \"ok\"; } }").successful());
    }

    @ParameterizedTest(name = "{0} rejects {1}")
    @MethodSource("warningSources")
    void rejectsAllWarningCategoriesForEveryJavaSourceSet(String taskName, String category, String diagnosticCode, String source)
            throws Exception {
        Compilation result = compile(taskName, source);
        assertFalse(result.successful());
        assertTrue(result.diagnostics().contains(diagnosticCode),
                result.diagnostics().toString());
        assertTrue(result.diagnostics().stream().anyMatch(code -> code.contains("warnings.and.werror")),
                result.diagnostics().toString());
    }

    private static Stream<Arguments> warningSources() {
        return Stream.of("compileJava", "compileTestJava", "compileAuxiliaryJava").flatMap(task -> Stream.of(
                Arguments.of(task, "deprecated", "compiler.warn.has.been.deprecated", "final class Fixture { int value() { return new java.util.Date().getYear(); } }"),
                Arguments.of(task, "unchecked", "compiler.warn.prob.found.req", "final class Fixture { java.util.List<String> value(Object input) { return (java.util.List<String>) input; } }"),
                Arguments.of(task, "redundant cast", "compiler.warn.redundant.cast", "final class Fixture { String value(String input) { return (String) input; } }"),
                Arguments.of(task, "rawtypes", "compiler.warn.raw.class.use", "final class Fixture { java.util.List value() { return java.util.List.of(); } }")));
    }

    private Compilation compile(String taskName, String source) throws Exception {
        Project project = ProjectBuilder.builder().withProjectDir(directory.toFile()).withName("lib").build();
        project.getPluginManager().apply("buildlogic.java-common-conventions");
        JavaCompile task = "compileAuxiliaryJava".equals(taskName)
                ? project.getTasks().register(taskName, JavaCompile.class).get()
                : project.getTasks().named(taskName, JavaCompile.class).get();
        assertTrue(task.getOptions().isWarnings());
        List<String> options = new ArrayList<>(task.getOptions().getCompilerArgs());
        assertTrue(options.contains("-Xlint:all"));
        assertTrue(options.contains("-Werror"));
        assertTrue(options.contains("-Xmaxwarns"));
        assertTrue(options.contains("100000"));
        Path output = Files.createDirectory(directory.resolve("classes"));
        options.addAll(List.of("-d", output.toString()));
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        JavaFileObject fixture = new SimpleJavaFileObject(URI.create("string:///Fixture.java"),
                JavaFileObject.Kind.SOURCE) {
            @Override
            public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                return source;
            }
        };
        var compiler = ToolProvider.getSystemJavaCompiler();
        try (var files = compiler.getStandardFileManager(diagnostics, Locale.ROOT, null)) {
            boolean successful = compiler.getTask(null, files, diagnostics, options, null, List.of(fixture)).call();
            return new Compilation(successful, diagnostics.getDiagnostics().stream()
                    .map(diagnostic -> diagnostic.getCode()).toList());
        }
    }

    private record Compilation(boolean successful, List<String> diagnostics) { }
}
