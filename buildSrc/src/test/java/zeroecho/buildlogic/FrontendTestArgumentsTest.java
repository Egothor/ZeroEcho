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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.gradle.testfixtures.ProjectBuilder;
import org.gradle.testkit.runner.BuildResult;
import org.gradle.testkit.runner.GradleRunner;
import org.gradle.testkit.runner.TaskOutcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FrontendTestArgumentsTest {
    @TempDir Path directory;

    @Test
    void preservesAPathWithSpacesAsOneJvmArgumentAndRejectsMissingValue() {
        var project = ProjectBuilder.builder().withProjectDir(directory.toFile()).build();
        var arguments = project.getObjects().newInstance(FrontendTestArguments.class);
        assertThrows(IllegalStateException.class, arguments::asArguments);
        arguments.getExecutable().set("/opt/Node Runtime/bin/node");
        assertEquals(List.of("-Dfrontend.node=/opt/Node Runtime/bin/node"), arguments.asArguments());
    }

    @Test
    void resolvesLazyNodeDefaultAndReusesConfigurationCache() throws Exception {
        fixture();
        assertTrue(run("run").getOutput().contains("NODE=/pinned/node/bin/node"));
        BuildResult cached = run("run");
        assertTrue(cached.getOutput().contains("Reusing configuration cache."), cached.getOutput());
        assertTrue(cached.getOutput().contains("NODE=/pinned/node/bin/node"));
    }

    @Test
    void explicitExecutableOverrideWinsAndPresenceFlagsKeepExistingSemantics() throws Exception {
        fixture();
        BuildResult absent = run("run", "-PfrontendNode=/opt/Override Node/node", "-PrequireOptIn");
        assertEquals(TaskOutcome.SKIPPED, absent.task(":run").getOutcome());
        BuildResult present = run("run", "-PfrontendNode=/opt/Override Node/node", "-PrequireOptIn", "-PrunFrontendE2e=false");
        assertEquals(TaskOutcome.SUCCESS, present.task(":run").getOutcome());
        assertTrue(present.getOutput().contains("NODE=/opt/Override Node/node"), present.getOutput());
    }

    @Test
    void resolvesWindowsNodePathWithoutUsingTheHostOperatingSystem() throws Exception {
        fixture();
        BuildResult result = run("run", "-PnodeWindows");
        assertTrue(result.getOutput().contains("NODE=/pinned/node/node.exe"), result.getOutput());
    }

    private void fixture() throws Exception {
        String helper = Path.of(FrontendTestArguments.class.getProtectionDomain().getCodeSource().getLocation().toURI())
                .toString().replace("\\", "\\\\").replace("'", "\\'");
        Files.writeString(directory.resolve("settings.gradle"), "rootProject.name = 'frontend-arguments-fixture'\n");
        Files.writeString(directory.resolve("build.gradle"), """
                buildscript { dependencies { classpath files('%s') } }
                import zeroecho.buildlogic.FrontendTestArguments
                plugins { id 'application' }
                application { mainClass = 'Fixture' }
                def nodeDirectory = objects.directoryProperty()
                nodeDirectory.set(file('/pinned/node'))
                def windows = providers.gradleProperty('nodeWindows').map { true }.orElse(false)
                def resolvedNode = nodeDirectory.zip(windows) { directory, isWindows ->
                    new File(directory.asFile, isWindows ? 'node.exe' : 'bin/node').absolutePath
                }
                def executable = providers.gradleProperty('frontendNode').orElse(resolvedNode)
                def requireOptIn = providers.gradleProperty('requireOptIn').isPresent()
                def enabled = providers.gradleProperty('runFrontendE2e')
                tasks.named('run', JavaExec) {
                    def nodeArguments = objects.newInstance(FrontendTestArguments)
                    nodeArguments.executable.set(executable)
                    jvmArgumentProviders.add(nodeArguments)
                    onlyIf { !requireOptIn || enabled.isPresent() }
                }
                """.formatted(helper));
        Path source = directory.resolve("src/main/java/Fixture.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, "public class Fixture { public static void main(String[] args) { "
                + "System.out.println(\"NODE=\" + System.getProperty(\"frontend.node\")); } }");
    }

    private BuildResult run(String... arguments) {
        var command = new java.util.ArrayList<>(List.of(arguments));
        command.addAll(List.of("--warning-mode=fail", "--configuration-cache", "--offline", "--stacktrace"));
        GradleRunner runner = GradleRunner.create().withProjectDir(directory.toFile())
                .withTestKitDir(directory.resolve("test-kit").toFile()).withArguments(command);
        String installation = System.getProperty("gradleQualificationHome", "");
        if (!installation.isBlank()) runner.withGradleInstallation(Path.of(installation).toFile());
        return runner.build();
    }
}
