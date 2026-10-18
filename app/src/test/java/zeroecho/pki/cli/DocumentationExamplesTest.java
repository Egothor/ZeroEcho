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
package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.application.PkiOperationValue;

/** Checks maintained examples with offline parsers and temporary publisher stores. */
class DocumentationExamplesTest {
    private static final Pattern BLOCK = Pattern.compile("(?m)^ *```(bash|sh|console|json) *\\R(.*?)^ *```", Pattern.DOTALL);
    private static final Pattern TOKEN = Pattern.compile("\"([^\"]*)\"|'([^']*)'|([^\\s]+)");

    @TempDir
    Path temporaryDirectory;

    @Test
    void documentedPublisherCommandsRoundTripAllProtectionProfiles() throws Exception {
        String page = Files.readString(repositoryRoot().resolve("documentation/admin/publication.md"));
        String joined = page.replaceAll("\\\\\\R\\s*", " ");
        Map<String, List<String>> examples = new HashMap<>();
        for (String line : joined.lines().toList()) {
            int command = line.indexOf("zeroecho-pki-publisher-secrets ");
            if (command >= 0 && !line.strip().startsWith("#") && !line.contains("`")) {
                List<String> arguments = tokens(line.substring(command + "zeroecho-pki-publisher-secrets ".length()));
                examples.put(arguments.getFirst(), arguments);
            }
        }
        assertEquals(Set.of("generate-bike-key", "write-store", "verify-store"), examples.keySet());
        Path publicKey = temporaryDirectory.resolve("bike-public.der");
        Path privateKey = temporaryDirectory.resolve("bike-private.der");
        Path secrets = temporaryDirectory.resolve("secrets.json");
        Files.writeString(secrets, "{\"fixture-alias\":\"fixture-value\"}");
        List<String> generate = new ArrayList<>(examples.get("generate-bike-key"));
        replaceOption(generate, "--pub", publicKey.toString());
        replaceOption(generate, "--priv", privateKey.toString());
        runPublisher(generate);
        for (String protection : List.of("PQC", "CLASSIC", "HYBRID")) {
            Path store = temporaryDirectory.resolve(protection + ".pss");
            List<String> write = new ArrayList<>(examples.get("write-store"));
            replaceOption(write, "--store", store.toString());
            replaceOption(write, "--secrets", secrets.toString());
            replaceOption(write, "--protection", protection);
            replaceOption(write, "--bike-pub", publicKey.toString());
            if (!protection.equals("PQC")) {
                write.addAll(List.of("--password-env", "ZE_DOCUMENTATION_TEST_PASSWORD"));
            }
            runPublisher(write);
            if (!protection.equals("CLASSIC")) {
                List<String> verify = new ArrayList<>(examples.get("verify-store"));
                replaceOption(verify, "--store", store.toString());
                replaceOption(verify, "--bike-priv", privateKey.toString());
                assertTrue(runPublisher(verify).contains("fixture-alias"));
            }
            if (!protection.equals("PQC")) {
                List<String> verify = List.of("verify-store", "--store", store.toString(),
                        "--password-env", "ZE_DOCUMENTATION_TEST_PASSWORD");
                assertTrue(runPublisher(verify).contains("fixture-alias"));
                runPublisher(List.of("verify-store", "--store", store.toString(),
                        "--password-env", "ZE_DOCUMENTATION_WRONG_PASSWORD"), 1);
            }
        }
    }

    private String runPublisher(List<String> arguments) throws Exception {
        return runPublisher(arguments, 0);
    }

    private String runPublisher(List<String> arguments, int expectedExit) throws Exception {
        List<String> command = new ArrayList<>();
        command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
        command.add("-cp");
        command.add(System.getProperty("java.class.path"));
        command.add(PublisherSecretsManagerCli.class.getName());
        command.addAll(arguments);
        Path output = temporaryDirectory.resolve("publisher-output.txt");
        ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(output.toFile());
        builder.environment().put("ZE_DOCUMENTATION_TEST_PASSWORD", "documentation-fixture-password");
        builder.environment().put("ZE_DOCUMENTATION_WRONG_PASSWORD", "wrong-fixture-password");
        Process process = builder.start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Publisher fixture timed out");
            String text = Files.readString(output);
            assertEquals(expectedExit, process.exitValue(), text);
            assertFalse(text.contains("fixture-value"), "Secret value leaked");
            return text;
        } finally {
            process.destroyForcibly();
        }
    }

    private static void replaceOption(List<String> arguments, String name, String value) {
        int index = arguments.indexOf(name);
        assertTrue(index >= 0, "Documented option missing: " + name);
        arguments.set(index + 1, value);
    }

    @Test
    void committedLocalConfigurationsAndPlanParse() throws IOException {
        Path root = repositoryRoot();
        int configurations = 0;
        int plans = 0;
        for (Path page : pages(root)) {
            Matcher blocks = BLOCK.matcher(Files.readString(page));
            while (blocks.find()) {
                String document = blocks.group(2).strip();
                if (!blocks.group(1).equals("json") || !document.startsWith("{")) {
                    continue;
                }
                if (document.contains("\"mode\": \"local\"")) {
                    Path fixture = temporaryDirectory.resolve("local-" + configurations++ + ".json");
                    Files.writeString(fixture, document);
                    assertNotNull(PkiCliConfiguration.read(fixture), page.toString());
                } else if (document.contains("\"failurePolicy\"")) {
                    Path fixture = temporaryDirectory.resolve("plan-" + plans++ + ".json");
                    Files.writeString(fixture, document);
                    assertNotNull(PkiPlanParser.read(fixture, new PkiOperationRegistry().names()), page.toString());
                }
            }
        }
        assertTrue(configurations >= 2, "No complete local configuration examples found");
        assertTrue(plans >= 1, "No plan examples found");
    }

    @Test
    void committedRemoteCommandsPassCliAndCatalogArgumentValidation() throws IOException {
        Map<String, PkiOperationValue.ObjectValue> schema = schema();
        int commands = 0;
        for (Path page : pages(repositoryRoot())) {
            Matcher blocks = BLOCK.matcher(Files.readString(page));
            while (blocks.find()) {
                if (blocks.group(1).equals("json")) {
                    continue;
                }
                String joined = blocks.group(2).replaceAll("\\\\\\R\\s*", " ");
                for (String line : joined.lines().toList()) {
                    String command = line.strip().replaceFirst("^\\$ ", "");
                    if (!command.startsWith("zeroecho pki ") || !command.contains("--url ")) {
                        continue;
                    }
                    List<String> tokens = tokens(command.substring("zeroecho pki ".length()));
                    String operation = tokens.getFirst();
                    AtomicBoolean reached = new AtomicBoolean();
                    PkiCli.RemoteExchangeFactory factory = target -> request -> {
                        reached.set(true);
                        if (!operation.equals("signing.operation.inspect")) {
                            PkiOperationValue.ObjectValue descriptor = schema.get(operation);
                            assertNotNull(descriptor, page + ": unknown operation " + operation);
                            PkiOperationValue.ObjectValue envelope = object(PkiCliJson.parse(request.body().orElseThrow()));
                            PkiOperationValue.ObjectValue arguments = object(envelope.fields().get("arguments"));
                            Set<String> known = new HashSet<>();
                            for (PkiOperationValue field : list(descriptor.fields().get("fields"))) {
                                PkiOperationValue.ObjectValue specification = object(field);
                                String name = text(specification.fields().get("name"));
                                known.add(name);
                                if (((PkiOperationValue.BooleanValue) specification.fields().get("required")).value()) {
                                    assertTrue(arguments.fields().containsKey(name), page + ": missing " + name);
                                }
                            }
                            assertTrue(known.containsAll(arguments.fields().keySet()),
                                    page + ": unknown argument in " + command);
                        }
                        throw new IOException("Documentation fixture stops before network I/O");
                    };
                    ByteArrayOutputStream output = new ByteArrayOutputStream();
                    int exit = PkiCli.execute(tokens.toArray(String[]::new), output,
                            configuration -> { throw new AssertionError("Remote example opened local store"); },
                            () -> false, factory);
                    assertTrue(reached.get(), page + ": rejected " + command + ": " + output);
                    assertTrue(exit == PkiExitCodes.RESOURCE_FAILURE || exit == PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN,
                            "Expected the fixture's I/O failure, got " + exit);
                    commands++;
                }
            }
        }
        assertTrue(commands >= 15, "Remote example coverage disappeared: " + commands);
        System.out.println("Validated documented remote commands: " + commands);
    }

    private static List<String> tokens(String command) {
        List<String> result = new ArrayList<>();
        Matcher tokens = TOKEN.matcher(command);
        while (tokens.find()) {
            String token = tokens.group(1) != null ? tokens.group(1)
                    : tokens.group(2) != null ? tokens.group(2) : tokens.group(3);
            result.add(token);
        }
        return result;
    }

    private static Map<String, PkiOperationValue.ObjectValue> schema() throws IOException {
        try (InputStream input = DocumentationExamplesTest.class.getResourceAsStream("/schema/operationSchema.json")) {
            assertNotNull(input);
            Map<String, PkiOperationValue.ObjectValue> entries = new HashMap<>();
            for (PkiOperationValue entry : list(PkiCliJson.parse(input.readAllBytes()))) {
                PkiOperationValue.ObjectValue object = object(entry);
                entries.put(text(object.fields().get("operationId")), object);
            }
            assertFalse(entries.isEmpty());
            return entries;
        }
    }

    private static Path repositoryRoot() {
        Path path = Path.of("").toAbsolutePath();
        while (!Files.isRegularFile(path.resolve("settings.gradle"))) {
            path = path.getParent();
            assertNotNull(path, "Cannot find repository root");
        }
        return path;
    }

    private static List<Path> pages(Path root) throws IOException {
        List<Path> pages = new ArrayList<>();
        pages.add(root.resolve("README.md"));
        pages.add(root.resolve("docs/pki-cli.md"));
        try (Stream<Path> files = Files.walk(root.resolve("documentation"))) {
            pages.addAll(files.filter(path -> path.toString().endsWith(".md")).sorted().toList());
        }
        return pages;
    }

    private static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
        return (PkiOperationValue.ObjectValue) value;
    }

    private static List<PkiOperationValue> list(PkiOperationValue value) {
        return ((PkiOperationValue.ListValue) value).values();
    }

    private static String text(PkiOperationValue value) {
        return ((PkiOperationValue.Text) value).value();
    }
}
