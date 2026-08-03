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
package zeroecho.pki.cli;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;

/** Composition root for the synchronous {@code zeroecho pki} command family. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidReassigningLoopVariables", "PMD.CloseResource", "PMD.DoNotUseThreads", "PMD.UseVarargs" })
public final class PkiCli {

    private static final String CONFIG = "--config";
    private static final String OUTPUT = "--output";
    private static final String RUN = "run";
    private static final int RUN_TOKEN_COUNT = 2;

    private PkiCli() {
    }

    /**
     * Executes one direct PKI operation or one sequential plan.
     *
     * @param arguments arguments following the {@code pki} command
     * @param output exclusive result output stream
     * @return stable PKI CLI process exit code
     * @throws NullPointerException if an argument container is {@code null}
     */
    public static int execute(String[] arguments, OutputStream output) {
        return execute(arguments, output, PkiSession::open, () -> Thread.currentThread().isInterrupted());
    }

    /* default */ static int execute(String[] arguments, OutputStream output, SessionOpener opener,
            CancellationSignal cancellation) {
        Objects.requireNonNull(arguments, "arguments");
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(opener, "opener");
        Objects.requireNonNull(cancellation, "cancellation");
        PkiOutputRenderer renderer = new PkiOutputRenderer();
        Invocation invocation;
        try {
            invocation = parseInvocation(arguments);
        } catch (IllegalArgumentException failure) {
            return renderFailure(renderer, PkiOutputMode.HUMAN, "INVALID_INVOCATION", "INVOCATION_INVALID",
                    PkiExitCodes.INVALID_INVOCATION, output);
        }
        if (invocation.help()) {
            renderHelp(output);
            return PkiExitCodes.SUCCESS;
        }

        PkiSessionConfiguration configuration;
        try {
            configuration = PkiCliConfiguration.read(invocation.configuration());
        } catch (IOException | RuntimeException failure) {
            return renderFailure(renderer, invocation.outputMode(), "CONFIGURATION_FAILURE", "CONFIGURATION_INVALID",
                    PkiExitCodes.CONFIGURATION_FAILURE, output);
        }

        PkiOperationRegistry registry = new PkiOperationRegistry();
        PkiPlan plan;
        try {
            plan = invocation.batch() ? PkiPlanParser.read(invocation.plan(), registry.names())
                    : singlePlan(invocation, registry);
        } catch (IOException | RuntimeException failure) {
            return renderFailure(renderer, invocation.outputMode(), "INVALID_PLAN", "PLAN_INVALID",
                    PkiExitCodes.INVALID_INVOCATION, output);
        }

        PkiSession session;
        try {
            session = opener.open(configuration);
        } catch (IllegalArgumentException failure) {
            return renderFailure(renderer, invocation.outputMode(), "CONFIGURATION_FAILURE", "CONFIGURATION_INVALID",
                    PkiExitCodes.CONFIGURATION_FAILURE, output);
        } catch (RuntimeException failure) {
            return renderFailure(renderer, invocation.outputMode(), "RESOURCE_FAILURE", "SESSION_OPEN_FAILED",
                    PkiExitCodes.RESOURCE_FAILURE, output);
        }

        PkiPlanExecution execution;
        try {
            execution = new PkiPlanExecutor(registry).execute(plan, session, cancellation);
        } catch (RuntimeException failure) {
            execution = internalFailure(plan);
        }
        try {
            session.close();
        } catch (Exception failure) {
            execution = execution.withPlanFailure(PkiOperationFailure.RESOURCE_FAILURE, "SESSION_CLOSE_FAILED");
        }
        try {
            renderer.render(execution, invocation.outputMode(), invocation.batch(), output);
        } catch (IOException failure) {
            return PkiExitCodes.RESOURCE_FAILURE;
        }
        return PkiExitCodes.from(execution);
    }

    @SuppressWarnings("PMD.CyclomaticComplexity")
    private static Invocation parseInvocation(String[] arguments) {
        if (arguments.length == 0) {
            throw new IllegalArgumentException("PKI command is missing");
        }
        Path configuration = null;
        PkiOutputMode outputMode = PkiOutputMode.HUMAN;
        List<String> commandTokens = new ArrayList<>();
        boolean help = false;
        boolean outputSelected = false;
        for (int index = 0; index < arguments.length; index++) {
            String argument = Objects.requireNonNull(arguments[index], "argument");
            if (CONFIG.equals(argument)) {
                if (configuration != null) {
                    throw new IllegalArgumentException("PKI configuration option is duplicated");
                }
                configuration = Path.of(requireValue(arguments, ++index));
            } else if (OUTPUT.equals(argument)) {
                if (outputSelected) {
                    throw new IllegalArgumentException("PKI output option is duplicated");
                }
                outputMode = parseOutput(requireValue(arguments, ++index));
                outputSelected = true;
            } else if ("--help".equals(argument) || "-h".equals(argument)) {
                help = true;
            } else {
                commandTokens.add(argument);
            }
        }
        if (help) {
            return new Invocation(null, outputMode, false, null, null, null, true);
        }
        if (configuration == null || commandTokens.isEmpty()) {
            throw new IllegalArgumentException("PKI configuration or operation is missing");
        }
        String command = commandTokens.get(0);
        if (RUN.equals(command)) {
            if (commandTokens.size() != RUN_TOKEN_COUNT) {
                throw new IllegalArgumentException("Plan path is invalid");
            }
            return new Invocation(configuration, outputMode, true, Path.of(commandTokens.get(1)), null, null, false);
        }
        PkiOperationValue.ObjectValue operationArguments = directArguments(commandTokens.subList(1,
                commandTokens.size()));
        return new Invocation(configuration, outputMode, false, null, command, operationArguments, false);
    }

    private static PkiOperationValue.ObjectValue directArguments(List<String> tokens) {
        if ((tokens.size() & 1) != 0) {
            throw new IllegalArgumentException("Operation arguments must be option-value pairs");
        }
        Map<String, PkiOperationValue> arguments = new LinkedHashMap<>();
        for (int index = 0; index < tokens.size(); index += 2) {
            String name = argumentName(tokens.get(index));
            String raw = tokens.get(index + 1);
            PkiOperationValue value = "limit".equals(name) ? new PkiOperationValue.IntegerValue(parseLong(raw))
                    : new PkiOperationValue.Text(raw);
            if (arguments.putIfAbsent(name, value) != null) {
                throw new IllegalArgumentException("Operation argument is duplicated");
            }
        }
        return new PkiOperationValue.ObjectValue(arguments);
    }

    private static String argumentName(String option) {
        return switch (option) {
            case "--profile-file" -> "profileFile";
            case "--credential-id" -> "credentialId";
            case "--publication-id" -> "publicationId";
            case "--reason" -> "reason";
            case "--limit" -> "limit";
            default -> throw new IllegalArgumentException("Unknown PKI operation argument");
        };
    }

    private static PkiPlan singlePlan(Invocation invocation, PkiOperationRegistry registry) throws IOException {
        if (!registry.names().contains(invocation.operation())) {
            throw new IllegalArgumentException("Unknown PKI operation");
        }
        Path base = Path.of(".").toAbsolutePath().normalize();
        PkiPlan.Step step = new PkiPlan.Step("command", invocation.operation(), invocation.arguments());
        return new PkiPlan(PkiPlan.CURRENT_VERSION, PkiPlan.FailurePolicy.FAIL_FAST, List.of(step), base);
    }

    private static PkiPlanExecution internalFailure(PkiPlan plan) {
        List<PkiPlanExecution.StepResult> results = new ArrayList<>(plan.steps().size());
        boolean first = true;
        for (PkiPlan.Step step : plan.steps()) {
            if (first) {
                results.add(PkiPlanExecution.StepResult.failure(step.id(), step.operation(),
                        PkiOperationFailure.INTERNAL_FAILURE, "INTERNAL_FAILURE"));
                first = false;
            } else {
                results.add(PkiPlanExecution.StepResult.skipped(step.id(), step.operation(), "FAIL_FAST"));
            }
        }
        return new PkiPlanExecution(results);
    }

    private static int renderFailure(PkiOutputRenderer renderer, PkiOutputMode mode, String category, String code,
            int exitCode, OutputStream output) {
        try {
            renderer.renderFailure(mode, category, code, output);
        } catch (IOException ignored) {
            return PkiExitCodes.RESOURCE_FAILURE;
        }
        return exitCode;
    }

    private static void renderHelp(OutputStream output) {
        java.io.PrintWriter writer = new java.io.PrintWriter(output, false, java.nio.charset.StandardCharsets.UTF_8);
        writer.println("Usage: zeroecho pki <operation> --config <file> [--output human|json] [arguments]");
        writer.println("       zeroecho pki run <plan-file> --config <file> [--output human|json]");
        writer.println("Operations:");
        writer.println("  configuration.validate");
        writer.println("  profile.validate --profile-file <file>");
        writer.println("  credential.inspect --credential-id <id>");
        writer.println("  credential.revoke --credential-id <id> --reason <permanent-reason>");
        writer.println("  revocation.history --credential-id <id> --limit <1..1000>");
        writer.println("  publication.inspect --publication-id <id>");
        writer.flush();
    }

    private static PkiOutputMode parseOutput(String raw) {
        return switch (raw) {
            case "human" -> PkiOutputMode.HUMAN;
            case "json" -> PkiOutputMode.JSON;
            default -> throw new IllegalArgumentException("Output mode is invalid");
        };
    }

    private static String requireValue(String[] arguments, int index) {
        if (index >= arguments.length) {
            throw new IllegalArgumentException("Option value is missing");
        }
        return arguments[index];
    }

    private static long parseLong(String raw) {
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("Numeric operation argument is invalid", failure);
        }
    }

    /** Lifecycle construction seam for CLI orchestration tests. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    interface SessionOpener {
        /** Opens one lifecycle-owned backend session. */
        PkiSession open(PkiSessionConfiguration configuration);
    }

    private record Invocation(Path configuration, PkiOutputMode outputMode, boolean batch, Path plan,
            String operation, PkiOperationValue.ObjectValue arguments, boolean help) {
    }
}
