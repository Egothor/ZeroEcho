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
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;

/** Composition root for the synchronous {@code zeroecho pki} command family. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidInstantiatingObjectsInLoops",
        "PMD.AvoidReassigningLoopVariables", "PMD.CloseResource", "PMD.CyclomaticComplexity",
        "PMD.DoNotUseThreads", "PMD.UseVarargs" })
public final class PkiCli {

    private static final String CONFIG = "--config";
    private static final String OUTPUT = "--output";
    private static final String PENDING_WAIT = "--pending-wait";
    private static final String RUN = "run";
    private static final String URL = "--url";
    private static final String CLIENT_KEYSTORE = "--client-keystore";
    private static final String CLIENT_KEYSTORE_PASSWORD_ENV = "--client-keystore-password-env";
    private static final String CLIENT_CERT = "--client-cert";
    private static final String CLIENT_KEY = "--client-key";
    private static final String TRUST = "--trust";
    private static final String TRUST_PASSWORD_ENV = "--trust-password-env";
    private static final String AUTHORITY_ID = "--authority-id";
    private static final String APPROVAL_ID = "--approval-id";
    private static final String DEADLINE = "--deadline";
    private static final java.util.regex.Pattern REMOTE_OPERATION_ID =
            java.util.regex.Pattern.compile("[a-z][a-z0-9]*(\\.[a-z0-9]+)+");
    private static final java.time.Duration REMOTE_POLL_INTERVAL = java.time.Duration.ofMillis(100);
    private static final RemoteExchangeFactory DEFAULT_EXCHANGE_FACTORY = target ->
            JdkHttpExchange.open(target.baseUri(), PkiRemoteTls.createContext(target, System::getenv));
    private static final Map<String, String> OPERATION_ARGUMENT_NAMES = Map.ofEntries(
            Map.entry("--profile-file", "profileFile"), Map.entry("--profile-id", "profileId"),
            Map.entry("--profile-version", "profileVersion"), Map.entry("--ca-id", "caId"),
            Map.entry("--issuer-ca-id", "issuerCaId"), Map.entry("--format-id", "formatId"),
            Map.entry("--subject-ref", "subjectRef"), Map.entry("--key-ref", "keyRef"),
            Map.entry("--state", "state"), Map.entry("--request-id", "requestId"),
            Map.entry("--request-file", "requestFile"), Map.entry("--encoding", "encoding"),
            Map.entry("--credential-id", "credentialId"), Map.entry("--status-object-id", "statusObjectId"),
            Map.entry("--type", "type"), Map.entry("--publication-id", "publicationId"),
            Map.entry("--source-type", "sourceType"), Map.entry("--source-id", "sourceId"),
            Map.entry("--target-type", "targetType"), Map.entry("--target-id", "targetId"),
            Map.entry("--reason", "reason"), Map.entry("--justification", "justification"),
            Map.entry("--limit", "limit"),
            Map.entry("--binding-id", "bindingId"),
            Map.entry("--binding-commitment", "bindingCommitment"),
            Map.entry("--origin", "origin"), Map.entry("--role", "role"),
            Map.entry("--issuer-id", "issuerId"), Map.entry("--path-id", "pathId"),
            Map.entry("--parent-path-id", "parentPathId"), Map.entry("--subject-ca-id", "subjectCaId"),
            Map.entry("--existing-credential-id", "existingCredentialId"),
            Map.entry("--new-key-ref", "newKeyRef"));
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
        return execute(arguments, output, opener, cancellation, DEFAULT_EXCHANGE_FACTORY);
    }

    /* default */ static int execute(String[] arguments, OutputStream output, SessionOpener opener,
            CancellationSignal cancellation, RemoteExchangeFactory remoteExchangeFactory) {
        Objects.requireNonNull(arguments, "arguments");
        Objects.requireNonNull(output, "output");
        Objects.requireNonNull(opener, "opener");
        Objects.requireNonNull(cancellation, "cancellation");
        Objects.requireNonNull(remoteExchangeFactory, "remoteExchangeFactory");
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
        if (invocation.remote().isPresent()) {
            return executeRemote(invocation.remote().orElseThrow(), invocation.outputMode(),
                    invocation.pendingWait(), renderer, remoteExchangeFactory, cancellation, output);
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
            PkiOperationTransport transport = new LocalPkiOperationTransport(session);
            execution = new PkiPlanExecutor(registry, invocation.pendingWait()).execute(plan, transport, cancellation);
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

    // The exchange is explicitly closed in finally so close failures never replace a stable CLI result.
    @SuppressWarnings("PMD.UseTryWithResources")
    private static int executeRemote(Remote remote, PkiOutputMode mode, java.time.Duration pendingWait,
            PkiOutputRenderer renderer, RemoteExchangeFactory factory, CancellationSignal cancellation,
            OutputStream output) {
        PkiHttpExchange exchange;
        try {
            exchange = factory.open(remote.target());
        } catch (IOException | GeneralSecurityException | RuntimeException failure) {
            return renderFailure(renderer, mode, "CONFIGURATION_FAILURE", "REMOTE_CLIENT_SETUP_FAILED",
                    PkiExitCodes.CONFIGURATION_FAILURE, output);
        }
        try {
            RemotePkiOperationTransport transport = new RemotePkiOperationTransport(exchange, pendingWait,
                    REMOTE_POLL_INTERVAL);
            PkiRemoteResult result = transport.submit(remote.operationId(), remote.arguments(),
                    remote.authorityId(), remote.approvalId(), remote.deadline(), cancellation);
            new PkiRemoteReporter().render(result, mode, output);
            return PkiRemoteExitCodes.from(result);
        } catch (PkiRemoteTransportException failure) {
            return renderFailure(renderer, mode, failure.category(), failure.code(), failure.exitCode(), output);
        } catch (IOException failure) {
            return PkiExitCodes.RESOURCE_FAILURE;
        } catch (RuntimeException failure) {
            return renderFailure(renderer, mode, "INTERNAL_FAILURE", "REMOTE_INTERNAL_FAILURE",
                    PkiExitCodes.INTERNAL_FAILURE, output);
        } finally {
            closeQuietly(exchange);
        }
    }

    private static void closeQuietly(PkiHttpExchange exchange) {
        try {
            exchange.close();
        } catch (Exception ignored) {
            // Deliberately ignored.
        }
    }

    @SuppressWarnings({ "PMD.CyclomaticComplexity" })
    private static Invocation parseInvocation(String[] arguments) {
        if (arguments.length == 0) {
            throw new IllegalArgumentException("PKI command is missing");
        }
        Path configuration = null;
        PkiOutputMode outputMode = PkiOutputMode.HUMAN;
        List<String> commandTokens = new ArrayList<>();
        boolean help = false;
        boolean outputSelected = false;
        java.time.Duration pendingWait = PkiPlanExecutor.DEFAULT_PENDING_WAIT;
        boolean pendingWaitSelected = false;
        RemoteOptions remoteOptions = new RemoteOptions();
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
            } else if (PENDING_WAIT.equals(argument)) {
                if (pendingWaitSelected) {
                    throw new IllegalArgumentException("PKI pending-wait option is duplicated");
                }
                pendingWait = parsePendingWait(requireValue(arguments, ++index));
                pendingWaitSelected = true;
            } else if ("--help".equals(argument) || "-h".equals(argument)) {
                help = true;
            } else if (isRemoteOption(argument)) {
                index = remoteOptions.accept(argument, arguments, index);
            } else {
                commandTokens.add(argument);
            }
        }
        if (help) {
            return new Invocation(null, outputMode, false, null, null, null, true, pendingWait, Optional.empty());
        }
        if (remoteOptions.url() != null) {
            return remoteInvocation(remoteOptions, commandTokens, outputMode, pendingWait);
        }
        if (remoteOptions.hasClientMaterial()) {
            throw new IllegalArgumentException("Remote client options require --url");
        }
        if (configuration == null || commandTokens.isEmpty()) {
            throw new IllegalArgumentException("PKI configuration or operation is missing");
        }
        String command = commandTokens.get(0);
        if (RUN.equals(command)) {
            if (commandTokens.size() != RUN_TOKEN_COUNT) {
                throw new IllegalArgumentException("Plan path is invalid");
            }
            return new Invocation(configuration, outputMode, true, Path.of(commandTokens.get(1)), null, null, false,
                    pendingWait, Optional.empty());
        }
        PkiOperationValue.ObjectValue operationArguments = directArguments(commandTokens.subList(1,
                commandTokens.size()));
        return new Invocation(configuration, outputMode, false, null, command, operationArguments, false,
                pendingWait, Optional.empty());
    }

    private static Invocation remoteInvocation(RemoteOptions remoteOptions, List<String> commandTokens,
            PkiOutputMode outputMode, java.time.Duration pendingWait) {
        PkiRemoteTarget target = remoteOptions.target();
        if (commandTokens.isEmpty()) {
            throw new IllegalArgumentException("Remote operation is missing");
        }
        String operation = commandTokens.get(0);
        if (RUN.equals(operation)) {
            throw new IllegalArgumentException("Remote mode executes a single operation, not a batch plan");
        }
        if (!REMOTE_OPERATION_ID.matcher(operation).matches()) {
            throw new IllegalArgumentException("Remote operation identifier is invalid");
        }
        PkiOperationValue.ObjectValue arguments = PkiRemoteArguments.parse(commandTokens.subList(1,
                commandTokens.size()), OPERATION_ARGUMENT_NAMES);
        Remote remote = new Remote(target, operation, arguments, Optional.ofNullable(remoteOptions.authorityId()),
                Optional.ofNullable(remoteOptions.approvalId()), Optional.ofNullable(remoteOptions.deadline()));
        return new Invocation(null, outputMode, false, null, null, null, false, pendingWait, Optional.of(remote));
    }

    private static boolean isRemoteOption(String argument) {
        return switch (argument) {
            case URL, CLIENT_KEYSTORE, CLIENT_KEYSTORE_PASSWORD_ENV, CLIENT_CERT, CLIENT_KEY, TRUST,
                    TRUST_PASSWORD_ENV, AUTHORITY_ID, APPROVAL_ID, DEADLINE -> true;
            default -> false;
        };
    }

    private static PkiOperationValue.ObjectValue directArguments(List<String> tokens) {
        if ((tokens.size() & 1) != 0) {
            throw new IllegalArgumentException("Operation arguments must be option-value pairs");
        }
        Map<String, PkiOperationValue> arguments = new LinkedHashMap<>();
        for (int index = 0; index < tokens.size(); index += 2) {
            String name = argumentName(tokens.get(index));
            String raw = tokens.get(index + 1);
            PkiOperationValue value = "limit".equals(name) || "profileVersion".equals(name)
                    ? new PkiOperationValue.IntegerValue(parseLong(raw)) : new PkiOperationValue.Text(raw);
            if (arguments.putIfAbsent(name, value) != null) {
                throw new IllegalArgumentException("Operation argument is duplicated");
            }
        }
        return new PkiOperationValue.ObjectValue(arguments);
    }

    private static String argumentName(String option) {
        String name = OPERATION_ARGUMENT_NAMES.get(option);
        if (name == null) {
            throw new IllegalArgumentException("Unknown PKI operation argument");
        }
        return name;
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

    // Keeping the complete stable command synopsis together prevents drift between fragmented help sections.
    @SuppressWarnings("PMD.NcssCount")
    private static void renderHelp(OutputStream output) {
        java.io.PrintWriter writer = new java.io.PrintWriter(output, false, java.nio.charset.StandardCharsets.UTF_8);
        writer.println("Usage (local, in-process):");
        writer.println("       zeroecho pki <operation> --config <file> [--output human|json]"
                + " [--pending-wait <seconds>] [arguments]");
        writer.println("       zeroecho pki run <plan-file> --config <file> [--output human|json]"
                + " [--pending-wait <seconds>]");
        writer.println("Usage (remote, pki-server admin API over mutual TLS):");
        writer.println("       zeroecho pki <operation.id> --url <https-base-url>"
                + " (--client-keystore <p12> [--client-keystore-password-env <ENV>]");
        writer.println("                     | --client-cert <pem> --client-key <pem>) [--trust <p12|pem>"
                + " [--trust-password-env <ENV>]]");
        writer.println("                     [--authority-id <id>] [--approval-id <id>] [--deadline <ISO-8601>]"
                + " [--output human|json] [--pending-wait <seconds>] [--arg name=value]...");
        writer.println("Mode selection: supplying --url together with client certificate material"
                + " (--client-keystore, or");
        writer.println("  --client-cert and --client-key) selects REMOTE mode; otherwise the LOCAL"
                + " in-process mode runs.");
        writer.println("  --url with missing/partial client material (or client material without --url)"
                + " is invalid (exit 2).");
        writer.println("  Remote mode ignores --config (no local backend providers are opened) and runs a"
                + " single operation.");
        writer.println("  Remote mode accepts any dotted operation id (including security.*, acme.*, ocsp.*,"
                + " repository.*);");
        writer.println("  arguments use --arg name=value, --arg-int name=value, --arg-bool name=true|false,"
                + " or the known --option spellings.");
        writer.println("  Passwords are read only from the named environment variables, never from the"
                + " command line.");
        writer.println("  --pending-wait <seconds>  bounded wait (default 3) for an asynchronously-signed");
        writer.println("                            operation to finish before a clean pending exit (code 7)");
        writer.println("Operations (local typed registry):");
        writer.println("  algorithm.binding.list --limit <1..1000> [--origin <origin>] [--role <role>]");
        writer.println("  algorithm.binding.inspect --binding-id <id>");
        writer.println("  algorithm.binding.validate [--binding-id <id> --binding-commitment <commitment>]");
        writer.println("  configuration.validate");
        writer.println("  profile.validate --profile-file <file>");
        writer.println("  profile.register --profile-file <file>");
        writer.println("  profile.inspect --profile-id <id> --profile-version <version>");
        writer.println("  profile.list --profile-id <id>");
        writer.println("  profile.activate --profile-id <id> --profile-version <version>");
        writer.println("  ca.inspect --ca-id <id>");
        writer.println("  ca.list --limit <1..1000>");
        writer.println("  ca.create --format-id <id> --subject-ref <subject> --profile-id <id> --key-ref <ref>");
        writer.println("  ca.transition --ca-id <id> --state <state> --reason <reason>");
        writer.println("  request.inspect --request-id <id>");
        writer.println("  request.import --format-id <id> --encoding DER --request-file <file>");
        writer.println("  request.verify --request-id <id>");
        writer.println("  credential.inspect --credential-id <id>");
        writer.println("  credential.issue --issuer-ca-id <id> --request-id <id> --profile-id <id>");
        writer.println("  credential.renew --credential-id <id>");
        writer.println("  credential.replace --existing-credential-id <id> --request-id <id> --profile-id <id>");
        writer.println("  credential.reissue --credential-id <id>");
        writer.println("  ca.intermediate.create --format-id <id> --issuer-ca-id <id> --subject-ref <subject>");
        writer.println("                         --profile-id <id> [--key-ref <ref>]");
        writer.println("  ca.intermediate.issue --format-id <id> --issuer-ca-id <id> --subject-ca-id <id>"
                + " --profile-id <id>");
        writer.println("  ca.rollover --ca-id <id> [--issuer-ca-id <id>]");
        writer.println("  ca.rotate --ca-id <id> [--new-key-ref <ref>] [--issuer-ca-id <id>]");
        writer.println("  issuer.generation.inspect --issuer-id <id>");
        writer.println("  issuer.path.inspect --path-id <id>");
        writer.println("  issuer.path.list --issuer-id <id>");
        writer.println("  issuer.path.register --ca-id <id> --issuer-id <id> --parent-path-id <id>");
        writer.println("  issuer.path.select --ca-id <id> --issuer-id <id> --path-id <id> --reason <reason>");
        writer.println("  credential.revoke --credential-id <id> --reason <permanent-reason>");
        writer.println("                    [--justification <operator-justification-or-ticket>]");
        writer.println("  revocation.inspect --credential-id <id>");
        writer.println("  revocation.history --credential-id <id> --limit <1..1000>");
        writer.println("  revocation.snapshot --limit <1..1000>");
        writer.println("  status.inspect --status-object-id <id>");
        writer.println("  status.generate --issuer-ca-id <id> --type <type> --format-id <id>");
        writer.println("  inventory.status --issuer-ca-id <id> --limit <1..1000>");
        writer.println("  publication.inspect --publication-id <id>");
        writer.println("  publication.list --limit <1..1000>");
        writer.println("  publication.register --publication-id <id> --source-type <type> --source-id <id>");
        writer.println("                       --target-type <type> --target-id <id>");
        writer.println("  publication.process --publication-id <id>");
        writer.println("  publication.retry --publication-id <id>");
        writer.println("  publication.reconcile --publication-id <id>");
        writer.flush();
    }

    private static PkiOutputMode parseOutput(String raw) {
        return switch (raw) {
            case "human" -> PkiOutputMode.HUMAN;
            case "json" -> PkiOutputMode.JSON;
            default -> throw new IllegalArgumentException("Output mode is invalid");
        };
    }

    private static java.time.Duration parsePendingWait(String raw) {
        long seconds;
        try {
            seconds = Long.parseLong(raw);
        } catch (NumberFormatException failure) {
            throw new IllegalArgumentException("Pending-wait seconds are invalid", failure);
        }
        if (seconds < 0L || seconds > 3600L) {
            throw new IllegalArgumentException("Pending-wait seconds are out of range");
        }
        return java.time.Duration.ofSeconds(seconds);
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

    /** Construction seam for the remote mutual-TLS HTTP exchange, overridable in tests. */
    @FunctionalInterface
    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    interface RemoteExchangeFactory {
        /**
         * Opens a mutual-TLS admin-API exchange for the supplied target.
         *
         * @param target validated connection target
         * @return an open exchange
         * @throws IOException on unreadable client or trust material
         * @throws GeneralSecurityException on invalid key, certificate, or store material
         */
        PkiHttpExchange open(PkiRemoteTarget target) throws IOException, GeneralSecurityException;
    }

    /** Mutable accumulator for the remote connection and scope options during parsing. */
    // Mutable parsing accumulator; behavior belongs to the enclosing CLI parser after validation.
    @SuppressWarnings("PMD.DataClass")
    private static final class RemoteOptions {
        private String url;
        private String clientKeystore;
        private String clientKeystorePasswordEnv;
        private String clientCert;
        private String clientKey;
        private String trust;
        private String trustPasswordEnv;
        private String authorityId;
        private String approvalId;
        private String deadline;

        private int accept(String option, String[] arguments, int index) {
            int cursor = index;
            String value = requireValue(arguments, ++cursor);
            switch (option) {
                case URL -> url = value;
                case CLIENT_KEYSTORE -> clientKeystore = value;
                case CLIENT_KEYSTORE_PASSWORD_ENV -> clientKeystorePasswordEnv = value;
                case CLIENT_CERT -> clientCert = value;
                case CLIENT_KEY -> clientKey = value;
                case TRUST -> trust = value;
                case TRUST_PASSWORD_ENV -> trustPasswordEnv = value;
                case AUTHORITY_ID -> authorityId = value;
                case APPROVAL_ID -> approvalId = value;
                case DEADLINE -> deadline = value;
                default -> throw new IllegalArgumentException("Unknown remote option");
            }
            return cursor;
        }

        private String url() {
            return url;
        }

        private String authorityId() {
            return authorityId;
        }

        private String approvalId() {
            return approvalId;
        }

        private String deadline() {
            return deadline;
        }

        private boolean hasClientMaterial() {
            return clientKeystore != null || clientKeystorePasswordEnv != null || clientCert != null
                    || clientKey != null || trust != null || trustPasswordEnv != null || authorityId != null
                    || approvalId != null || deadline != null;
        }

        private PkiRemoteTarget target() {
            return PkiRemoteTarget.parse(url, clientKeystore, clientKeystorePasswordEnv, clientCert, clientKey,
                    trust, trustPasswordEnv);
        }
    }

    /** One validated remote single-operation invocation. */
    private record Remote(PkiRemoteTarget target, String operationId, PkiOperationValue.ObjectValue arguments,
            Optional<String> authorityId, Optional<String> approvalId, Optional<String> deadline) {
    }

    private record Invocation(Path configuration, PkiOutputMode outputMode, boolean batch, Path plan,
            String operation, PkiOperationValue.ObjectValue arguments, boolean help,
            java.time.Duration pendingWait, Optional<Remote> remote) {
    }
}
