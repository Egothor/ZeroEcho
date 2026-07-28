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
package zeroecho;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.crypto.SecretKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Command-line utility for managing key material in a text-based keyring store.
 *
 * <h2>Overview</h2> The {@code KeyStoreManagement} subcommand provides
 * lifecycle operations on key material stored in
 * {@link zeroecho.core.storage.KeyringStore}. It supports listing algorithms
 * and aliases, generating key pairs or symmetric keys, exporting/importing
 * versioned text snippets, and overwriting existing entries.
 * 
 * The keystore is a plain-text file with aliases mapped to keys. Import/export
 * uses line-oriented snippets with format-version headers, suitable for
 * exchanging public keys or migrating key material between systems.
 *
 * <h2>Usage</h2> Invoked as: <pre>{@code
 * ZeroEcho -K [options]
 * }</pre>
 *
 * <h2>Modes</h2> Exactly one action must be chosen:
 * <ul>
 * <li>{@code --list-algorithms} - list catalog algorithms and whether they
 * support symmetric/asymmetric builders.</li>
 * <li>{@code --list-aliases} - list aliases present in the keystore.</li>
 * <li>{@code --generate} - generate a new key pair or secret and store under
 * the given alias.</li>
 * <li>{@code --export} - export one or more aliases as a versioned
 * snippet.</li>
 * <li>{@code --import} - import a versioned snippet into the keystore.</li>
 * </ul>
 *
 * <h2>General options</h2>
 * <ul>
 * <li>{@code -k | --keystore <file>} - path to keystore file (required).</li>
 * <li>{@code --overwrite} - overwrite existing aliases on conflict.</li>
 * </ul>
 *
 * <h2>Generate options</h2>
 * <ul>
 * <li>{@code --alg <id>} - algorithm id (e.g., RSA, Ed25519, AES, Frodo).</li>
 * <li>{@code --alias <name>} - base alias; for asymmetric, both public and
 * private entries will be created.</li>
 * <li>{@code --kind sym|asym} - force symmetric or asymmetric if the algorithm
 * supports both (optional).</li>
 * <li>{@code --pub-suffix <sfx>} - suffix for public alias (default:
 * .pub).</li>
 * <li>{@code --prv-suffix <sfx>} - suffix for private alias (default:
 * .prv).</li>
 * </ul>
 *
 * <h2>Export options</h2>
 * <ul>
 * <li>{@code --aliases a,b,c} - comma-separated list of aliases to export
 * (default: all).</li>
 * <li>{@code --out <file|-} - output file path (default: "-" for stdout).</li>
 * </ul>
 *
 * <h2>Import options</h2>
 * <ul>
 * <li>{@code --in <file|-} - input file path (default: "-" for stdin).</li>
 * <li>{@code --overwrite} - allow replacing existing aliases when
 * importing.</li>
 * </ul>
 *
 * <h2>Examples</h2> <pre>{@code
 * # List available algorithms
 * ZeroEcho -K --list-algorithms
 *
 * # Generate a new RSA key pair and store as alice.pub / alice.prv
 * ZeroEcho -K --generate --alg RSA --alias alice --keystore keys.txt
 *
 * # Generate a new AES secret key and store as "backup-key"
 * ZeroEcho -K --generate --alg AES --alias backup-key --kind sym --keystore keys.txt
 *
 * # List aliases in the keystore
 * ZeroEcho -K --list-aliases --keystore keys.txt
 *
 * # Export selected aliases to a file
 * ZeroEcho -K --export --aliases alice.pub,alice.prv --out alice-keys.txt --keystore keys.txt
 *
 * # Import aliases from stdin, overwriting if necessary
 * ZeroEcho -K --import --in - --overwrite --keystore keys.txt < alice-keys.txt
 * }</pre>
 *
 * <h2>Exit codes</h2>
 * <ul>
 * <li>0 - operation succeeded</li>
 * <li>non-zero - error occurred (parse error, I/O failure, or invalid
 * arguments)</li>
 * </ul>
 *
 * @since 1.0
 */
public final class KeyStoreManagement { // NOPMD

    private final static String STD_IN_OUT = "-";

    // ---------------------------------------------------------------------
    // Option constants (centralized for maintainability)
    // ---------------------------------------------------------------------

    private static final Option KEYSTORE_OPTION = Option.builder("k").longOpt("keystore").hasArg().argName("file")
            .desc("Path to keyring store").get();

    private static final Option LIST_ALGORITHMS_OPTION = Option.builder().longOpt("list-algorithms")
            .desc("List catalog algorithms with symmetric/asymmetric support").get();

    private static final Option LIST_ALIASES_OPTION = Option.builder().longOpt("list-aliases")
            .desc("List aliases present in the keyring").get();

    private static final Option GENERATE_OPTION = Option.builder().longOpt("generate")
            .desc("Generate a keypair or a secret").get();

    private static final Option ALG_OPTION = Option.builder().longOpt("alg").hasArg().argName("id")
            .desc("Algorithm id (e.g., RSA, Ed25519, AES, Frodo)").get();

    private static final Option ALIAS_OPTION = Option.builder().longOpt("alias").hasArg().argName("name")
            .desc("Alias base; for asymmetric, two entries will be written").get();

    private static final Option KIND_OPTION = Option.builder().longOpt("kind").hasArg().argName("sym|asym")
            .desc("Force symmetric or asymmetric when algorithm supports both").get();

    private static final Option PUB_SUFFIX_OPTION = Option.builder().longOpt("pub-suffix").hasArg().argName("sfx")
            .desc("Suffix for public alias (default .pub)").get();

    private static final Option PRV_SUFFIX_OPTION = Option.builder().longOpt("prv-suffix").hasArg().argName("sfx")
            .desc("Suffix for private alias (default .prv)").get();

    private static final Option OVERWRITE_OPTION = Option.builder().longOpt("overwrite")
            .desc("Overwrite existing aliases on conflict").get();

    private static final Option EXPORT_OPTION = Option.builder().longOpt("export")
            .desc("Export selected aliases as a versioned text snippet").get();

    private static final Option IMPORT_OPTION = Option.builder().longOpt("import")
            .desc("Import a versioned text snippet into the keyring").get();

    private static final Option ALIASES_OPTION = Option.builder().longOpt("aliases").hasArg().argName("a,b,c")
            .desc("Comma-separated aliases to export; empty means all").get();

    private static final Option OUTFILE_OPTION = Option.builder().longOpt("out").hasArg().argName("file|-")
            .desc("Output file for export (default '-' for stdout)").get();

    private static final Option INFILE_OPTION = Option.builder().longOpt("in").hasArg().argName("file|-")
            .desc("Input file for import (default '-' for stdin)").get();

    /** Prevents instantiation. */
    private KeyStoreManagement() {
    }

    // ---------------------------------------------------------------------
    // Entry point - lets exceptions bubble to the caller (ZeroEcho)
    // ---------------------------------------------------------------------

    /**
     * Parses arguments, executes the requested action, and returns an exit code.
     * Parser and IO exceptions are intentionally propagated for the central CLI to
     * handle.
     *
     * @param args              arguments passed by the application dispatcher
     * @param dispatcherOptions an existing {@code Options} instance used by the
     *                          dispatcher; this method only adds its own options
     * @return process exit code (0 for success; non-zero for semantic errors)
     * @throws ParseException if the parser fails
     * @throws IOException    if I/O fails
     */
    public static int main(final String[] args, final Options dispatcherOptions) throws ParseException, IOException {
        ZeroEchoSession session = new ZeroEchoSession();
        defineOptions(dispatcherOptions);
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(dispatcherOptions, args);

        if (cmd.hasOption(LIST_ALGORITHMS_OPTION.getLongOpt())) {
            listAlgorithms();
            return 0;
        }

        if (!cmd.hasOption(KEYSTORE_OPTION.getLongOpt())) {
            throw new ParseException("Missing required option: k/keystore");
        }

        Path keyringPath = Path.of(cmd.getOptionValue(KEYSTORE_OPTION.getLongOpt()));
        KeyringStore store = Files.exists(keyringPath) ? KeyringStore.load(session, keyringPath)
                : new KeyringStore(session);

        if (cmd.hasOption(LIST_ALIASES_OPTION.getLongOpt())) {
            listAliases(store);
            return 0;
        }
        if (cmd.hasOption(GENERATE_OPTION.getLongOpt())) {
            doGenerate(session, store, cmd);
            store.save(keyringPath);
            return 0;
        }
        if (cmd.hasOption(EXPORT_OPTION.getLongOpt())) {
            doExportSnippet(store, cmd);
            return 0;
        }
        if (cmd.hasOption(IMPORT_OPTION.getLongOpt())) {
            doImportSnippet(store, cmd);
            store.save(keyringPath);
            return 0;
        }

        throw new IllegalArgumentException("No operation selected");
    }

    /**
     * Adds this subcommand's options to the provided {@code Options} instance.
     *
     * @param options an existing {@code Options} instance from the central
     *                dispatcher
     */
    public static void defineOptions(final Options options) {
        options.addOption(KEYSTORE_OPTION);

        OptionGroup actions = new OptionGroup();
        actions.setRequired(true);
        actions.addOption(LIST_ALGORITHMS_OPTION);
        actions.addOption(LIST_ALIASES_OPTION);
        actions.addOption(GENERATE_OPTION);
        actions.addOption(EXPORT_OPTION);
        actions.addOption(IMPORT_OPTION);
        options.addOptionGroup(actions);

        options.addOption(ALG_OPTION);
        options.addOption(ALIAS_OPTION);
        options.addOption(KIND_OPTION);
        options.addOption(PUB_SUFFIX_OPTION);
        options.addOption(PRV_SUFFIX_OPTION);
        options.addOption(OVERWRITE_OPTION);

        options.addOption(ALIASES_OPTION);
        options.addOption(OUTFILE_OPTION);
        options.addOption(INFILE_OPTION);
    }

    // ---------------------------------------------------------------------
    // Actions
    // ---------------------------------------------------------------------

    /**
     * Lists available algorithms with builder availability to stdout.
     */
    public static void listAlgorithms() {
        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8); // NOPMD
        Set<String> ids = CryptoAlgorithms.available();
        for (String id : ids) {
            CryptoAlgorithm a = CryptoAlgorithms.require(id);
            boolean hasAsym = a.keyOperations().stream()
                    .anyMatch(info -> info.operation() != KeyOperation.SYMMETRIC_GENERATE
                            && info.operation() != KeyOperation.SYMMETRIC_IMPORT);
            boolean hasSym = a.keyOperations().stream()
                    .anyMatch(info -> info.operation() == KeyOperation.SYMMETRIC_GENERATE
                            || info.operation() == KeyOperation.SYMMETRIC_IMPORT);
            out.printf(Locale.ROOT, "%-12s  asym:%s  sym:%s%n", id, hasAsym, hasSym);
        }
    }

    /**
     * Lists aliases present in the store to stdout.
     *
     * @param store loaded keyring store
     */
    public static void listAliases(final KeyringStore store) {
        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8); // NOPMD
        List<String> aliases = store.aliases();
        if (aliases.isEmpty()) {
            out.println("(empty)");
            return;
        }
        for (String alias : aliases) {
            out.println(alias);
        }
    }

    /**
     * Generates a keypair or secret and stores entries under the chosen aliases.
     *
     * <p>
     * This reuses the same import-spec construction heuristic as the project's
     * dynamic tests: find plausible import-spec classes and build specs from
     * SPKI/PKCS8/RAW bytes.
     * </p>
     *
     * @param store keyring store to mutate
     * @param cmd   parsed command line
     */
    public static void doGenerate(final ZeroEchoSession session, final KeyringStore store,
            final CommandLine cmd) {
        String algId = required(cmd, ALG_OPTION, "--alg is required for --generate");
        String aliasBase = required(cmd, ALIAS_OPTION, "--alias is required for --generate");
        String kind = cmd.getOptionValue(KIND_OPTION.getLongOpt());
        String pubSfx = cmd.getOptionValue(PUB_SUFFIX_OPTION.getLongOpt(), ".pub");
        String prvSfx = cmd.getOptionValue(PRV_SUFFIX_OPTION.getLongOpt(), ".prv");
        boolean overwrite = cmd.hasOption(OVERWRITE_OPTION.getLongOpt());

        CryptoAlgorithm alg = CryptoAlgorithms.require(algId);
        boolean canAsym = alg.keyOperations().stream()
                .anyMatch(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE);
        boolean canSym = alg.keyOperations().stream()
                .anyMatch(info -> info.operation() == KeyOperation.SYMMETRIC_GENERATE);

        GenerationKind generationKind = selectGenerationKind(kind, canAsym, canSym);
        if (generationKind == GenerationKind.ASYMMETRIC) {
            generateAsymmetric(session, store, alg, algId, aliasBase, pubSfx, prvSfx, overwrite);
        }
        if (generationKind == GenerationKind.SYMMETRIC) {
            generateSymmetric(session, store, alg, algId, aliasBase, overwrite);
        }
    }

    private static GenerationKind selectGenerationKind(String requestedKind, boolean canAsymmetric,
            boolean canSymmetric) {
        if ("asym".equalsIgnoreCase(requestedKind) || requestedKind == null && canAsymmetric && !canSymmetric) {
            return GenerationKind.ASYMMETRIC;
        }
        if ("sym".equalsIgnoreCase(requestedKind) || requestedKind == null && canSymmetric && !canAsymmetric) {
            return GenerationKind.SYMMETRIC;
        }
        if (canAsymmetric && canSymmetric) {
            throw new IllegalArgumentException("Algorithm supports both; specify --kind sym|asym");
        }
        return GenerationKind.NONE;
    }

    private static void generateAsymmetric(ZeroEchoSession session, KeyringStore store, CryptoAlgorithm algorithm,
            String algorithmId, String aliasBase, String publicSuffix, String privateSuffix, boolean overwrite) {
        GeneratedKeyPair generated = firstGeneratedKeyPair(session, algorithm, algorithmId);
        Class<?> publicImport = findImportSpecClass(algorithm, KeyOperation.ASYMMETRIC_PUBLIC_IMPORT, true);
        Class<?> privateImport = findImportSpecClass(algorithm, KeyOperation.ASYMMETRIC_PRIVATE_IMPORT, false);
        if (publicImport == null && privateImport == null) {
            throw new IllegalStateException("No import spec class found for " + algorithmId + " (asymmetric)");
        }

        KeyPair pair = generated.pair();
        byte[] publicEncoding = pair.getPublic() == null ? null : pair.getPublic().getEncoded();
        byte[] privateEncoding = pair.getPrivate() == null ? null : pair.getPrivate().getEncoded();
        AlgorithmKeySpec publicSpec = publicImport == null ? null
                : makeImportSpec(publicImport, publicEncoding, algorithmId, generated.info().defaultSpec());
        AlgorithmKeySpec privateSpec = privateImport == null ? null
                : makeImportSpec(privateImport, privateEncoding, algorithmId, generated.info().defaultSpec());
        requireImportSpec(publicImport, publicSpec, "public", algorithmId);
        requireImportSpec(privateImport, privateSpec, "private", algorithmId);

        String publicAlias = aliasBase + publicSuffix;
        String privateAlias = aliasBase + privateSuffix;
        ensureWritable(store, publicAlias, overwrite);
        ensureWritable(store, privateAlias, overwrite);
        store.putPublic(publicAlias, algorithmId, publicSpec);
        store.putPrivate(privateAlias, algorithmId, privateSpec);

        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8); // NOPMD
        out.printf("Generated %s -> %s, %s%n", algorithmId, publicAlias, privateAlias);
    }

    private static GeneratedKeyPair firstGeneratedKeyPair(ZeroEchoSession session, CryptoAlgorithm algorithm,
            String algorithmId) {
        for (KeyOperationInfo info : algorithm.keyOperations()) {
            if (info.operation() != KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE || info.defaultSpec() == null) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) info.specType();
            try {
                KeyPair pair = session.keyBuilders().asymmetric().keyPairGenerator(algorithmId, specType)
                        .generateKeyPair(info.defaultSpec());
                if (pair != null) {
                    return new GeneratedKeyPair(pair, info);
                }
            } catch (GeneralSecurityException | RuntimeException ignored) { // NOPMD
                // Try the next registered default specification.
            }
        }
        throw new IllegalStateException("No asymmetric builder with default spec worked for " + algorithmId);
    }

    private static Class<?> findImportSpecClass(CryptoAlgorithm algorithm, KeyOperation operation,
            boolean publicImport) {
        for (KeyOperationInfo info : algorithm.keyOperations()) {
            boolean matchingName = publicImport ? looksLikeImportSpecForPublic(info.specType())
                    : looksLikeImportSpecForPrivate(info.specType());
            if (info.operation() == operation && matchingName) {
                return info.specType();
            }
        }
        return null;
    }

    private static void requireImportSpec(Class<?> specType, AlgorithmKeySpec spec, String kind, String algorithmId) {
        if (specType != null && spec == null) {
            throw new IllegalStateException("Cannot construct " + kind + " import spec for " + algorithmId);
        }
    }

    private static void generateSymmetric(ZeroEchoSession session, KeyringStore store, CryptoAlgorithm algorithm,
            String algorithmId, String alias, boolean overwrite) {
        GeneratedSecret generated = firstGeneratedSecret(session, algorithm, algorithmId);
        Class<?> importType = findSymmetricImportSpecClass(algorithm);
        if (importType == null) {
            throw new IllegalStateException("No symmetric import spec class for " + algorithmId);
        }

        byte[] encoding = generated.key().getEncoded();
        AlgorithmKeySpec spec = makeImportSpec(importType, encoding, algorithmId, generated.info().defaultSpec());
        if (spec == null) {
            throw new IllegalStateException("Cannot construct symmetric import spec for " + algorithmId);
        }
        ensureWritable(store, alias, overwrite);
        store.putSecret(alias, algorithmId, spec);

        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8); // NOPMD
        out.printf("Generated %s -> %s%n", algorithmId, alias);
    }

    private static GeneratedSecret firstGeneratedSecret(ZeroEchoSession session, CryptoAlgorithm algorithm,
            String algorithmId) {
        for (KeyOperationInfo info : algorithm.keyOperations()) {
            if (info.operation() != KeyOperation.SYMMETRIC_GENERATE || info.defaultSpec() == null) {
                continue;
            }
            @SuppressWarnings("unchecked")
            Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) info.specType();
            try {
                SecretKey key = session.keyBuilders().symmetric().generator(algorithmId, specType)
                        .generateSecret(info.defaultSpec());
                if (key != null) {
                    return new GeneratedSecret(key, info);
                }
            } catch (GeneralSecurityException | RuntimeException ignored) { // NOPMD
                // Try the next registered default specification.
            }
        }
        throw new IllegalStateException("No symmetric builder with default spec worked for " + algorithmId);
    }

    private record GeneratedKeyPair(KeyPair pair, KeyOperationInfo info) {
    }

    private record GeneratedSecret(SecretKey key, KeyOperationInfo info) {
    }

    /** Selects the exact key-generation operation requested by the command. */
    private enum GenerationKind {
        ASYMMETRIC,
        SYMMETRIC,
        NONE
    }

    /**
     * Exports a versioned, line-oriented snippet to stdout or a file.
     *
     * @param store source keyring store
     * @param cmd   parsed command line
     * @throws IOException if writing fails
     */
    public static void doExportSnippet(final KeyringStore store, final CommandLine cmd) throws IOException {
        List<String> aliases = parseCsv(cmd.getOptionValue(ALIASES_OPTION.getLongOpt(), ""));
        if (aliases.isEmpty()) {
            aliases = store.aliases();
        }

        String text = store.exportText(aliases);
        String outFile = cmd.getOptionValue(OUTFILE_OPTION.getLongOpt(), STD_IN_OUT);

        if (STD_IN_OUT.equals(outFile)) {
            try (PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8)) {
                out.print(text);
                if (!text.endsWith("\n")) {
                    out.println();
                }
            }
        } else {
            Files.writeString(Path.of(outFile), text, StandardCharsets.UTF_8);
            System.out.printf("Wrote snippet: %s%n", outFile);
        }
    }

    /**
     * Imports a versioned, line-oriented snippet from stdin or a file.
     *
     * @param store destination keyring store
     * @param cmd   parsed command line
     * @throws IOException if reading fails or the snippet is invalid
     */
    public static void doImportSnippet(final KeyringStore store, final CommandLine cmd) throws IOException {
        boolean overwrite = cmd.hasOption(OVERWRITE_OPTION.getLongOpt());
        String inFile = cmd.getOptionValue(INFILE_OPTION.getLongOpt(), STD_IN_OUT);

        String text;
        if (STD_IN_OUT.equals(inFile)) {
            StringBuilder sb = new StringBuilder(1024);
            try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                String line = br.readLine();
                while (line != null) {
                    sb.append(line).append('\n');
                    line = br.readLine();
                }
            }
            text = sb.toString();
        } else {
            text = Files.readString(Path.of(inFile), StandardCharsets.UTF_8);
        }

        store.importText(text, overwrite);
        PrintWriter out = new PrintWriter(System.out, true, StandardCharsets.UTF_8); // NOPMD
        out.println("Imported snippet.");
    }

    // ---------------------------------------------------------------------
    // Helpers - EXACTLY the dynamic-test strategy
    // ---------------------------------------------------------------------

    private static boolean looksLikeImportSpecForPublic(Class<?> specType) {
        String n = specType.getSimpleName();
        return n.contains("Public") || n.endsWith("PublicKeySpec");
    }

    private static boolean looksLikeImportSpecForPrivate(Class<?> specType) {
        String n = specType.getSimpleName();
        return n.contains("Private") || n.endsWith("PrivateKeySpec");
    }

    private static Class<?> findSymmetricImportSpecClass(CryptoAlgorithm alg) {
        for (KeyOperationInfo x : alg.keyOperations()) {
            if (x.operation() == KeyOperation.SYMMETRIC_IMPORT) {
                return x.specType();
            }
        }
        return null;
    }

    /**
     * Constructs an AlgorithmKeySpec from encoded bytes using conventional
     * factories/ctors. Mirrors the makeImportSpec approach used in the dynamic
     * test.
     *
     * @param specType    target spec class
     * @param material    encoded bytes (SPKI, PKCS#8, or RAW)
     * @param algId       algorithm id (used for variant name heuristics)
     * @param defaultSpec the default spec used by the builder (for optional variant
     *                    hints)
     * @return constructed AlgorithmKeySpec or null if none matched
     */
    private static AlgorithmKeySpec makeImportSpec(Class<?> specType, byte[] material, String algId,
            Object defaultSpec) {
        if (material == null) {
            return null;
        }
        try {
            Method m = specType.getMethod("fromRaw", byte[].class);
            Object spec = m.invoke(null, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) { // NOPMD
        }
        try {
            Method m = specType.getMethod("fromRaw", String.class, byte[].class);
            String name = deriveVariantNameForImport(algId, defaultSpec);
            Object spec = m.invoke(null, name, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) { // NOPMD
        }
        try {
            Method m = specType.getMethod("of", byte[].class);
            Object spec = m.invoke(null, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) { // NOPMD
        }
        try {
            Constructor<?> c = specType.getConstructor(byte[].class);
            Object spec = c.newInstance(material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) { // NOPMD
        }
        try {
            Constructor<?> c = specType.getConstructor(String.class);
            String b64 = Base64.getEncoder().encodeToString(material);
            Object spec = c.newInstance(b64);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) { // NOPMD
        }
        return null;
    }

    private static String deriveVariantNameForImport(String algId, Object defaultSpec) {
        if (defaultSpec != null) {
            try {
                Method m = defaultSpec.getClass().getMethod("macName");
                Object v = m.invoke(defaultSpec);
                if (v instanceof String) {
                    return (String) v;
                }
            } catch (Throwable ignored) { // NOPMD
            }
        }
        if ("HMAC".equalsIgnoreCase(algId)) { // NOPMD
            return "HmacSHA256";
        }
        return algId;
    }

    private static String required(CommandLine cmd, Option opt, String message) {
        if (!cmd.hasOption(opt.getLongOpt())) {
            throw new IllegalArgumentException(message);
        }
        return cmd.getOptionValue(opt.getLongOpt());
    }

    private static List<String> parseCsv(String csv) {
        List<String> list = new ArrayList<>();
        if (csv == null || csv.isBlank()) {
            return list;
        }
        String[] parts = csv.split("\\s*,\\s*");
        for (String part : parts) {
            if (!part.isBlank()) {
                list.add(part);
            }
        }
        return list;
    }

    /**
     * Ensures that an alias can be written under the current collision policy.
     *
     * @param store     keyring store
     * @param alias     alias to check
     * @param overwrite whether collisions are allowed
     * @throws IllegalArgumentException if alias exists and overwrite is false
     */
    private static void ensureWritable(KeyringStore store, String alias, boolean overwrite) {
        if (store.contains(alias) && !overwrite) {
            throw new IllegalArgumentException("Alias already exists: " + alias + " (use --overwrite)");
        }
    }
}
