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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringStore;
import zeroecho.core.util.RandomSupport;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.builders.core.PlainFileBuilder;
import zeroecho.sdk.guard.MultiRecipientContent;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.RecipientKekSizes;
import zeroecho.sdk.guard.UnlockMaterial;

/**
 * Guard is a unified subcommand that encrypts and decrypts using a
 * multi-recipient envelope with AES or ChaCha payloads.
 *
 * <h2>Overview</h2> The class replaces the previous MultiRecipientAes and
 * PasswordBasedAes CLIs by exposing a single entry point. It builds an envelope
 * with a recipients table (real and decoy) via
 * {@code MultiRecipientDataSourceBuilder}, then delegates the payload to either
 * {@code AesDataContentBuilder} or {@code ChaChaDataContentBuilder}.
 *
 * <p>
 * Default behavior:
 * </p>
 * <ul>
 * <li>Recipients are shuffled by default to harden traffic analysis. Disable
 * with {@code --no-shuffle}.</li>
 * <li>The symmetric stage writes and parses its own header by default.</li>
 * </ul>
 *
 * <h2>Keyring resolution</h2> Recipient aliases and the unlocking alias are
 * resolved from {@code KeyringStore}. The algorithm id stored in the keyring
 * drives which recipient method to call, so the user does not have to specify
 * the algorithm again.
 *
 * <h2>Payload selection</h2> Use {@code --alg} to choose one of:
 * {@code aes-gcm}, {@code aes-ctr}, {@code aes-cbc-pkcs7},
 * {@code aes-cbc-nopad}, {@code chacha-aead}, {@code chacha-stream}.
 *
 * <h2>Examples</h2> <pre>{@code
 * # Encrypt with KEM + RSA recipients, 2 decoy passwords, AES-GCM
 * ZeroEcho -G --encrypt in.bin --ks keys.txt \
 *   --to-alias alice --to-alias bob \
 *   --decoy-psw-rand 2 \
 *   --pbkdf2-max "$PBKDF2_POLICY_MAX" \
 *   --pbkdf2-hard-max "$PBKDF2_HARD_MAX" \
 *   --alg aes-gcm --tag-bits 128 --aad-hex 01ff
 *
 * # Decrypt with private key (payload is ChaCha20-Poly1305)
 * ZeroEcho -G --decrypt blob.bin --ks keys.txt \
 *   --priv-alias alice \
 *   --alg chacha-aead
 * }</pre>
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class Guard {

    private Guard() {
    }

    /**
     * Entry point for the Guard subcommand. It preserves Apache Commons CLI usage
     * and the subcommand invocation pattern used by {@code ZeroEcho}.
     *
     * @param args    command-line arguments
     * @param options options object provided by the dispatcher; this method
     *                augments it
     * @return exit code (0 = success, non-zero = failure)
     * @throws ParseException           on CLI parsing errors
     * @throws IOException              on I/O errors
     * @throws GeneralSecurityException on cryptographic setup or keyring errors
     */
    public static int main(final String[] args, final Options options)
            throws ParseException, IOException, GeneralSecurityException {
        return main(args, options, KeyringUnlocks.console());
    }

    /**
     * Executes Guard with an explicit keyring unlock source.
     *
     * @param args                  command arguments
     * @param options               dispatcher options
     * @param keyringUnlockProvider destroyable-password provider
     * @return process exit code
     * @throws ParseException           if parsing fails
     * @throws IOException              if I/O fails
     * @throws GeneralSecurityException if cryptographic processing fails
     */
    @SuppressWarnings({ "PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.CyclomaticComplexity", "PMD.NPathComplexity" })
    public static int main(final String[] args, final Options options, KeyringUnlockProvider keyringUnlockProvider)
            throws ParseException, IOException, GeneralSecurityException {
        // ---- operation selection
        final Option OPT_ENCRYPT = Option.builder("e").longOpt("encrypt").hasArg().argName("in-file")
                .desc("Encrypt the given file").get();
        final Option OPT_DECRYPT = Option.builder("d").longOpt("decrypt").hasArg().argName("in-file")
                .desc("Decrypt the given file").get();
        final OptionGroup OP = new OptionGroup().addOption(OPT_ENCRYPT).addOption(OPT_DECRYPT);
        OP.setRequired(true);

        // ---- common I/O
        final Option OPT_OUT = Option.builder("o").longOpt("output").hasArg().argName("out-file")
                .desc("Output file (default: <in>.enc for encrypt, <in>.dec for decrypt)").get();
        final Option OPT_KEYRING = Option.builder().longOpt("keyring").hasArg().argName("keyring.txt")
                .desc("KeyringStore file for aliases (required when aliases are used)").get();

        // ---- payload selection and parameters
        final Option OPT_ALG = Option.builder().longOpt("alg").hasArg().argName("name")
                .desc("Payload: aes-gcm | aes-ctr | aes-cbc-pkcs7 | aes-cbc-nopad | chacha-aead | chacha-stream "
                        + "(default: aes-gcm)")
                .get();
        final Option OPT_AAD_HEX = Option.builder("a").longOpt("aad-hex").hasArg().argName("hex")
                .desc("Additional authenticated data as hex (AEAD modes)").get();
        final Option OPT_TAG_BITS = Option.builder().longOpt("tag-bits").hasArg().argName("96..128")
                .desc("AES-GCM tag length in bits (default 128)").get();
        final Option OPT_NONCE_HEX = Option.builder().longOpt("nonce-hex").hasArg().argName("hex")
                .desc("ChaCha decryption nonce (12-byte hex; rejected for encryption)").get();
        final Option OPT_INIT_CTR = Option.builder().longOpt("init-ctr").hasArg().argName("int")
                .desc("ChaCha stream initial counter (default 1)").get();
        final Option OPT_CTR = Option.builder().longOpt("ctr").hasArg().argName("int")
                .desc("ChaCha stream counter override (propagated via context)").get();
        final Option OPT_NO_HDR = Option.builder().longOpt("no-header")
                .desc("Do not write or expect a symmetric header").get();

        // ---- envelope parameters
        final Option OPT_CEK_BYTES = Option.builder().longOpt("cek-bytes").hasArg().argName("len")
                .desc("Payload key (CEK) length in bytes (default 32)").get();
        final Option OPT_MAX_RECIPS = Option.builder().longOpt("max-recipients").hasArg().argName("n")
                .desc("Max recipients in the envelope header (default 64)").get();
        final Option OPT_MAX_ENTRY = Option.builder().longOpt("max-entry-len").hasArg().argName("bytes")
                .desc("Max single recipient-entry length (default 1048576)").get();
        final Option OPT_NO_SHUFFLE = Option.builder().longOpt("no-shuffle")
                .desc("Disable shuffling of recipients (enabled by default)").get();

        // ---- recipients (real)
        final Option OPT_TO_ALIAS = Option.builder().longOpt("to-alias").hasArg().argName("alias")
                .desc("Add recipient by alias from keyring (repeatable)").get();
        final Option OPT_TO_PSW = Option.builder().longOpt("to-psw").hasArg().argName("password")
                .desc("Add password recipient (repeatable)").get();
        final Option OPT_PSW_ITER = Option.builder().longOpt("to-iter").hasArg().argName("n")
                .desc("PBKDF2 iterations for password recipients (default 200000)").get();
        final Option OPT_PSW_SALT = Option.builder().longOpt("to-salt-len").hasArg().argName("bytes")
                .desc("PBKDF2 salt length for password recipients (default 16)").get();
        final Option OPT_PSW_KEK = Option.builder().longOpt("to-kek-bytes").hasArg().argName("bytes")
                .desc("Recipient KEK length: exactly 16 or 32 bytes (default 32)").get();
        final Option OPT_PBKDF2_MAX = Option.builder().longOpt("pbkdf2-max").hasArg().argName("iterations")
                .desc("Operational PBKDF2 ceiling; required for password operations").get();
        final Option OPT_PBKDF2_HARD_MAX = Option.builder().longOpt("pbkdf2-hard-max").hasArg().argName("iterations")
                .desc("Absolute decoded PBKDF2 safety ceiling; required for password operations").get();

        // ---- decoys (all types)
        final Option OPT_DECOY_ALIAS = Option.builder().longOpt("decoy-alias").hasArg().argName("alias")
                .desc("Add a decoy recipient from keyring (repeatable)").get();
        final Option OPT_DECOY_PSW = Option.builder().longOpt("decoy-psw").hasArg().argName("password")
                .desc("Add a decoy password recipient (repeatable)").get();
        final Option OPT_DECOY_PSW_RAND = Option.builder().longOpt("decoy-psw-rand").hasArg().argName("n")
                .desc("Add N random decoy password recipients").get();

        // ---- unlock (decrypt)
        final Option OPT_PRIV_ALIAS = Option.builder().longOpt("priv-alias").hasArg().argName("alias")
                .desc("Unlock with private key from keyring").get();
        final Option OPT_PASSWORD = Option.builder("p").longOpt("password").hasArg().argName("password")
                .desc("Unlock with password").get();

        options.addOptionGroup(OP);
        options.addOption(OPT_OUT);
        options.addOption(OPT_KEYRING);

        options.addOption(OPT_ALG);
        options.addOption(OPT_AAD_HEX);
        options.addOption(OPT_TAG_BITS);
        options.addOption(OPT_NONCE_HEX);
        options.addOption(OPT_INIT_CTR);
        options.addOption(OPT_CTR);
        options.addOption(OPT_NO_HDR);

        options.addOption(OPT_CEK_BYTES);
        options.addOption(OPT_MAX_RECIPS);
        options.addOption(OPT_MAX_ENTRY);
        options.addOption(OPT_NO_SHUFFLE);

        options.addOption(OPT_TO_ALIAS);
        options.addOption(OPT_TO_PSW);
        options.addOption(OPT_PSW_ITER);
        options.addOption(OPT_PSW_SALT);
        options.addOption(OPT_PSW_KEK);
        options.addOption(OPT_PBKDF2_MAX);
        options.addOption(OPT_PBKDF2_HARD_MAX);

        options.addOption(OPT_DECOY_ALIAS);
        options.addOption(OPT_DECOY_PSW);
        options.addOption(OPT_DECOY_PSW_RAND);

        options.addOption(OPT_PRIV_ALIAS);
        options.addOption(OPT_PASSWORD);

        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd = parser.parse(options, args);
        final boolean passwordOperation = cmd.hasOption(OPT_TO_PSW) || cmd.hasOption(OPT_DECOY_PSW)
                || cmd.hasOption(OPT_DECOY_PSW_RAND) || cmd.hasOption(OPT_PASSWORD);
        final ZeroEchoSession session = createSession(cmd, OPT_PBKDF2_MAX, OPT_PBKDF2_HARD_MAX, passwordOperation);

        final boolean encrypt = cmd.hasOption(OPT_ENCRYPT);
        final Path inPath = Paths.get(cmd.getOptionValue(encrypt ? OPT_ENCRYPT : OPT_DECRYPT));
        final Path outPath = computeOutPath(cmd, inPath, encrypt);

        final String alg = cmd.getOptionValue(OPT_ALG, "aes-gcm").toLowerCase(Locale.ROOT);

        final byte[] aad = cmd.hasOption(OPT_AAD_HEX) ? parseHex(cmd.getOptionValue(OPT_AAD_HEX)) : null;
        final int tagBits = Integer.parseInt(cmd.getOptionValue(OPT_TAG_BITS, "128"));
        final byte[] chachaNonce = cmd.hasOption(OPT_NONCE_HEX) ? parseHex(cmd.getOptionValue(OPT_NONCE_HEX)) : null;
        final Integer initCtr = cmd.hasOption(OPT_INIT_CTR) ? Integer.valueOf(cmd.getOptionValue(OPT_INIT_CTR)) : null;
        final Integer ctrOverride = cmd.hasOption(OPT_CTR) ? Integer.valueOf(cmd.getOptionValue(OPT_CTR)) : null;
        final boolean header = !cmd.hasOption(OPT_NO_HDR);

        final int cekBytes = Integer.parseInt(cmd.getOptionValue(OPT_CEK_BYTES, "32"));
        final int maxRecipients = Integer.parseInt(cmd.getOptionValue(OPT_MAX_RECIPS, "64"));
        final int maxEntryLen = Integer.parseInt(cmd.getOptionValue(OPT_MAX_ENTRY, "1048576"));
        final boolean shuffle = !cmd.hasOption(OPT_NO_SHUFFLE); // default true

        // configure symmetric builder
        final AesDataContentBuilder aes;
        final ChaChaDataContentBuilder chacha;
        switch (alg) {
            case "aes-gcm" -> {
                aes = AesDataContentBuilder.builder(session).modeGcm(tagBits);
                if (header) {
                    aes.withHeader();
                }
                if (aad != null) {
                    aes.withAad(aad);
                }
                chacha = null;
            }
            case "aes-ctr" -> {
                aes = AesDataContentBuilder.builder(session).modeCtr();
                if (header) {
                    aes.withHeader();
                }
                chacha = null;
            }
            case "aes-cbc-pkcs7" -> {
                aes = AesDataContentBuilder.builder(session).modeCbcPkcs5();
                if (header) {
                    aes.withHeader();
                }
                chacha = null;
            }
            case "aes-cbc-nopad" -> {
                aes = AesDataContentBuilder.builder(session).modeCbcNoPadding();
                if (header) {
                    aes.withHeader();
                }
                chacha = null;
            }
            case "chacha-aead" -> {
                chacha = ChaChaDataContentBuilder.builder(session);
                // selecting AEAD: if the user did not supply AAD, pass empty to pick AEAD
                chacha.withAad(aad != null ? aad : new byte[0]);
                if (header) {
                    chacha.withHeader();
                }
                if (chachaNonce != null) {
                    chacha.withDecryptionNonce(chachaNonce);
                }
                if (ctrOverride != null || initCtr != null) {
                    // providing counters together with AAD would be conflicting; builder enforces
                    // it
                    if (initCtr != null) {
                        chacha.initialCounter(initCtr);
                    }
                    if (ctrOverride != null) {
                        chacha.withCounter(ctrOverride);
                    }
                }
                aes = null;
            }
            case "chacha-stream" -> {
                chacha = ChaChaDataContentBuilder.builder(session);
                if (header) {
                    chacha.withHeader();
                }
                if (chachaNonce != null) {
                    chacha.withDecryptionNonce(chachaNonce);
                }
                if (initCtr != null) {
                    chacha.initialCounter(initCtr);
                }
                if (ctrOverride != null) {
                    chacha.withCounter(ctrOverride);
                }
                aes = null;
            }
            default -> throw new ParseException("Unknown --alg: " + alg);
        }

        // envelope builder (new API)
        final MultiRecipientDataSourceBuilder env = MultiRecipientDataSourceBuilder.builder(session)
                .payloadKeyBytes(cekBytes).headerLimits(maxRecipients, maxEntryLen);
        UnlockMaterial borrowedUnlockMaterial = null;
        try (env) {
            if (aes != null) {
                env.withAes(aes);
            } else {
                env.withChaCha(chacha);
            }
            if (shuffle) {
                env.shuffle();
            }
            if (encrypt) {
                final int iter = Integer.parseInt(cmd.getOptionValue(OPT_PSW_ITER, "200000"));
                final int saltLen = Integer.parseInt(cmd.getOptionValue(OPT_PSW_SALT, "16"));
                final int kekLen = RecipientKekSizes
                        .requireSupported(Integer.parseInt(cmd.getOptionValue(OPT_PSW_KEK, "32")));

                KeyringStore ks = loadKeyringIfPresent(cmd, OPT_KEYRING, keyringUnlockProvider);
                try (ks) {
                    for (String alias : cmd.getOptionValues(OPT_TO_ALIAS) == null ? new String[0]
                            : cmd.getOptionValues(OPT_TO_ALIAS)) {
                        addRecipientFromAlias(session, env, ks, alias, kekLen, saltLen, false);
                    }
                    for (String psw : cmd.getOptionValues(OPT_TO_PSW) == null ? new String[0]
                            : cmd.getOptionValues(OPT_TO_PSW)) {
                        char[] passwordChars = psw.toCharArray();
                        try {
                            env.addPasswordRecipient(passwordChars, iter, saltLen, kekLen);
                        } finally {
                            Arrays.fill(passwordChars, '\0');
                        }
                    }
                    for (String alias : cmd.getOptionValues(OPT_DECOY_ALIAS) == null ? new String[0]
                            : cmd.getOptionValues(OPT_DECOY_ALIAS)) {
                        addRecipientFromAlias(session, env, ks, alias, kekLen, saltLen, true);
                    }
                    for (String psw : cmd.getOptionValues(OPT_DECOY_PSW) == null ? new String[0]
                            : cmd.getOptionValues(OPT_DECOY_PSW)) {
                        char[] passwordChars = psw.toCharArray();
                        try {
                            env.addPasswordRecipientDecoy(passwordChars, iter, saltLen, kekLen);
                        } finally {
                            Arrays.fill(passwordChars, '\0');
                        }
                    }
                    final int rndCount = Integer.parseInt(cmd.getOptionValue(OPT_DECOY_PSW_RAND, "0"));
                    for (int i = 0; i < rndCount; i++) {
                        char[] passwordChars = randomPassword();
                        try {
                            env.addPasswordRecipientDecoy(passwordChars, iter, saltLen, kekLen);
                        } finally {
                            Arrays.fill(passwordChars, '\0');
                        }
                    }
                }
            } else {
                final String privAlias = cmd.getOptionValue(OPT_PRIV_ALIAS);
                final String password = cmd.getOptionValue(OPT_PASSWORD);

                if ((privAlias == null && password == null) || (privAlias != null && password != null)) {
                    throw new ParseException("Specify exactly one of --priv-alias or --password for decryption");
                }
                if (privAlias != null) {
                    try (KeyringStore ks = requireKeyring(cmd, OPT_KEYRING, keyringUnlockProvider)) {
                        final KeyringStore.PrivateWithId pr = ks.getPrivateWithId(privAlias);
                        borrowedUnlockMaterial = new UnlockMaterial.Private(pr.key());
                    }
                } else {
                    char[] passwordChars = password.toCharArray();
                    try {
                        borrowedUnlockMaterial = new UnlockMaterial.Password(passwordChars);
                    } finally {
                        Arrays.fill(passwordChars, '\0');
                    }
                }
                env.unlockWith(borrowedUnlockMaterial);
            }

            try (MultiRecipientContent content = env.build(encrypt)) {
                content.setInput(PlainFileBuilder.builder().url(inPath.toUri().toURL()).build(encrypt));
                try (InputStream in = content.getStream(); OutputStream out = Files.newOutputStream(outPath)) {
                    in.transferTo(out);
                }
            }
        } finally {
            if (borrowedUnlockMaterial instanceof UnlockMaterial.Password passwordMaterial) {
                passwordMaterial.destroy();
            }
        }

        return 0;
    }

    // -------------------------------------------------------------------------
    // Helpers (package-private/private)
    // -------------------------------------------------------------------------

    private static Path computeOutPath(CommandLine cmd, Path inPath, boolean encrypt) {
        if (cmd.hasOption("output")) {
            return Paths.get(cmd.getOptionValue("output"));
        }
        final String s = inPath.toString();
        final String suffix = encrypt ? ".enc" : ".dec";
        return Paths.get(s + suffix);
    }

    private static ZeroEchoSession createSession(CommandLine cmd, Option operationalMaximumOption,
            Option absoluteMaximumOption, boolean passwordOperation) throws ParseException {
        boolean hasOperationalMaximum = cmd.hasOption(operationalMaximumOption);
        boolean hasAbsoluteMaximum = cmd.hasOption(absoluteMaximumOption);
        if (!hasOperationalMaximum && !hasAbsoluteMaximum) {
            if (passwordOperation) {
                throw new ParseException("Password operations require --pbkdf2-max and --pbkdf2-hard-max");
            }
            return new ZeroEchoSession();
        }
        if (!hasOperationalMaximum || !hasAbsoluteMaximum) {
            throw new ParseException("--pbkdf2-max and --pbkdf2-hard-max must be specified together");
        }
        try {
            int operationalMaximum = Integer.parseInt(cmd.getOptionValue(operationalMaximumOption));
            int absoluteMaximum = Integer.parseInt(cmd.getOptionValue(absoluteMaximumOption));
            return new ZeroEchoSession().withPbkdf2Limits(new Pbkdf2Limits(operationalMaximum, absoluteMaximum));
        } catch (IllegalArgumentException exception) {
            ParseException parseException = new ParseException("Invalid PBKDF2 limits: " + exception.getMessage());
            parseException.initCause(exception);
            throw parseException;
        }
    }

    private static byte[] parseHex(String s) throws ParseException {
        try {
            return HexFormat.of().parseHex(s);
        } catch (IllegalArgumentException ex) {
            throw new ParseException("Bad hex: " + ex.getMessage()); // NOPMD
        }
    }

    /**
     * Adds a recipient to the given multi-recipient encryption builder by resolving
     * a public key from the keyring.
     *
     * <p>
     * The method looks up the alias in the {@link KeyringStore}, extracts its
     * algorithm identifier and public key, and then attempts to create an
     * appropriate cryptographic context:
     * </p>
     * <ul>
     * <li><b>KEM path</b>: If the algorithm supports
     * {@link zeroecho.core.context.KemContext} under
     * {@link zeroecho.core.KeyUsage#ENCAPSULATE}, a key encapsulation recipient is
     * added with the provided key-encryption key (KEK) size and salt length.</li>
     * <li><b>Fallback path</b>: If KEM encapsulation is not supported, the method
     * falls back to {@link zeroecho.core.context.EncryptionContext} under
     * {@link zeroecho.core.KeyUsage#ENCRYPT} for classic public-key
     * encryption.</li>
     * </ul>
     *
     * <p>
     * In both cases, the created context is consumed by the matching
     * {@link MultiRecipientDataSourceBuilder} recipient method and is closed
     * internally by the resulting content.
     * </p>
     *
     * @param env      target builder to which the recipient is added
     * @param ks       keyring store that provides public keys by alias
     * @param alias    alias name of the recipient's public key in the keyring
     * @param kekBytes key-encryption key length; exactly 16 or 32 bytes
     * @param saltLen  salt length in bytes when using KEM
     * @param decoy    whether the recipient is a decoy
     * @throws GeneralSecurityException if the algorithm does not support the
     *                                  requested usage or key material is invalid
     * @throws IOException              if context creation or builder operations
     *                                  require I/O and fail
     */
    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    private static void addRecipientFromAlias(ZeroEchoSession session, MultiRecipientDataSourceBuilder env,
            KeyringStore ks, String alias, int kekBytes, int saltLen, boolean decoy)
            throws GeneralSecurityException, IOException {
        KeyringStore.PublicWithId r = ks.getPublicWithId(alias);
        final String algId = r.algorithm();
        final java.security.PublicKey pub = r.key();

        KemContext kem;
        try {
            kem = session.createContext(algId, KeyUsage.ENCAPSULATE, pub);
        } catch (UnsupportedRoleException notKem) {
            addEncryptionRecipient(session, env, algId, pub, decoy);
            return;
        }

        boolean transferred = false;
        try {
            if (decoy) {
                env.addRecipientDecoy(kem, kekBytes, saltLen);
            } else {
                env.addRecipient(kem, kekBytes, saltLen);
            }
            transferred = true;
        } finally {
            if (!transferred) {
                kem.close();
            }
        }
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.UseTryWithResources" })
    private static void addEncryptionRecipient(ZeroEchoSession session, MultiRecipientDataSourceBuilder env,
            String algorithmId, java.security.PublicKey publicKey, boolean decoy) throws IOException {
        EncryptionContext encryption = session.createContext(algorithmId, KeyUsage.ENCRYPT, publicKey);
        boolean transferred = false;
        try {
            if (decoy) {
                env.addRecipientDecoy(encryption);
            } else {
                env.addRecipient(encryption);
            }
            transferred = true;
        } finally {
            if (!transferred) {
                encryption.close();
            }
        }
    }

    private static char[] randomPassword() {
        // simple random alnum for decoy purposes only
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        final int len = 16 + RandomSupport.nextInt(17); // 16..32
        final char[] out = new char[len];
        for (int i = 0; i < len; i++) {
            out[i] = alphabet.charAt(RandomSupport.nextInt(alphabet.length()));
        }
        return out;
    }

    private static KeyringStore loadKeyringIfPresent(CommandLine cmd, Option optKs,
            KeyringUnlockProvider unlockProvider) throws IOException, GeneralSecurityException {
        if (!cmd.hasOption(optKs)) {
            return null;
        }
        return KeyringUnlocks.open(Paths.get(cmd.getOptionValue(optKs)), unlockProvider);
    }

    private static KeyringStore requireKeyring(CommandLine cmd, Option optKs, KeyringUnlockProvider unlockProvider)
            throws IOException, ParseException, GeneralSecurityException {
        if (!cmd.hasOption(optKs)) {
            throw new ParseException("--keyring <file> is required when aliases are used");
        }
        return KeyringUnlocks.open(Paths.get(cmd.getOptionValue(optKs)), unlockProvider);
    }
}
