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
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.CatalogSelector;
import zeroecho.core.KeyUsage;
import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.builders.alg.ChaChaDataContentBuilder;
import zeroecho.sdk.builders.alg.KemDataContentBuilder;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.builders.core.PlainFileBuilder;
import zeroecho.sdk.content.api.DataContent;

/**
 * Command-line utility that performs hybrid file encryption and decryption
 * using a KEM envelope and an AES or ChaCha payload.
 *
 * <h2>Overview</h2> This tool encapsulates a symmetric key with a selected KEM
 * (post-quantum friendly) and then applies a symmetric cipher to the payload.
 * The symmetric stage is configured on {@code KemDataContentBuilder} and
 * supports AES (GCM/CTR/CBC) and ChaCha (AEAD or stream) including AAD,
 * IV/nonce, counters, and an optional compact header. Keys are loaded from
 * {@code KeyringStore} by alias. Use {@code --list-kems} to discover valid KEM
 * identifiers.
 *
 * <h2>Examples</h2> <pre>{@code
 * # List available KEM identifiers
 * ZeroEcho -E --list-kems
 *
 * # Encrypt with Kyber768 + AES-GCM (128-bit tag), writing a header
 * ZeroEcho -E --encrypt in.bin -o out.bin --keyring keys.txt --pub alice-pub \
 *   --kem ML-KEM --hkdf 5a45524f --key-bytes 32 --max-kem-ct 65536 \
 *   --aes --aes-cipher gcm --aes-tag-bits 128 --aad DEADBEEF --header
 *
 * # Decrypt with the corresponding private key
 * ZeroEcho -E --decrypt out.bin -o plain.bin --keyring keys.txt --priv alice-priv \
 *   --kem ML-KEM --aes --aes-cipher gcm --aes-tag-bits 128 --header
 *
 * # Encrypt with ChaCha20-Poly1305 (AEAD) and header
 * ZeroEcho -E --encrypt in.bin -o out.cc20p.bin --keyring keys.txt --pub alice-pub \
 *   --kem ML-KEM --chacha --chacha-nonce 00112233445566778899AABB \
 *   --aad 01020304 --header
 *
 * # Encrypt with ChaCha20 stream mode and explicit counters
 * ZeroEcho -E --encrypt in.bin -o out.cc20.bin --keyring keys.txt --pub alice-pub \
 *   --kem ML-KEM --chacha --chacha-nonce 00112233445566778899AABB \
 *   --chacha-initial 1 --chacha-counter 00000007
 * }</pre>
 */
public final class Kem { // NOPMD
    private static final Logger LOG = Logger.getLogger(Kem.class.getName());

    // ---------------------------------------------------------------------
    // CLI option constants
    // ---------------------------------------------------------------------

    /** Encrypt mode: -e|--encrypt &lt;input&gt; */
    public static final Option OPT_ENCRYPT = Option.builder("e").longOpt("encrypt").hasArg().argName("input")
            .desc("Encrypt the input file").get();

    /** Decrypt mode: -d|--decrypt &lt;input&gt; */
    public static final Option OPT_DECRYPT = Option.builder("d").longOpt("decrypt").hasArg().argName("input")
            .desc("Decrypt the input file").get();

    /** Output path: -o|--output &lt;file&gt; */
    public static final Option OPT_OUTPUT = Option.builder("o").longOpt("output").hasArg().argName("file")
            .desc("Output file path (default: &lt;input&gt;.enc for encrypt, &lt;input&gt;.dec for decrypt)").get();

    /** Keyring path: -K|--keyring &lt;file&gt; */
    public static final Option OPT_KEYRING = Option.builder("K").longOpt("keyring").hasArg().argName("file")
            .desc("Path to KeyringStore file").get();

    /** Recipient public alias (encrypt): --pub &lt;alias&gt; */
    public static final Option OPT_PUB = Option.builder().longOpt("pub").hasArg().argName("alias")
            .desc("Recipient public key alias (encryption)").get();

    /** Recipient private alias (decrypt): --priv &lt;alias&gt; */
    public static final Option OPT_PRIV = Option.builder().longOpt("priv").hasArg().argName("alias")
            .desc("Recipient private key alias (decryption)").get();

    /** KEM id: --kem &lt;id&gt; */
    public static final Option OPT_KEM = Option.builder().longOpt("kem").hasArg().argName("id")
            .desc("KEM algorithm id (see --list-kems)").get();

    /** Discovery: --list-kems */
    public static final Option OPT_LIST_KEMS = Option.builder().longOpt("list-kems")
            .desc("List KEM algorithms that support ENCAPSULATE and DECAPSULATE and exit").get();

    /** Payload switch: --aes */
    public static final Option OPT_AES = Option.builder().longOpt("aes")
            .desc("Use AES payload (select mode via --aes-cipher)").get();

    /** Payload switch: --chacha */
    public static final Option OPT_CHACHA = Option.builder().longOpt("chacha")
            .desc("Use ChaCha payload (AEAD if --aad is provided, otherwise stream)").get();

    /** AAD (hex): --aad &lt;hex&gt; */
    public static final Option OPT_AAD = Option.builder().longOpt("aad").hasArg().argName("hex")
            .desc("Additional Authenticated Data (hex)").get();

    /** Header toggle: --header */
    public static final Option OPT_HEADER = Option.builder().longOpt("header")
            .desc("Write/read a compact symmetric header (IV/AAD/params) when supported").get();

    /** HKDF: --hkdf [infoHex] */
    public static final Option OPT_HKDF = Option.builder().longOpt("hkdf").optionalArg(true).hasArg().argName("infoHex")
            .desc("Use HKDF-SHA256 for KEM secret; optional info as hex (default internal info)").get();

    /** Direct secret: --direct */
    public static final Option OPT_DIRECT = Option.builder().longOpt("direct")
            .desc("Use the raw KEM shared secret directly (disable HKDF)").get();

    /** Derived key bytes: --key-bytes &lt;int&gt; */
    public static final Option OPT_KEY_BYTES = Option.builder().longOpt("key-bytes").hasArg().argName("int")
            .type(Number.class).desc("Derived symmetric key length in bytes (default 32)").get();

    /** Max KEM ciphertext len: --max-kem-ct &lt;int&gt; */
    public static final Option OPT_MAX_KEM_CT = Option.builder().longOpt("max-kem-ct").hasArg().argName("int")
            .type(Number.class).desc("Maximum accepted KEM ciphertext length in bytes (default 65536)").get();

    /** AES mode: --aes-cipher gcm|ctr|cbc */
    public static final Option OPT_AES_CIPHER = Option.builder().longOpt("aes-cipher").hasArg().argName("gcm|ctr|cbc")
            .desc("AES cipher variant for payload (default gcm)").get();

    /** AES IV: --aes-iv &lt;hex&gt; */
    public static final Option OPT_AES_IV = Option.builder().longOpt("aes-iv").hasArg().argName("hex")
            .desc("AES decryption IV/nonce (hex; rejected for encryption)").get();

    /** AES tag bits: --aes-tag-bits &lt;int&gt; */
    public static final Option OPT_AES_TAG_BITS = Option.builder().longOpt("aes-tag-bits").hasArg().argName("int")
            .type(Number.class).desc("AES-GCM authentication tag length in bits (default 128)").get();

    /** ChaCha nonce: --chacha-nonce &lt;hex&gt; */
    public static final Option OPT_CHACHA_NONCE = Option.builder().longOpt("chacha-nonce").hasArg().argName("hex")
            .desc("ChaCha decryption nonce (hex, usually 12 bytes; rejected for encryption)").get();

    /** ChaCha counter value: --chacha-counter &lt;int&gt; */
    public static final Option OPT_CHACHA_COUNTER = Option.builder().longOpt("chacha-counter").hasArg().argName("int")
            .type(Number.class).desc("ChaCha counter value for stream mode (integer)").get();

    /** ChaCha initial counter: --chacha-initial &lt;int&gt; */
    public static final Option OPT_CHACHA_INITIAL = Option.builder().longOpt("chacha-initial").hasArg().argName("int")
            .type(Number.class).desc("ChaCha initial counter (integer)").get();

    private Kem() {
        // no instances
    }

    public static int main(String[] args, Options opts) throws ParseException, IOException, GeneralSecurityException { // NOPMD
        ZeroEchoSession session = new ZeroEchoSession();
        defineOptions(opts);
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(opts, args);

        // Fast path: listing does not require any other arguments (keyring, mode, etc.)
        if (cmd.hasOption(OPT_LIST_KEMS.getLongOpt())) {
            listKems();
            return 0;
        }

        // Validate mode
        boolean encrypt = cmd.hasOption(OPT_ENCRYPT.getLongOpt()) || cmd.hasOption(OPT_ENCRYPT.getOpt());
        boolean decrypt = cmd.hasOption(OPT_DECRYPT.getLongOpt()) || cmd.hasOption(OPT_DECRYPT.getOpt());
        if (encrypt == decrypt) {
            throw new ParseException("Choose exactly one of --encrypt or --decrypt");
        }

        // Validate payload selection
        boolean wantAes = cmd.hasOption(OPT_AES.getLongOpt());
        boolean wantChaCha = cmd.hasOption(OPT_CHACHA.getLongOpt());
        if (wantAes == wantChaCha) {
            throw new ParseException("Choose exactly one payload cipher: --aes or --chacha");
        }

        // Required arguments for actual work
        require(cmd, OPT_KEM, "Missing required option: --kem");
        require(cmd, OPT_KEYRING, "Missing required option: --keyring");

        final String input = encrypt ? cmd.getOptionValue(OPT_ENCRYPT) : cmd.getOptionValue(OPT_DECRYPT);
        if (input == null || input.isBlank()) {
            throw new ParseException("Missing input file for the selected mode");
        }

        final Path output = Path.of(cmd.getOptionValue(OPT_OUTPUT.getLongOpt(), input + (encrypt ? ".enc" : ".dec")));

        final String kemId = cmd.getOptionValue(OPT_KEM.getLongOpt());
        final Path keyringPath = Path.of(cmd.getOptionValue(OPT_KEYRING.getLongOpt()));
        final KeyringStore keyring = KeyringStore.load(session, keyringPath);

        // Configure KEM envelope
        KemDataContentBuilder kem = KemDataContentBuilder.builder(session).kem(kemId);
        if (cmd.hasOption(OPT_DIRECT.getLongOpt())) {
            kem = kem.directSecret();
        } else {
            byte[] info = parseOptionalHex(cmd, OPT_HKDF, "ZeroEcho-KEM".getBytes());
            kem = kem.hkdfSha256(info);
        }
        // typed numeric options
        Integer keyBytes = parsedIntOpt(cmd, OPT_KEY_BYTES);
        if (keyBytes != null) {
            kem = kem.derivedKeyBytes(keyBytes);
        }
        Integer maxKemCt = parsedIntOpt(cmd, OPT_MAX_KEM_CT);
        if (maxKemCt != null) {
            kem = kem.maxKemCiphertextLen(maxKemCt);
        }

        // Common symmetric knobs
        final byte[] aad = parseHexOpt(cmd, OPT_AAD);
        final boolean wantHeader = cmd.hasOption(OPT_HEADER.getLongOpt());

        // AES payload
        if (wantAes) {
            String mode = cmd.getOptionValue(OPT_AES_CIPHER.getLongOpt(), "gcm").toLowerCase(Locale.ROOT);
            AesDataContentBuilder aes = AesDataContentBuilder.builder(session);
            switch (mode) {
                case "gcm" -> {
                    Integer tagBitsOpt = parsedIntOpt(cmd, OPT_AES_TAG_BITS);
                    int tagBits = tagBitsOpt == null ? 128 : tagBitsOpt;

                    aes = aes.modeGcm(tagBits);
                }
                case "ctr" -> aes = aes.modeCtr();
                case "cbc" -> aes = aes.modeCbcPkcs5();
                default -> throw new ParseException("Unsupported --aes-cipher: " + mode);
            }
            byte[] iv = parseHexOpt(cmd, OPT_AES_IV);
            if (iv != null) {
                aes = aes.withDecryptionIv(iv);
            }
            if (aad != null && aad.length > 0) {
                aes = aes.withAad(aad);
            }
            if (wantHeader) {
                aes = aes.withHeader();
            }
            kem = kem.withAes(aes);
        }

        // ChaCha payload
        if (wantChaCha) {
            ChaChaDataContentBuilder cc = ChaChaDataContentBuilder.builder(session);
            byte[] nonce = parseHexOpt(cmd, OPT_CHACHA_NONCE);
            if (nonce != null) {
                cc = cc.withDecryptionNonce(nonce);
            }
            // counter is an integer, not bytes; use typed parsed option
            Integer counter = parsedIntOpt(cmd, OPT_CHACHA_COUNTER);
            if (counter != null) {
                cc = cc.withCounter(counter);
            }
            Integer initial = parsedIntOpt(cmd, OPT_CHACHA_INITIAL);
            if (initial != null) {
                cc = cc.initialCounter(initial);
            }
            if (aad != null && aad.length > 0) {
                cc = cc.withAad(aad); // selects AEAD
            }
            if (wantHeader) {
                cc = cc.withHeader();
            }
            kem = kem.withChaCha(cc);
        }

        // Pipeline: source -> kem payload stage
        DataContent chain;
        if (encrypt) {
            String alias = require(cmd, OPT_PUB, "Missing --pub for encryption");
            PublicKey recipient = keyring.getPublic(alias);
            chain = DataContentChainBuilder.encrypt()
                    .add(PlainFileBuilder.builder().url(Path.of(input).toUri().toURL()))
                    .add(kem.recipientPublic(recipient)).build();
        } else {
            String alias = require(cmd, OPT_PRIV, "Missing --priv for decryption");
            PrivateKey recipient = keyring.getPrivate(alias);
            chain = DataContentChainBuilder.decrypt()
                    .add(PlainFileBuilder.builder().url(Path.of(input).toUri().toURL()))
                    .add(kem.recipientPrivate(recipient)).build();
        }

        try (InputStream in = chain.getStream(); OutputStream out = Files.newOutputStream(output)) {
            in.transferTo(out);
        } catch (IOException ex) {
            if (LOG.isLoggable(Level.SEVERE)) {
                LOG.log(Level.SEVERE, "I/O error", ex);
            }
            return 1;
        }
        return 0;
    }

    /**
     * Builds the CLI option set.
     *
     * @return populated {@link Options}
     */
    private static Options defineOptions(Options opts) {
        // Mode group (not required up-front; validated after --list-kems short-circuit)
        OptionGroup mode = new OptionGroup();
        mode.addOption(OPT_ENCRYPT);
        mode.addOption(OPT_DECRYPT);
        opts.addOptionGroup(mode);

        // Payload selection group
        OptionGroup payload = new OptionGroup();
        payload.addOption(OPT_AES);
        payload.addOption(OPT_CHACHA);
        opts.addOptionGroup(payload);

        // General and catalog options
        opts.addOption(OPT_OUTPUT);
        opts.addOption(OPT_KEYRING);
        opts.addOption(OPT_PUB);
        opts.addOption(OPT_PRIV);
        opts.addOption(OPT_KEM);
        opts.addOption(OPT_LIST_KEMS);

        // Symmetric common knobs
        opts.addOption(OPT_AAD);
        opts.addOption(OPT_HEADER);

        // AES knobs
        opts.addOption(OPT_AES_CIPHER);
        opts.addOption(OPT_AES_IV);
        opts.addOption(OPT_AES_TAG_BITS);

        // ChaCha knobs
        opts.addOption(OPT_CHACHA_NONCE);
        opts.addOption(OPT_CHACHA_COUNTER);
        opts.addOption(OPT_CHACHA_INITIAL);

        // KEM knobs
        opts.addOption(OPT_HKDF);
        opts.addOption(OPT_DIRECT);
        opts.addOption(OPT_KEY_BYTES);
        opts.addOption(OPT_MAX_KEM_CT);

        return opts;
    }

    /**
     * Prints KEM algorithm identifiers that belong to family {@code KEM} and
     * support both {@code ENCAPSULATE} and {@code DECAPSULATE}.
     */
    private static void listKems() {
        List<String> ids = CatalogSelector.selectByFamilyAndRoles(AlgorithmFamily.KEM,
                EnumSet.of(KeyUsage.ENCAPSULATE, KeyUsage.DECAPSULATE));
        if (ids.isEmpty()) {
            System.out.println("(no KEM algorithms found)");
            return;
        }
        for (String id : ids) {
            System.out.println(id);
        }
    }

    /**
     * Returns the non-empty value of the given option or throws a
     * {@link ParseException}.
     *
     * @param cmd     parsed command line
     * @param opt     option definition
     * @param message error message when missing
     * @return option value string
     * @throws ParseException if missing or empty
     */
    private static String require(CommandLine cmd, Option opt, String message) throws ParseException {
        String v = cmd.getOptionValue(opt.getLongOpt());
        if (v == null || v.isBlank()) {
            throw new ParseException(message);
        }
        return v;
    }

    /**
     * Parses an optional integer using Commons CLI typed parsing.
     *
     * <p>
     * Requires the {@link Option} to declare {@code .type(Number.class)}. If the
     * option is present and convertible, returns its {@code intValue()}, otherwise
     * {@code null}.
     * </p>
     *
     * @param cmd parsed command line
     * @param opt the option to parse
     * @return {@code Integer} value or {@code null} if not present
     * @throws ParseException if present but not a valid integer
     */
    private static Integer parsedIntOpt(CommandLine cmd, Option opt) throws ParseException {
        // getParsedOptionValue returns null if absent; otherwise a Number if
        // .type(Number.class) is set
        Object v = cmd.getParsedOptionValue(opt.getLongOpt());
        if (v == null) {
            return null;
        }
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        // Fallback: attempt manual parse when type not respected by the parser
        String s = cmd.getOptionValue(opt.getLongOpt());
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return Integer.valueOf(s);
        } catch (NumberFormatException e) {
            throw new ParseException("Invalid integer for --" + opt.getLongOpt() + ": " + s); // NOPMD
        }
    }

    /**
     * Parses an optional hex string for the given option.
     *
     * @param cmd parsed command line
     * @param opt option definition
     * @return byte array or {@code null} if absent
     * @throws ParseException if the hex value is invalid
     */
    private static byte[] parseHexOpt(CommandLine cmd, Option opt) throws ParseException {
        if (!cmd.hasOption(opt.getLongOpt())) {
            return null; // NOPMD
        }
        String v = cmd.getOptionValue(opt.getLongOpt());
        if (v == null || v.isBlank()) {
            return null; // NOPMD
        }
        try {
            return HexFormat.of().parseHex(v);
        } catch (IllegalArgumentException e) {
            throw new ParseException("Invalid hex for --" + opt.getLongOpt() + ": " + e.getMessage()); // NOPMD
        }
    }

    /**
     * Returns the hex-decoded bytes from an optional value; if the option is
     * absent, returns the provided default.
     *
     * @param cmd parsed command line
     * @param opt option definition
     * @param def default bytes to use when option is not present
     * @return decoded bytes or default when absent
     * @throws ParseException if the option is present but the value is not valid
     *                        hex
     */
    private static byte[] parseOptionalHex(CommandLine cmd, Option opt, byte[] def) throws ParseException {
        if (!cmd.hasOption(opt.getLongOpt())) {
            return def;
        }
        String v = cmd.getOptionValue(opt.getLongOpt());
        if (v == null || v.isBlank()) {
            return def;
        }
        try {
            return HexFormat.of().parseHex(v);
        } catch (IllegalArgumentException e) {
            throw new ParseException("Invalid hex for --" + opt.getLongOpt() + ": " + e.getMessage()); // NOPMD
        }
    }
}
