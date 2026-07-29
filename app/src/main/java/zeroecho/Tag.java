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

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Locale;
import java.util.Objects;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.help.HelpFormatter;

import zeroecho.core.alg.digest.DigestSpec;
import zeroecho.core.err.VerificationException;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringStore;
import zeroecho.core.tag.TagEngineBuilder;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.content.builtin.PlainFile;

/**
 * CLI entry point for producing and verifying trailer tags based on digital
 * signatures or digests.
 *
 * <h2>Overview</h2> This class wires command line options to content-processing
 * pipelines that either append a tag (produce mode) or validate and strip a tag
 * (verify mode). The tag can be a digital signature or a message digest,
 * depending on the selected type and algorithm.
 *
 * <h2>Usage</h2> <pre>{@code
 * ZeroEcho -T --type signature --mode produce --alg Ed25519 \
 *         --ks keys.txt --priv my-signing-key --in file.bin --out file.tagged
 *
 * ZeroEcho -T --type signature --mode verify --alg Ed25519 \
 *         --ks keys.txt --pub my-verify-key --in file.tagged --out file.bin
 *
 * ZeroEcho -T --type digest --mode produce --alg SHA-256 \
 *         --in file.bin --out file.tagged
 *
 * ZeroEcho -T --type digest --mode verify --alg SHA-256 \
 *         --in file.tagged --out file.bin
 *
 * # Use "-" to read from STDIN or write to STDOUT:
 * ZeroEcho -T --type digest --mode produce --alg SHA-256 --in - --out -
 * }</pre>
 *
 * <h2>Notes</h2> The signature mode requires a keyring file. In produce mode a
 * private key is required, while in verify mode a public key is required.
 * Digest mode does not require keys. A non-zero exit status indicates a
 * verification mismatch or input errors.
 */
public final class Tag { // NOPMD
    /**
     * Conventional marker for standard input or output stream.
     */
    private final static String STD_IN_OUT = "-";

    // ---- All options as constants
    private static final Option TYPE_OPT = Option.builder().longOpt("type").hasArg().argName("signature|digest")
            .desc("tag primitive type").get();

    private static final Option MODE_OPT = Option.builder().longOpt("mode").hasArg().argName("produce|verify")
            .desc("operation mode").get();

    private static final Option ALG_OPT = Option.builder().longOpt("alg").hasArg().argName("id")
            .desc("algorithm id (signature: Ed25519/Ed448/ECDSA/RSA; digest: SHA-256/.../SHAKE256:N)").get();

    private static final Option KS_OPT = Option.builder().longOpt("ks").hasArg().argName("file")
            .desc("keyring file (required for signature)").get();

    private static final Option PRIV_OPT = Option.builder().longOpt("priv").hasArg().argName("alias")
            .desc("private key alias (signature + produce)").get();

    private static final Option PUB_OPT = Option.builder().longOpt("pub").hasArg().argName("alias")
            .desc("public key alias (signature + verify)").get();

    private static final Option IN_OPT = Option.builder().longOpt("in").hasArg().argName("file|-")
            .desc("input file or - for STDIN").get();

    private static final Option OUT_OPT = Option.builder().longOpt("out").hasArg().argName("file|-")
            .desc("output file or - for STDOUT").get();

    // ---- Allowed values and defaults (no enums)
    private static final String TYPE_SIGNATURE = "signature";
    private static final String TYPE_DIGEST = "digest";
    private static final String MODE_PRODUCE = "produce";
    private static final String MODE_VERIFY = "verify";

    private Tag() {
    }

    /**
     * Parses CLI arguments and executes produce or verify operation for signature
     * or digest tags.
     *
     * <h4>Behavior</h4> The method validates required options, constructs the
     * appropriate processing pipeline, and streams data from the input to the
     * output while producing or verifying the trailing tag. On verification
     * mismatch, it returns a non-zero exit code and attempts to remove a corrupted
     * output file when applicable.
     *
     * @param args the command line arguments that follow {@code -T}
     * @param root the options container to which this method appends its own
     *             options before parsing
     * @return process exit code: {@code 0} on success, {@code 1} on verification
     *         mismatch or I/O error during verification, {@code 2} on invalid
     *         arguments or unsupported options
     * @throws ParseException           if CLI parsing fails
     * @throws IOException              if an I/O error occurs while reading or
     *                                  writing streams
     * @throws GeneralSecurityException if a cryptographic error occurs during
     *                                  signature or digest processing
     */
    public static int main(String[] args, Options root)
            throws ParseException, IOException, GeneralSecurityException {
        return main(args, root, KeyringUnlocks.console());
    }

    /**
     * Executes the command with an explicit keyring unlock source.
     *
     * @param args command arguments
     * @param root root options
     * @param unlockProvider keyring password provider
     * @return process exit code
     * @throws ParseException if parsing fails
     * @throws IOException if I/O fails
     * @throws GeneralSecurityException if cryptographic processing fails
     */
    public static int main(String[] args, Options root,
            KeyringUnlockProvider unlockProvider)
            throws ParseException, IOException, GeneralSecurityException {
        ZeroEchoSession session = new ZeroEchoSession();
        Options opts = root;
        opts.addOption(TYPE_OPT);
        opts.addOption(MODE_OPT);
        opts.addOption(ALG_OPT);
        opts.addOption(KS_OPT);
        opts.addOption(PRIV_OPT);
        opts.addOption(PUB_OPT);
        opts.addOption(IN_OPT);
        opts.addOption(OUT_OPT);

        CommandLine cli = new DefaultParser().parse(opts, args);

        if (!has(cli, TYPE_OPT) || !has(cli, MODE_OPT) || !has(cli, ALG_OPT) || !has(cli, IN_OPT)
                || !has(cli, OUT_OPT)) {
            HelpFormatter.builder().get().printHelp("zeroecho -T [options]", "", opts, "", false);
            return 2;
        }

        String type = opt(cli, TYPE_OPT).trim().toLowerCase(Locale.ROOT);
        String mode = opt(cli, MODE_OPT).trim().toLowerCase(Locale.ROOT);
        if (!isOneOf(type, TYPE_SIGNATURE, TYPE_DIGEST)) {
            System.err.println("Unsupported --type: " + type);
            return 2;
        }
        if (!isOneOf(mode, MODE_PRODUCE, MODE_VERIFY)) {
            System.err.println("Unsupported --mode: " + mode);
            return 2;
        }

        String alg = opt(cli, ALG_OPT);
        String inPath = opt(cli, IN_OPT);
        String outPath = opt(cli, OUT_OPT);

        PlainContent source = source(inPath);
        boolean produce = MODE_PRODUCE.equals(mode);
        DataContent tail;

        if (TYPE_SIGNATURE.equals(type)) {
            String ksPath = require(cli, KS_OPT, "--ks <file> is required for --type signature");
            try (KeyringStore keyring = KeyringUnlocks.open(Path.of(ksPath), unlockProvider)) {
                ContextSpec spec = VoidSpec.INSTANCE;
                if (produce) {
                    String privAlias = require(cli, PRIV_OPT, "signature produce requires --priv <alias>");
                    PrivateKey priv = keyring.getPrivate(privAlias);
                    tail = new TagTrailerDataContentBuilder<>(
                            TagEngineBuilder.signature(session, alg, priv, spec)).build(true);
                } else {
                    String pubAlias = require(cli, PUB_OPT, "signature verify requires --pub <alias>");
                    PublicKey pub = keyring.getPublic(pubAlias);
                    tail = new TagTrailerDataContentBuilder<>(
                            TagEngineBuilder.signature(session, alg, pub, spec)).build(false);
                }
            }
        } else { // digest
            DigestSpec spec = parseDigest(alg);
            tail = new TagTrailerDataContentBuilder<>(TagEngineBuilder.digest(session, spec)).build(produce);
        }

        tail.setInput(source);

        try (InputStream in = tail.getStream(); OutputStream out = sink(outPath)) {
            in.transferTo(out);
        } catch (IOException verifyFail) {
            System.out.println("ERROR: " + verifyFail.getMessage());
            if (verifyFail.getCause() instanceof VerificationException) {
                try {
                    // remove the file if it is corrupted
                    Files.deleteIfExists(Path.of(outPath));
                } catch (IOException e1) { // NOPMD
                    // ignore any errors
                }
            }
            return 1; // non-zero exit for verify mismatch
        }

        return 0;
    }

    // ---------- helpers ----------

    private static boolean has(CommandLine cli, Option opt) {
        return cli.hasOption(opt.getLongOpt());
    }

    private static String opt(CommandLine cli, Option opt) {
        return cli.getOptionValue(opt.getLongOpt());
    }

    private static String require(CommandLine cli, Option opt, String msg) {
        String v = cli.getOptionValue(opt.getLongOpt());
        if (v == null) {
            throw new IllegalArgumentException(msg);
        }
        return v;
    }

    private static boolean isOneOf(String s, String a, String b) {
        return a.equalsIgnoreCase(s) || b.equalsIgnoreCase(s);
    }

    private static PlainContent source(String path) throws IOException {
        if (STD_IN_OUT.equals(path)) {
            return new StdinContent(System.in);
        }
        return new PlainFile(Path.of(path).toUri().toURL());
    }

    private static OutputStream sink(String path) throws IOException {
        if (STD_IN_OUT.equals(path)) {
            return new NonClosingBufferedOutputStream(System.out, 64 * 1024);
        }
        return new BufferedOutputStream(Files.newOutputStream(Path.of(path)), 64 * 1024);
    }

    private static DigestSpec parseDigest(String s) {
        String u = s.trim().toUpperCase(Locale.ROOT);
        if ("SHA-256".equals(u) || "SHA256".equals(u)) {
            return DigestSpec.sha256();
        }
        if ("SHA-512".equals(u) || "SHA512".equals(u)) {
            return DigestSpec.sha512();
        }
        if ("SHA3-256".equals(u) || "SHA3_256".equals(u)) {
            return DigestSpec.sha3_256();
        }
        if ("SHA3-512".equals(u) || "SHA3_512".equals(u)) {
            return DigestSpec.sha3_512();
        }
        if (u.startsWith("SHAKE128:")) {
            int len = Integer.parseInt(u.substring("SHAKE128:".length()));
            return DigestSpec.shake128(len);
        }
        if (u.startsWith("SHAKE256:")) {
            int len = Integer.parseInt(u.substring("SHAKE256:".length()));
            return DigestSpec.shake256(len);
        }
        throw new IllegalArgumentException("Unsupported digest: " + s);
    }

    /** STDIN wrapper that implements PlainContent. */
    private static final class StdinContent implements PlainContent {
        private final InputStream in;

        private StdinContent(InputStream in) {
            this.in = Objects.requireNonNull(in, "stdin");
        }

        @Override
        public void setInput(DataContent upstream) {
            if (upstream != null) {
                throw new IllegalArgumentException("stdin is a source; no input allowed");
            }
        }

        @Override
        public InputStream getStream() {
            return in;
        }
    }

    /** Buffered stream that never closes the underlying stream (for STDOUT). */
    private static final class NonClosingBufferedOutputStream extends BufferedOutputStream {
        private NonClosingBufferedOutputStream(OutputStream out, int size) {
            super(out, size);
        }

        @Override
        public void close() throws IOException {
            flush();
        } // do not close underlying System.out
    }
}
