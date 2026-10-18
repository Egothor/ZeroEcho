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
package zeroecho;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.cli.Options;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * CLI-level tests for the Tag subcommand (signature + digest).
 *
 * <h2>Scope</h2>
 * <ul>
 * <li>Signature produce+verify with Ed25519 via a real keyring file,</li>
 * <li>Signature verify failure appends marker text and returns rc=1,</li>
 * <li>Digest produce+verify (SHA-256) round trip,</li>
 * <li>Digest verify failure appends marker text and returns rc=1,</li>
 * <li>Digest round trip over STDIN/STDOUT.</li>
 * </ul>
 */
public class TagTest {

    @TempDir
    Path tmp;

    private PrintStream savedOut;
    private PrintStream savedErr;
    private java.io.InputStream savedIn;

    @BeforeAll
    static void bootBouncyCastle() {
        BouncyCastleActivator.init();
    }

    @AfterEach
    void restoreStd() {
        if (savedOut != null) {
            System.setOut(savedOut);
            savedOut = null;
        }
        if (savedErr != null) {
            System.setErr(savedErr);
            savedErr = null;
        }
        if (savedIn != null) {
            System.setIn(savedIn);
            savedIn = null;
        }
    }

    // ---------- boilerplate logging ----------
    private static void logBegin(Object... params) {
        String thisClass = TagTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = TagTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
        System.out.println();
    }

    /** Ed25519 signature round-trip using files. */
    @Test
    void signature_ed25519_roundTrip_files_ok() throws Exception {
        logBegin("signature_ed25519_roundTrip_files_ok");

        Path ring = tmp.resolve("ring-ed25519.txt");
        KeyAliases ed = generateIntoKeyStore(ring, "Ed25519", "ed");
        // sanity
        try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                KeyringStore ks = KeyringStore.open(ring, password)) {
            assertTrue(ks.contains(ed.pub) && ks.contains(ed.prv), "missing expected aliases");
        }

        byte[] pt = randomBytes(4096);
        Path plain = tmp.resolve("plain.bin");
        Path signed = tmp.resolve("signed.bin");
        Path recovered = tmp.resolve("recovered.bin");
        Files.write(plain, pt);

        // produce
        String[] produce = { "--type", "signature", "--mode", "produce", "--alg", "Ed25519", "--ks", ring.toString(),
                "--priv", ed.prv, "--in", plain.toString(), "--out", signed.toString() };
        assertEquals(0, Tag.main(produce, new Options(), TestKeyringUnlocks.provider()), "produce rc");

        // verify (match)
        String[] verify = { "--type", "signature", "--mode", "verify", "--alg", "Ed25519", "--ks", ring.toString(),
                "--pub", ed.pub, "--in", signed.toString(), "--out", recovered.toString() };
        assertEquals(0, Tag.main(verify, new Options(), TestKeyringUnlocks.provider()), "verify rc");

        assertArrayEquals(pt, Files.readAllBytes(recovered), "round-trip mismatch");

        logEnd();
    }

    @Test
    void signature_verify_mismatch_throws_and_appends_text() throws Exception {
        logBegin("signature_verify_mismatch_throws_and_appends_text");

        Path ring = tmp.resolve("ring-ed25519-neg.txt");
        KeyAliases ed = generateIntoKeyStore(ring, "Ed25519", "ed-neg");

        byte[] pt = randomBytes(1024);
        Path plain = tmp.resolve("plain-neg.bin");
        Path signed = tmp.resolve("signed-neg.bin");
        Path out = tmp.resolve("out-neg.bin");
        Files.write(plain, pt);

        // produce
        assertEquals(0,
                Tag.main(new String[] { "--type", "signature", "--mode", "produce", "--alg", "Ed25519", "--ks",
                        ring.toString(), "--priv", ed.prv, "--in", plain.toString(), "--out", signed.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        // corrupt last byte -> break signature
        flipLastByte(signed);

        // verify (mismatch): expect throw + marker appended
        assertEquals(1,
                Tag.main(
                        new String[] { "--type", "signature", "--mode", "verify", "--alg", "Ed25519", "--ks",
                                ring.toString(), "--pub", ed.pub, "--in", signed.toString(), "--out", out.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        assertTrue(Files.notExists(out, LinkOption.NOFOLLOW_LINKS));

        logEnd();
    }

    /** SHA-256 digest round-trip using files. */
    @Test
    void digest_sha256_roundTrip_files_ok() throws Exception {
        logBegin("digest_sha256_roundTrip_files_ok");

        byte[] pt = randomBytes(5000);
        Path plain = tmp.resolve("plain-d.bin");
        Path tagged = tmp.resolve("tagged-d.bin");
        Path recovered = tmp.resolve("recovered-d.bin");
        Files.write(plain, pt);

        // produce
        assertEquals(0,
                Tag.main(
                        new String[] { "--type", "digest", "--mode", "produce", "--alg", "SHA-256", "--in",
                                plain.toString(), "--out", tagged.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        // verify (match)
        assertEquals(0,
                Tag.main(
                        new String[] { "--type", "digest", "--mode", "verify", "--alg", "SHA-256", "--in",
                                tagged.toString(), "--out", recovered.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        assertArrayEquals(pt, Files.readAllBytes(recovered), "digest round-trip mismatch");

        logEnd();
    }

    @Test
    void digest_verify_mismatch_throws_and_appends_text() throws Exception {
        logBegin("digest_verify_mismatch_throws_and_appends_text");

        byte[] pt = randomBytes(2048);
        Path plain = tmp.resolve("plain-d-neg.bin");
        Path tagged = tmp.resolve("tagged-d-neg.bin");
        Path out = tmp.resolve("out-d-neg.bin");
        Files.write(plain, pt);

        // produce
        assertEquals(0,
                Tag.main(
                        new String[] { "--type", "digest", "--mode", "produce", "--alg", "SHA-256", "--in",
                                plain.toString(), "--out", tagged.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        // corrupt last byte -> break digest
        flipLastByte(tagged);

        // verify (mismatch): expect throw + default marker ("digest invalid")
        assertEquals(1,
                Tag.main(
                        new String[] { "--type", "digest", "--mode", "verify", "--alg", "SHA-256", "--in",
                                tagged.toString(), "--out", out.toString() },
                        new Options(), TestKeyringUnlocks.provider()));

        assertTrue(Files.notExists(out, LinkOption.NOFOLLOW_LINKS));

        logEnd();
    }

    /** Digest round trip over STDIN/STDOUT. */
    @Test
    void digest_roundTrip_stdin_stdout_ok() throws Exception {
        logBegin("digest_roundTrip_stdin_stdout_ok");

        byte[] pt = randomBytes(3000);

        // produce (stdin -> stdout)
        savedIn = System.in;
        savedOut = System.out;
        ByteArrayInputStream src = new ByteArrayInputStream(pt);
        ByteArrayOutputStream producedSink = new ByteArrayOutputStream();
        System.setIn(src);
        System.setOut(new PrintStream(producedSink, true, StandardCharsets.UTF_8));

        assertEquals(0, Tag.main(
                new String[] { "--type", "digest", "--mode", "produce", "--alg", "SHA-256", "--in", "-", "--out", "-" },
                new Options(), TestKeyringUnlocks.provider()));

        // save produced bytes
        Path tagged = tmp.resolve("stdio-tagged.bin");
        Files.write(tagged, producedSink.toByteArray());

        // verify (file -> stdout)
        ByteArrayOutputStream verifiedSink = new ByteArrayOutputStream();
        System.setIn(savedIn); // not used in this step
        System.setOut(new PrintStream(verifiedSink, true, StandardCharsets.UTF_8));

        assertEquals(0, Tag.main(new String[] { "--type", "digest", "--mode", "verify", "--alg", "SHA-256", "--in",
                tagged.toString(), "--out", "-" }, new Options(), TestKeyringUnlocks.provider()));

        assertArrayEquals(pt, verifiedSink.toByteArray(), "stdio round-trip mismatch");

        logEnd();
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /** Generates an asymmetric keypair using the real KeyStoreManagement CLI. */
    private static KeyAliases generateIntoKeyStore(Path ring, String algId, String baseAlias) throws Exception {
        String[] genArgs = { "--keystore", ring.toString(), "--generate", "--alg", algId, "--alias", baseAlias,
                "--kind", "asym" };
        int rc = KeyStoreManagement.main(genArgs, new Options(), TestKeyringUnlocks.provider());
        if (rc != 0) {
            throw new GeneralSecurityException("KeyStoreManagement failed with rc=" + rc + " for " + algId);
        }
        return new KeyAliases(baseAlias + ".pub", baseAlias + ".prv");
    }

    private static void flipLastByte(Path file) throws Exception {
        byte[] all = Files.readAllBytes(file);
        if (all.length == 0) {
            throw new IllegalStateException("cannot flip byte in empty file");
        }
        all[all.length - 1] ^= 0xFF;
        Files.write(file, all);
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new Random(0xBADC0FFEL).nextBytes(b);
        return b;
    }

    private static final class KeyAliases {
        final String pub;
        final String prv;

        KeyAliases(String pub, String prv) {
            this.pub = pub;
            this.prv = prv;
        }
    }
}
