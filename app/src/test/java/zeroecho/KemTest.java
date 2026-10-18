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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.apache.commons.cli.Options;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * CLI-level tests for KEMAes that:
 * <ul>
 * <li>Verify {@code --list-kems} runs without a keyring.</li>
 * <li>Iterate over <em>all</em> available KEM ids discovered via
 * {@code --list-kems} and for each id perform hybrid round-trips:
 * <ul>
 * <li>AES-GCM with header and AAD,</li>
 * <li>ChaCha20-Poly1305 with header and AAD.</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <p>
 * The tests:
 * <ul>
 * <li>use the real KeyStore format by calling {@link KeyStoreManagement} to
 * generate a keypair,</li>
 * <li>pass the resulting aliases into
 * {@code KEMAes.main(String[], Options)},</li>
 * <li>print the method name and parameters first, progress lines prefixed by
 * {@code "..."},</li>
 * <li>end with {@code "...ok"} on success.</li>
 * </ul>
 */
public class KemTest {

    /** All temporary files live here and are auto-cleaned by JUnit. */
    @TempDir
    Path tmp;

    private PrintStream savedOut;

    @BeforeAll
    static void bootBouncyCastle() {
        System.out.println("bootBouncyCastle()");
        // The project initializes BC explicitly for KEM implementations.
        BouncyCastleActivator.init();
        System.out.println("bootBouncyCastle...ok");
    }

    @AfterEach
    void restoreStdout() {
        if (savedOut != null) {
            System.setOut(savedOut);
            savedOut = null;
        }
    }

    /**
     * Confirms that {@code --list-kems} short-circuits and exits 0 without
     * requiring a keyring.
     */
    @Test
    void listKems_runs() throws Exception {
        System.out.println("listKems_runs()");
        Options opts = new Options();
        String[] args = { "--list-kems" };

        System.out.println("...invoking: " + Arrays.toString(args));
        int rc = Kem.main(args, opts);
        assertEquals(0, rc, "... expected exit code 0");
        System.out.println("...ok");
    }

    /**
     * Runs hybrid round-trips for <em>every</em> KEM listed by {@code --list-kems}:
     * <ol>
     * <li>Generate a real KeyStore with a fresh keypair for the KEM,</li>
     * <li>Encrypt+decrypt using AES-GCM (header+AAD),</li>
     * <li>Encrypt+decrypt using ChaCha20-Poly1305 (header+AAD).</li>
     * </ol>
     *
     * <p>
     * If any KEM fails at any step, the test records it and continues. At the end,
     * it fails with a concise summary of all failures.
     * </p>
     */
    @Test
    void allKems_encryptDecrypt_aesAndChacha() throws Exception {
        final String method = "allKems_encryptDecrypt_aesAndChacha()";
        final int aesSize = 8192;
        final int chachaSize = 4096;
        final int gcmTagBits = 128;
        final String aadAes = "A1B2C3";
        final String aadChaCha = "DEADBEEF";

        System.out.println(method);
        System.out.println("...params: aesSize=" + aesSize + " chachaSize=" + chachaSize + " gcmTagBits=" + gcmTagBits
                + " aesAAD=" + aadAes + " chachaAAD=" + aadChaCha);

        // Discover KEM ids via the CLI (ensures we use exactly the ids users will see).
        List<String> kemIds = listKemsViaCli();
        System.out.println("...discovered " + kemIds.size() + " KEM ids");
        if (kemIds.isEmpty()) {
            throw new GeneralSecurityException("No KEM algorithms reported by --list-kems");
        }

        List<String> failures = new ArrayList<>();

        for (String kemId : kemIds) {
            System.out.println("...KEM " + kemId + " begin");

            try {
                // Real keystore for this KEM
                Path ring = tmp.resolve("ring-" + kemId.replace('/', '_') + ".txt");
                KeyAliases aliases = generateKemIntoKeyStore(ring, kemId, "alias-" + shortId(kemId));

                // Sanity: re-open to ensure the file is valid
                try (zeroecho.core.storage.KeyringPassword password = TestKeyringUnlocks.provider().acquire();
                        KeyringStore ks = KeyringStore.open(ring, password)) {
                    if (!(ks.contains(aliases.pub) && ks.contains(aliases.prv))) {
                        throw new IllegalStateException("Keyring does not contain expected aliases for " + kemId);
                    }
                }

                // AES-GCM round-trip
                {
                    byte[] content = randomBytes(aesSize);
                    Path plain = tmp.resolve("plain-aes-" + shortId(kemId) + ".bin");
                    Path enc = tmp.resolve("enc-aes-" + shortId(kemId) + ".bin");
                    Path dec = tmp.resolve("dec-aes-" + shortId(kemId) + ".bin");
                    Files.write(plain, content);
                    System.out.println("...[" + kemId + "] AES encrypt");
                    int e = Kem.main(new String[] { "--encrypt", plain.toString(), "--output", enc.toString(),
                            "--keyring", ring.toString(), "--pub", aliases.pub, "--kem", kemId, "--aes", "--aes-cipher",
                            "gcm", "--aes-tag-bits", Integer.toString(gcmTagBits), "--header", "--aad", aadAes },
                            new Options(), TestKeyringUnlocks.provider());
                    if (e != 0) {
                        throw new IllegalStateException("AES encrypt rc=" + e);
                    }
                    System.out.println("...[" + kemId + "] AES decrypt");
                    int d = Kem.main(new String[] { "--decrypt", enc.toString(), "--output", dec.toString(),
                            "--keyring", ring.toString(), "--priv", aliases.prv, "--kem", kemId, "--aes",
                            "--aes-cipher", "gcm", "--aes-tag-bits", Integer.toString(gcmTagBits), "--header", "--aad",
                            aadAes }, new Options(), TestKeyringUnlocks.provider());
                    if (d != 0) {
                        throw new IllegalStateException("AES decrypt rc=" + d);
                    }
                    byte[] back = Files.readAllBytes(dec);
                    assertArrayEquals(content, back, "[" + kemId + "] AES-GCM round-trip mismatch");
                    System.out.println("...[" + kemId + "] AES round-trip ok");
                }

                // ChaCha20-Poly1305 round-trip (AEAD implied by AAD)
                {
                    byte[] content = randomBytes(chachaSize);
                    Path plain = tmp.resolve("plain-cc20-" + shortId(kemId) + ".bin");
                    Path enc = tmp.resolve("enc-cc20-" + shortId(kemId) + ".bin");
                    Path dec = tmp.resolve("dec-cc20-" + shortId(kemId) + ".bin");
                    Files.write(plain, content);
                    System.out.println("...[" + kemId + "] ChaCha encrypt");
                    int e = Kem.main(new String[] { "--encrypt", plain.toString(), "--output", enc.toString(),
                            "--keyring", ring.toString(), "--pub", aliases.pub, "--kem", kemId, "--chacha", "--aad",
                            aadChaCha, "--header" }, new Options(), TestKeyringUnlocks.provider());
                    if (e != 0) {
                        throw new IllegalStateException("ChaCha encrypt rc=" + e);
                    }
                    System.out.println("...[" + kemId + "] ChaCha decrypt");
                    int d = Kem.main(new String[] { "--decrypt", enc.toString(), "--output", dec.toString(),
                            "--keyring", ring.toString(), "--priv", aliases.prv, "--kem", kemId, "--chacha", "--aad",
                            aadChaCha, "--header" }, new Options(), TestKeyringUnlocks.provider());
                    if (d != 0) {
                        throw new IllegalStateException("ChaCha decrypt rc=" + d);
                    }
                    byte[] back = Files.readAllBytes(dec);
                    assertArrayEquals(content, back, "[" + kemId + "] ChaCha20-Poly1305 round-trip mismatch");
                    System.out.println("...[" + kemId + "] ChaCha round-trip ok");
                }

                System.out.println("...KEM " + kemId + " ok");
            } catch (Throwable t) {
                System.out.println("...KEM " + kemId + " FAILED: " + t);
                failures.add(kemId + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }

        if (!failures.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            sb.append("Some KEM(s) failed:\n");
            for (String f : failures) {
                sb.append("  - ").append(f).append('\n');
            }
            throw new AssertionError(sb.toString());
        }

        System.out.println("...ok");
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    /**
     * Calls the CLI entrypoint with {@code --list-kems} and parses stdout lines to
     * a list of ids.
     */
    private List<String> listKemsViaCli() throws Exception {
        savedOut = System.out;
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        System.setOut(new PrintStream(sink, true, StandardCharsets.UTF_8));
        try {
            int rc = Kem.main(new String[] { "--list-kems" }, new Options(), TestKeyringUnlocks.provider());
            if (rc != 0) {
                throw new IllegalStateException("--list-kems rc=" + rc);
            }
        } finally {
            System.setOut(savedOut);
            savedOut = null;
        }
        String out = sink.toString(StandardCharsets.UTF_8);
        List<String> ids = new ArrayList<>();
        for (String line : out.split("\\R")) {
            String id = line.trim();
            if (!id.isEmpty() && !id.startsWith("(")) {
                ids.add(id);
            }
        }
        return ids;
    }

    /**
     * Generates a KEM keypair using the real KeyStoreManagement CLI and returns the
     * public/private aliases. The CLI stores aliases as {@code <alias>.pub} and
     * {@code <alias>.prv}.
     */
    private static KeyAliases generateKemIntoKeyStore(Path ring, String kemId, String baseAlias) throws Exception {
        String[] genArgs = { "--keystore", ring.toString(), "--generate", "--alg", kemId, "--alias", baseAlias,
                "--kind", "asym" };
        System.out.println("...KeyStoreManagement generate: " + Arrays.toString(genArgs));
        int rc = KeyStoreManagement.main(genArgs, new Options(), TestKeyringUnlocks.provider());
        if (rc != 0) {
            throw new GeneralSecurityException("KeyStoreManagement failed with rc=" + rc + " for " + kemId);
        }
        return new KeyAliases(baseAlias + ".pub", baseAlias + ".prv");
    }

    private static String shortId(String kemId) {
        String s = kemId.replaceAll("[^A-Za-z0-9]+", "");
        if (s.length() > 16) {
            s = s.substring(0, 16);
        }
        return s;
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        new Random(0x5EEDC0DEL).nextBytes(b);
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
