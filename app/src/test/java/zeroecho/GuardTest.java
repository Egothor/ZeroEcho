/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.cli.Options;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * CLI-level round-trip tests for the Guard subcommand.
 *
 * <h2>Scope</h2> These tests drive
 * {@link Guard#main(String[], org.apache.commons.cli.Options)} with only the
 * options implemented by Guard. They exercise:
 * <ul>
 * <li>Password-only encryption and decryption,</li>
 * <li>RSA recipients with private-key based decryption,</li>
 * <li>Mixed recipients (RSA + ElGamal + password) with decoys and default
 * shuffling,</li>
 * <li>AES-GCM (with tag bits and AAD) and ChaCha20-Poly1305 (with AAD and
 * explicit nonce).</li>
 * </ul>
 *
 * <p>
 * Keys are generated using the existing KeyStoreManagement CLI to populate a
 * real KeyringStore file, as done in KemTest. The CLI persists aliases as
 * {@code <alias>.pub} and {@code <alias>.prv}.
 * </p>
 */
public class GuardTest {

    /** All temporary files live here and are auto-cleaned by JUnit. */
    @TempDir
    Path tmp;

    private PrintStream savedOut;

    @BeforeAll
    static void bootBouncyCastle() {
        System.out.println("bootBouncyCastle()");
        // The project initializes BC explicitly where needed.
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
     * Password-only round trip using AES-GCM with header and AAD.
     *
     * <p>
     * This does not require a keyring.
     * </p>
     */
    @Test
    void password_aesGcm_roundTrip_ok() throws Exception {
        final String method = "password_aesGcm_roundTrip_ok()";
        final String password = "Tr0ub4dor&3";
        final int size = 4096;
        final String aadHex = "A1B2C3D4";
        final int tagBits = 128;

        System.out.println(method);
        System.out.println("...params: size=" + size + " tagBits=" + tagBits + " aadHex=" + aadHex);

        Path in = writeRandom(tmp.resolve("pt.bin"), size, 0xA11CE01);
        Path enc = tmp.resolve("pt.bin.enc");
        Path dec = tmp.resolve("pt.bin.dec");

        // Encrypt
        String[] encArgs = { "--encrypt", in.toString(), "--output", enc.toString(), "--to-psw", password, "--alg",
                "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex", aadHex };
        System.out.println("...encrypt: " + Arrays.toString(encArgs));
        int e = Guard.main(encArgs, new Options());
        assertEquals(0, e, "... encrypt expected exit code 0");

        // Decrypt (using password)
        String[] decArgs = { "--decrypt", enc.toString(), "--output", dec.toString(), "--password", password, "--alg",
                "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex", aadHex };
        System.out.println("...decrypt: " + Arrays.toString(decArgs));
        int d = Guard.main(decArgs, new Options());
        assertEquals(0, d, "... decrypt expected exit code 0");

        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec), "AES-GCM password round-trip mismatch");
        System.out.println("...ok");
    }

    /**
     * RSA recipient round trips with both AES-GCM and ChaCha20-Poly1305 payloads.
     *
     * <p>
     * Keys are generated through the real KeyStoreManagement CLI and read via Guard
     * with --to-alias and --priv-alias.
     * </p>
     */
    @Test
    void rsa_alias_aesGcm_and_chacha_roundTrip_ok() throws Exception {
        final String method = "rsa_alias_aesGcm_and_chacha_roundTrip_ok()";
        final String base = "alice";
        final String rsaId = "RSA";
        final int sizeAes = 8192;
        final int sizeCha = 3072;
        final int tagBits = 128;
        final String aadAes = "010203";
        final String aadCha = "D00DFEED";
        final String chNonce = "00112233445566778899AABB";

        System.out.println(method);
        System.out.println("...params: sizeAes=" + sizeAes + " sizeCha=" + sizeCha + " tagBits=" + tagBits + " aadAes="
                + aadAes + " aadCha=" + aadCha + " chNonce=" + chNonce);

        // Prepare keyring with RSA pair
        Path ring = tmp.resolve("ring-rsa.txt");
        KeyAliases rsa = generateIntoKeyStore(ring, rsaId, base);

        // AES-GCM round-trip
        {
            Path in = writeRandom(tmp.resolve("rsa-pt-aes.bin"), sizeAes, 0x5157A11);
            Path enc = tmp.resolve("rsa-pt-aes.bin.enc");
            Path dec = tmp.resolve("rsa-pt-aes.bin.dec");

            String[] encArgs = { "--encrypt", in.toString(), "--output", enc.toString(), "--keyring", ring.toString(),
                    "--to-alias", rsa.pub, "--alg", "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex",
                    aadAes };
            System.out.println("...AES encrypt: " + Arrays.toString(encArgs));
            int e = Guard.main(encArgs, new Options());
            assertEquals(0, e, "... AES encrypt rc");

            String[] decArgs = { "--decrypt", enc.toString(), "--output", dec.toString(), "--keyring", ring.toString(),
                    "--priv-alias", rsa.prv, "--alg", "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex",
                    aadAes };
            System.out.println("...AES decrypt: " + Arrays.toString(decArgs));
            int d = Guard.main(decArgs, new Options());
            assertEquals(0, d, "... AES decrypt rc");

            assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec), "RSA AES-GCM round-trip mismatch");
            System.out.println("...AES round-trip ok");
        }

        // ChaCha20-Poly1305 round-trip
        {
            Path in = writeRandom(tmp.resolve("rsa-pt-ch.bin"), sizeCha, 0xC0FFEE1);
            Path enc = tmp.resolve("rsa-pt-ch.bin.enc");
            Path dec = tmp.resolve("rsa-pt-ch.bin.dec");

            String[] encArgs = { "--encrypt", in.toString(), "--output", enc.toString(), "--keyring", ring.toString(),
                    "--to-alias", rsa.pub, "--alg", "chacha-aead", "--aad-hex", aadCha, "--nonce-hex", chNonce };
            System.out.println("...ChaCha encrypt: " + Arrays.toString(encArgs));
            int e = Guard.main(encArgs, new Options());
            assertEquals(0, e, "... ChaCha encrypt rc");

            String[] decArgs = { "--decrypt", enc.toString(), "--output", dec.toString(), "--keyring", ring.toString(),
                    "--priv-alias", rsa.prv, "--alg", "chacha-aead", "--aad-hex", aadCha, "--nonce-hex", chNonce };
            System.out.println("...ChaCha decrypt: " + Arrays.toString(decArgs));
            int d = Guard.main(decArgs, new Options());
            assertEquals(0, d, "... ChaCha decrypt rc");

            assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec),
                    "RSA ChaCha20-Poly1305 round-trip mismatch");
            System.out.println("...ChaCha round-trip ok");
        }

        System.out.println("...ok");
    }

    /**
     * Mixed recipients with decoys: RSA + password recipients plus an ElGamal decoy
     * alias.
     *
     * <p>
     * Verifies that default shuffling does not prevent decryption and that both
     * password and private-key paths can unlock.
     * </p>
     */
    @Test
    void mixed_recipients_with_decoys_roundTrip_ok() throws Exception {
        final String method = "mixed_recipients_with_decoys_roundTrip_ok()";
        final int size = 4096;

        System.out.println(method);

        // Prepare keyring with RSA and ElGamal
        Path ring = tmp.resolve("ring-mixed.txt");
        KeyAliases rsa = generateIntoKeyStore(ring, "RSA", "bob");
        KeyAliases elg = generateIntoKeyStore(ring, "ElGamal", "carol"); // used as decoy alias

        Path in = writeRandom(tmp.resolve("pt-mixed.bin"), size, 0xBADC0DE);
        Path enc = tmp.resolve("pt-mixed.bin.enc");
        Path dec1 = tmp.resolve("pt-mixed.bin.dec1");
        Path dec2 = tmp.resolve("pt-mixed.bin.dec2");

        final String password = "correct horse battery staple";
        final String aad = "FEEDFACE";
        final int tagBits = 128;

        // Encrypt with: RSA real recipient, password real recipient, ElGamal decoy
        // alias,
        // plus 2 random password decoys. Recipients are shuffled by default.
        String[] encArgs = { "--encrypt", in.toString(), "--output", enc.toString(), "--keyring", ring.toString(),
                "--to-alias", rsa.pub, "--to-psw", password, "--decoy-alias", elg.pub, "--decoy-psw-rand", "2", "--alg",
                "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex", aad };
        System.out.println("...encrypt: " + Arrays.toString(encArgs));
        int e = Guard.main(encArgs, new Options());
        assertEquals(0, e, "... encrypt rc");

        // Decrypt via private RSA key
        String[] decPriv = { "--decrypt", enc.toString(), "--output", dec1.toString(), "--keyring", ring.toString(),
                "--priv-alias", rsa.prv, "--alg", "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex",
                aad };
        System.out.println("...decrypt(private): " + Arrays.toString(decPriv));
        int d1 = Guard.main(decPriv, new Options());
        assertEquals(0, d1, "... decrypt(private) rc");
        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec1),
                "mixed recipients decrypt(private) mismatch");

        // Decrypt via password instead of key
        String[] decPwd = { "--decrypt", enc.toString(), "--output", dec2.toString(), "--password", password, "--alg",
                "aes-gcm", "--tag-bits", Integer.toString(tagBits), "--aad-hex", aad };
        System.out.println("...decrypt(password): " + Arrays.toString(decPwd));
        int d2 = Guard.main(decPwd, new Options());
        assertEquals(0, d2, "... decrypt(password) rc");
        assertArrayEquals(Files.readAllBytes(in), Files.readAllBytes(dec2),
                "mixed recipients decrypt(password) mismatch");

        System.out.println("...ok");
    }

    /**
     * Negative: decryption should fail to parse when both --priv-alias and
     * --password are given.
     */
    @Test
    void decrypt_with_both_unlock_material_rejected() throws Exception {
        final String method = "decrypt_with_both_unlock_material_rejected()";
        System.out.println(method);

        // Minimal valid blob: encrypt with password, then try to decrypt specifying
        // both unlock options
        Path in = writeRandom(tmp.resolve("pt-neg.bin"), 256, 0xABCD);
        Path enc = tmp.resolve("pt-neg.bin.enc");
        String pwd = "x";

        String[] encArgs = { "--encrypt", in.toString(), "--output", enc.toString(), "--to-psw", pwd, "--alg",
                "aes-gcm", "--tag-bits", "128" };
        int e = Guard.main(encArgs, new Options());
        assertEquals(0, e, "... encrypt rc");

        // Supply both options on purpose
        Exception ex = assertThrows(Exception.class, () -> {
            String[] bad = { "--decrypt", enc.toString(), "--output", tmp.resolve("out-neg.bin").toString(),
                    "--password", pwd, "--priv-alias", "whatever", "--alg", "aes-gcm" };
            Guard.main(bad, new Options());
        });
        System.out.println("...got expected exception: " + ex);
        System.out.println("...ok");
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    private static Path writeRandom(Path p, int size, long seed) throws Exception {
        byte[] b = new byte[size];
        new Random(seed).nextBytes(b);
        Files.write(p, b);
        return p;
    }

    /**
     * Generates an asymmetric keypair using the KeyStoreManagement CLI.
     *
     * <p>
     * The CLI stores aliases as {@code <alias>.pub} and {@code <alias>.prv}.
     * </p>
     *
     * @param ring      keyring file path
     * @param algId     algorithm id, e.g. "RSA", "ElGamal", "ML-KEM"
     * @param baseAlias base alias without suffix
     * @return public/private aliases to be used with Guard
     */
    private static KeyAliases generateIntoKeyStore(Path ring, String algId, String baseAlias) throws Exception {
        String[] genArgs = { "--keystore", ring.toString(), "--generate", "--alg", algId, "--alias", baseAlias,
                "--kind", "asym" };
        System.out.println("...KeyStoreManagement generate: " + Arrays.toString(genArgs));
        int rc = KeyStoreManagement.main(genArgs, new Options());
        if (rc != 0) {
            throw new GeneralSecurityException("KeyStoreManagement failed with rc=" + rc + " for " + algId);
        }
        return new KeyAliases(baseAlias + ".pub", baseAlias + ".prv");
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
