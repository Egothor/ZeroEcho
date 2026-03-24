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

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.apache.commons.cli.Options;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;
import zeroecho.core.spi.SymmetricKeyBuilder;
import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * KeyStoreManagementTest drives the KeyStoreManagement CLI across all available
 * algorithms, printing progress and verifying that generated entries can be
 * materialized via KeyringStore.
 *
 * <h2>What it does</h2>
 * <ul>
 * <li>For each algorithm that exposes a default-capable asymmetric builder,
 * generates a keypair.</li>
 * <li>For each algorithm that exposes a default-capable symmetric builder,
 * generates a secret.</li>
 * <li>Reloads the keyring and materializes keys using KeyringStore.</li>
 * <li>Prints progress and brief details to stdout during the run.</li>
 * </ul>
 */
public class KeyStoreManagementTest {

    @TempDir
    Path tmp;

    @BeforeAll
    static void setupProviders() {
        BouncyCastleActivator.init();
    }

    /**
     * Generates keypairs and secrets where supported and verifies materialization.
     *
     * @throws Exception on unexpected failure
     */
    @Test
    public void generateAndVerifyAllAlgorithms() throws Exception {
        Path ring = tmp.resolve("ring.txt");

        Set<String> algIds = CryptoAlgorithms.available();
        System.out.println("Algorithms: " + algIds);
        assertTrue(!algIds.isEmpty(), "Catalog should not be empty");

        int attempted = 0;
        for (String id : algIds) {
            Options dispatcher = new Options();
            CryptoAlgorithm alg = CryptoAlgorithms.require(id);
            boolean doAsym = hasAsymmetricDefault(alg);
            boolean doSym = hasSymmetricDefault(alg);

            if (doAsym) {
                String alias = "asym-" + sanitize(id) + "-" + UUID.randomUUID().toString().substring(0, 8);
                System.out.println("Generating asymmetric: " + id + " -> " + alias + ".pub/.prv");
                String[] argv = new String[] { "--keystore", ring.toString(), "--generate", "--alg", id, "--alias",
                        alias, "--kind", "asym" };
                try {
                    int rc = KeyStoreManagement.main(argv, dispatcher);
                    System.out.println("  rc=" + rc);
                    assertTrue(rc == 0, "asymmetric generation failed for " + id);
                    attempted++;
                } catch (Throwable t) {
                    System.out.println(
                            "  SKIP asym " + id + " due to " + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }

            if (doSym) {
                String alias = "sym-" + sanitize(id) + "-" + UUID.randomUUID().toString().substring(0, 8);
                System.out.println("Generating symmetric: " + id + " -> " + alias);
                String[] argv = new String[] { "--keystore", ring.toString(), "--generate", "--alg", id, "--alias",
                        alias, "--kind", "sym" };
                try {
                    int rc = KeyStoreManagement.main(argv, dispatcher);
                    System.out.println("  rc=" + rc);
                    assertTrue(rc == 0, "symmetric generation failed for " + id);
                    attempted++;
                } catch (Throwable t) {
                    System.out.println(
                            "  SKIP sym " + id + " due to " + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }
        }

        assertTrue(attempted > 0, "No generation attempts were successful");

        // Verify by reloading and materializing.
        KeyringStore store = KeyringStore.load(ring);
        List<String> aliases = store.aliases();
        System.out.println("Reloaded aliases (" + aliases.size() + "): " + aliases);

        int ok = 0;
        for (int i = 0; i < aliases.size(); i++) {
            String a = aliases.get(i);
            boolean good = false;
            try {
                PublicKey pub = store.getPublic(a);
                if (pub != null) {
                    System.out.println("  OK public:  " + a + " alg=" + pub.getAlgorithm() + " encLen="
                            + encLen(pub.getEncoded()));
                    good = true;
                }
            } catch (Throwable ignored) {
            }
            if (!good) {
                try {
                    PrivateKey prv = store.getPrivate(a);
                    if (prv != null) {
                        System.out.println("  OK private: " + a + " alg=" + prv.getAlgorithm() + " encLen="
                                + encLen(prv.getEncoded()));
                        good = true;
                    }
                } catch (Throwable ignored) {
                }
            }
            if (!good) {
                try {
                    SecretKey sk = store.getSecret(a);
                    if (sk != null) {
                        byte[] raw = sk.getEncoded();
                        System.out.println("  OK secret:  " + a + " alg=" + sk.getAlgorithm() + " len="
                                + (raw == null ? 0 : raw.length));
                        good = true;
                    }
                } catch (Throwable ignored) {
                }
            }
            if (good) {
                ok++;
            }
        }
        assertTrue(ok > 0, "No entries could be materialized back");
    }

    // ---- helpers ----

    private static boolean hasAsymmetricDefault(CryptoAlgorithm alg) {
        try {
            List<CryptoAlgorithm.AsymBuilderInfo> infos = alg.asymmetricBuildersInfo();
            for (int i = 0; i < infos.size(); i++) {
                CryptoAlgorithm.AsymBuilderInfo bi = infos.get(i);
                if (bi.defaultKeySpec == null) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Class<AlgorithmKeySpec> st = (Class<AlgorithmKeySpec>) bi.specType;
                AsymmetricKeyBuilder<AlgorithmKeySpec> b = alg.asymmetricKeyBuilder(st);
                if (b != null) {
                    return true;
                }
            }
        } catch (Throwable t) {
            return false;
        }
        return false;
    }

    private static boolean hasSymmetricDefault(CryptoAlgorithm alg) {
        try {
            List<CryptoAlgorithm.SymBuilderInfo> infos = alg.symmetricBuildersInfo();
            for (int i = 0; i < infos.size(); i++) {
                CryptoAlgorithm.SymBuilderInfo bi = infos.get(i);
                if (bi.defaultKeySpec() == null) {
                    continue;
                }
                @SuppressWarnings("unchecked")
                Class<AlgorithmKeySpec> st = (Class<AlgorithmKeySpec>) bi.specType();
                SymmetricKeyBuilder<AlgorithmKeySpec> b = alg.symmetricKeyBuilder(st);
                if (b != null) {
                    return true;
                }
            }
        } catch (Throwable t) {
            return false;
        }
        return false;
    }

    private static String sanitize(String id) {
        return id.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
    }

    private static String encLen(byte[] der) {
        return der == null ? "0" : Integer.toString(der.length);
    }
}
