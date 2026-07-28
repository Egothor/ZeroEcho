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
package zeroecho.core.storage;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.rsa.RsaPrivateKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.KeyOperation;
import zeroecho.core.KeyOperationInfo;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.SymmetricKeyGenerator;
import zeroecho.sdk.util.BouncyCastleActivator;

public class KeyringStoreDynamicTest {

    @BeforeAll
    static void setupProviders() {
        BouncyCastleActivator.init();
    }

    private static void logBegin(Object... params) {
        String thisClass = KeyringStoreDynamicTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = KeyringStoreDynamicTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static String encLen(byte[] der) {
        if (der == null) {
            return "0";
        }

        String str = Base64.getEncoder().withoutPadding().encodeToString(der);
        if (str.length() > 64) {
            str = str.substring(0, 64) + "...";
        }

        return der.length + " / b64 " + str;
    }

    private static AlgorithmKeySpec makeImportSpec(Class<?> specType, byte[] material, String algId, Object defaultSpec)
            throws Exception {
        try {
            Method m = specType.getMethod("fromRaw", byte[].class);
            Object spec = m.invoke(null, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        }
        try {
            Method m = specType.getMethod("fromRaw", String.class, byte[].class);
            String name = deriveVariantNameForImport(algId, defaultSpec);
            Object spec = m.invoke(null, name, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        }
        try {
            Method m = specType.getMethod("of", byte[].class);
            Object spec = m.invoke(null, material);
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        }
        try {
            Constructor<?> c = specType.getConstructor(byte[].class);
            Object spec = c.newInstance(new Object[] { material });
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        }
        try {
            Constructor<?> c = specType.getConstructor(String.class);
            Object spec = c.newInstance(Base64.getEncoder().encodeToString(material));
            return (AlgorithmKeySpec) spec;
        } catch (NoSuchMethodException ignored) {
        }
        throw new IllegalStateException("No usable import factory/ctor found for " + specType.getName());
    }

    private static String deriveVariantNameForImport(String algId, Object defaultSpec) {
        if (defaultSpec != null) {
            try {
                Method m = defaultSpec.getClass().getMethod("macName");
                Object v = m.invoke(defaultSpec);
                if (v instanceof String) {
                    return (String) v;
                }
            } catch (Exception ignored) {
            }
        }
        if ("HMAC".equalsIgnoreCase(algId)) {
            return "HmacSHA256";
        }
        return algId;
    }

    private static boolean looksLikeImportSpecForPublic(Class<?> specType) {
        String n = specType.getSimpleName();
        return n.contains("Public") || n.endsWith("PublicKeySpec");
    }

    private static boolean looksLikeImportSpecForPrivate(Class<?> specType) {
        String n = specType.getSimpleName();
        return n.contains("Private") || n.endsWith("PrivateKeySpec");
    }

    private static boolean looksLikeImportSpecForSecret(Class<?> specType) {
        String n = specType.getSimpleName();
        return n.contains("Import") || n.endsWith("KeyImportSpec") || n.endsWith("SecretSpec");
    }

    @Test
    void testExport(@TempDir Path tempDir) throws Exception {
        logBegin();

        Path keyringPath = tempDir.resolve("keyring-" + System.nanoTime() + ".txt");
        KeyringStore store = new KeyringStore(new zeroecho.sdk.ZeroEchoSession());

        zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession();
        KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa4096());
        store.putPrivate("alice.priv", "RSA", new RsaPrivateKeySpec(kp.getPrivate().getEncoded()));
        store.putPublic("alice.pub", "RSA", new RsaPublicKeySpec(kp.getPublic().getEncoded()));

        kp = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa4096());
        store.putPrivate("bob.priv", "RSA", new RsaPrivateKeySpec(kp.getPrivate().getEncoded()));
        store.putPublic("bob.pub", "RSA", new RsaPublicKeySpec(kp.getPublic().getEncoded()));
        store.save(keyringPath);

        store = KeyringStore.load(new zeroecho.sdk.ZeroEchoSession(), keyringPath);
        String s = store.exportText(Collections.singleton("alice.pub"));

        assertTrue(s.contains("# KeyringStore v1\n"));
        assertTrue(s.contains("\n@entry\n"));
        assertTrue(s.contains("\nalias=alice.pub\n"));
        assertTrue(s.contains("\nalgorithm=RSA\n"));
        assertTrue(s.contains("\nkind=PUBLIC_KEY\n"));
        assertTrue(s.contains("\nspec=zeroecho.core.alg.rsa.RsaPublicKeySpec\n"));
        assertTrue(s.contains("\ns.type=RSA-PUB\n"));
        assertTrue(s.contains("\ns.x509.b64="));

        logEnd();
    }

    @Test
    void keyring_dynamic_population_roundtrip_and_dump(@TempDir Path tempDir) throws Exception {
        logBegin();

        KeyringStore store = new KeyringStore(new zeroecho.sdk.ZeroEchoSession());

        Set<String> ids = CryptoAlgorithms.available();
        System.out.println("...algorithms discovered: " + ids);

        int totalAdded = 0;

        for (String id : ids) {
            CryptoAlgorithm alg = CryptoAlgorithms.require(id);
            System.out.println("\n-- " + id + " --");

            if (alg.keyOperations().stream()
                    .anyMatch(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE)) {
                int perAlg = 0;
                for (KeyOperationInfo bi : alg.keyOperations()) {
                    if (bi.operation() != KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE || bi.defaultSpec() == null) {
                        continue;
                    }
                    try {
                        @SuppressWarnings("unchecked")
                        Class<AlgorithmKeySpec> genSpecType = (Class<AlgorithmKeySpec>) bi.specType();
                        AsymmetricKeyPairGenerator<AlgorithmKeySpec> b = alg.asymmetricKeyPairGenerator(genSpecType);

                        AlgorithmKeySpec genSpec = bi.defaultSpec();
                        KeyPair kp = b.generateKeyPair(genSpec);
                        PublicKey pub = kp.getPublic();
                        PrivateKey prv = kp.getPrivate();

                        Class<?> pubImpType = null;
                        Class<?> prvImpType = null;
                        for (KeyOperationInfo x : alg.keyOperations()) {
                            if (x.operation() == KeyOperation.ASYMMETRIC_PUBLIC_IMPORT) {
                                pubImpType = x.specType();
                            } else if (x.operation() == KeyOperation.ASYMMETRIC_PRIVATE_IMPORT) {
                                prvImpType = x.specType();
                            }
                        }
                        if (pubImpType != null) {
                            AlgorithmKeySpec pubSpec = makeImportSpec(pubImpType, pub.getEncoded(), id,
                                    bi.defaultSpec());
                            String alias = id.toLowerCase() + "-pub-" + perAlg;
                            store.putPublic(alias, id, pubSpec);
                            System.out.println("..." + alias + " saved, len=" + encLen(pub.getEncoded()));
                            totalAdded++;
                        } else {
                            System.out.println("...*** SKIP *** no public import spec for " + id);
                        }
                        if (prvImpType != null) {
                            AlgorithmKeySpec prvSpec = makeImportSpec(prvImpType, prv.getEncoded(), id,
                                    bi.defaultSpec());
                            String alias = id.toLowerCase() + "-prv-" + perAlg;
                            store.putPrivate(alias, id, prvSpec);
                            System.out.println("..." + alias + " saved, len=" + encLen(prv.getEncoded()));
                            totalAdded++;
                        } else {
                            System.out.println("...*** SKIP *** no private import spec for " + id);
                        }

                        perAlg++;
                        if (perAlg >= 3) {
                            break;
                        }
                    } catch (Throwable t) {
                        System.out.println("...*** SKIP asym for " + id + " *** " + t.getClass().getSimpleName() + ": "
                                + t.getMessage());
                    }
                }
            }

            if (alg.keyOperations().stream()
                    .anyMatch(info -> info.operation() == KeyOperation.SYMMETRIC_GENERATE)) {
                int perAlg = 0;
                for (KeyOperationInfo bi : alg.keyOperations()) {
                    if (bi.operation() != KeyOperation.SYMMETRIC_GENERATE || bi.defaultSpec() == null) {
                        continue;
                    }
                    try {
                        @SuppressWarnings("unchecked")
                        Class<AlgorithmKeySpec> genSpecType = (Class<AlgorithmKeySpec>) bi.specType();
                        SymmetricKeyGenerator<AlgorithmKeySpec> b = alg.symmetricKeyGenerator(genSpecType);

                        AlgorithmKeySpec genSpec = bi.defaultSpec();
                        SecretKey sk = b.generateSecret(genSpec);

                        Class<?> impType = null;
                        for (KeyOperationInfo x : alg.keyOperations()) {
                            if (x.operation() == KeyOperation.SYMMETRIC_IMPORT
                                    && looksLikeImportSpecForSecret(x.specType())) {
                                impType = x.specType();
                            }
                        }
                        if (impType != null) {
                            byte[] raw = sk.getEncoded();
                            if (raw == null) {
                                raw = randomBytes(32);
                            }
                            AlgorithmKeySpec imp = makeImportSpec(impType, raw, id, bi.defaultSpec());
                            String alias = id.toLowerCase() + "-sec-" + perAlg;
                            store.putSecret(alias, id, imp);
                            System.out.println("..." + alias + " saved, len=" + raw.length);
                            totalAdded++;
                        } else {
                            System.out.println("...*** SKIP *** no symmetric import spec for " + id);
                        }
                        perAlg++;
                        if (perAlg >= 3) {
                            break;
                        }
                    } catch (Throwable t) {
                        System.out.println("...*** SKIP sym for " + id + " *** " + t.getClass().getSimpleName() + ": "
                                + t.getMessage());
                    }
                }
            }
        }

        // Persist using JUnit-managed temp directory
        Path keyringPath = tempDir.resolve("keyring-" + System.nanoTime() + ".txt");
        store.save(keyringPath);
        System.out.println("\n...saved keyring: " + keyringPath.getFileName());
        System.out.println("...entries stored: " + totalAdded);

        KeyringStore loaded = KeyringStore.load(new zeroecho.sdk.ZeroEchoSession(), keyringPath);
        assertTrue(loaded.aliases().size() >= Math.min(totalAdded, 1), "no entries reloaded");

        int ok = 0;
        for (String alias : loaded.aliases()) {
            boolean success = false;
            try {
                PublicKey k = loaded.getPublic(alias);
                if (k != null && k.getEncoded() != null) {
                    System.out.println("..." + alias + " OK public len=" + encLen(k.getEncoded()));
                    success = true;
                }
            } catch (Throwable ignore) {
            }
            if (!success) {
                try {
                    PrivateKey k = loaded.getPrivate(alias);
                    if (k != null && k.getEncoded() != null) {
                        System.out.println("..." + alias + " OK private len=" + encLen(k.getEncoded()));
                        success = true;
                    }
                } catch (Throwable ignore) {
                }
            }
            if (!success) {
                try {
                    SecretKey k = loaded.getSecret(alias);
                    if (k != null && k.getEncoded() != null) {
                        System.out.println("..." + alias + " OK secret len=" + encLen(k.getEncoded()));
                        success = true;
                    }
                } catch (Throwable ignore) {
                }
            }
            if (success) {
                ok++;
            } else {
                System.out.println("...*** WARN *** could not reconstruct: " + alias);
            }
        }
        assertTrue(ok > 0, "nothing reconstructed from keyring");

        System.out.println("\n===== KEYRING DUMP BEGIN =====");
        List<String> lines = Files.readAllLines(keyringPath, StandardCharsets.UTF_8);
        for (String ln : lines) {
            System.out.printf(ln.length() > 80 ? "%.77s...%n" : "%s%n", ln);
        }
        System.out.println("===== KEYRING DUMP END =====\n");

        logEnd();
    }
}
