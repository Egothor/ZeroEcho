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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.audit.AuditMode;
import zeroecho.core.audit.JulAuditListenerStd;
import zeroecho.core.context.DigestContext;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.MacContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;
import zeroecho.core.spi.SymmetricKeyGenerator;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.util.BouncyCastleActivator;

public class CatalogContractTest {
    private static ZeroEchoSession session;

    static Level effectiveLevel(Logger lg) {
        for (Logger x = lg; x != null; x = x.getParent()) {
            if (x.getLevel() != null) {
                return x.getLevel();
            }
        }
        return null;
    }

    static void dump(String name) {
        Logger lg = Logger.getLogger(name);
        System.out.println("[" + name + "] level=" + lg.getLevel() + " effective=" + effectiveLevel(lg) + " useParent="
                + lg.getUseParentHandlers());
        for (Handler h : lg.getHandlers()) {
            System.out.println("  handler=" + h.getClass().getSimpleName() + " level=" + h.getLevel());
        }
    }

    @BeforeAll
    public static void setupProvider() {
        BouncyCastleActivator.init();

        Logger jul = Logger.getLogger("zeroecho.audit");
        jul.setLevel(Level.FINE); // see PROGRESS at FINE

        session = new ZeroEchoSession()
                .withAuditListener(JulAuditListenerStd.builder().logger(jul).infoLevel(Level.INFO)
                        .warnLevel(Level.WARNING).progressLevel(Level.FINE).includeStackTraces(true).build())
                .withAuditMode(AuditMode.WRAP);

        dump("");
        dump("zeroecho.core.audit");
    }

    private static void logBegin(Object... params) {
        String thisClass = CatalogContractTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = CatalogContractTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static String prettyPrintXml(String xml) throws TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        try {
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        } catch (IllegalArgumentException ignored) {
        }
        try {
            tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        } catch (IllegalArgumentException ignored) {
        }

        Transformer t = tf.newTransformer();
        t.setOutputProperty(OutputKeys.METHOD, "xml");
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        t.setOutputProperty(OutputKeys.INDENT, "yes");
        t.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");

        StringWriter out = new StringWriter();
        t.transform(new StreamSource(new StringReader(xml)), new StreamResult(out));
        return out.toString();
    }

    // ---------- Tests ----------

    @Test
    void catalogSane() throws TransformerException {
        logBegin();
        CryptoCatalog cat = CryptoCatalog.load();
        System.out.println(prettyPrintXml(cat.toXml()));
        assertDoesNotThrow(cat::validate);
        assertTrue(CryptoAlgorithms.available().size() > 0);
        logEnd();
    }

    @Test
    void genericRoundTrips() throws Exception {
        logBegin();
        byte[] msg = "roundtrip".getBytes();
        for (String id : CryptoAlgorithms.available()) {
            CryptoAlgorithm alg = CryptoAlgorithms.require(id);
            boolean hasAsym = alg.keyOperations().stream()
                    .anyMatch(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE);
            boolean hasSym = alg.keyOperations().stream()
                    .anyMatch(info -> info.operation() == KeyOperation.SYMMETRIC_GENERATE);

            // SIGN/VERIFY (asymmetric)
            if (alg.roles().contains(KeyUsage.SIGN) && alg.roles().contains(KeyUsage.VERIFY) && hasAsym) {
                trySignVerify(id, msg);
                System.out.println();
            }

            // ENCRYPT/DECRYPT
            if (alg.roles().contains(KeyUsage.ENCRYPT) && alg.roles().contains(KeyUsage.DECRYPT)) {
                if (hasSym || hasAsym) {
                    tryEncryptDecrypt(id, msg, hasSym, hasAsym);
                    System.out.println();
                }
            }

            // KEM
            if (alg.roles().contains(KeyUsage.ENCAPSULATE) && alg.roles().contains(KeyUsage.DECAPSULATE) && hasAsym) {
                tryKem(id, msg);
                System.out.println();
            }

            // DIGEST
            if (alg.roles().contains(KeyUsage.DIGEST)) {
                tryDigest(id, msg);
                System.out.println();
            }

            // MAC (single role now; verification via setExpectedTag)
            if (alg.roles().contains(KeyUsage.MAC) && hasSym) {
                tryMac(id, msg);
                System.out.println();
            }
        }
        logEnd();
    }

    // ---------- Helpers: SIGN/VERIFY ----------

    private void trySignVerify(String id, byte[] msg) throws Exception {
        logBegin(id, Integer.valueOf(msg.length));
        KeyPair kp = tryKeyPairWithDefaultSpec(CryptoAlgorithms.require(id));
        if (kp == null) {
            logEnd();
            return;
        }

        // SIGN: produce [body][signature] and capture trailer
        SignatureContext signer = session.createContext(id, KeyUsage.SIGN, kp.getPrivate(), null);
        final byte[][] sigHolder = new byte[1][];
        final int sigLen = signer.tagLength();
        try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), sigLen, 8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                sigHolder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            assertArrayEquals(msg, readAll(in));
        } finally {
            signer.close();
        }
        byte[] sig = sigHolder[0];
        assertNotNull(sig, "signature missing");
        assertTrue(sig.length > 0, "signature empty");

        // VERIFY: supply signature via setExpectedTag and drain (throws on mismatch)
        SignatureContext verifier = session.createContext(id, KeyUsage.VERIFY, kp.getPublic(), null);
        verifier.setExpectedTag(sig);
        try (InputStream verIn = verifier.wrap(new ByteArrayInputStream(msg))) {
            readAll(verIn);
        } finally {
            verifier.close();
        }
        logEnd();
    }

    // ---------- Helpers: ENCRYPT/DECRYPT ----------

    private void tryEncryptDecrypt(String id, byte[] msg, boolean hasSym, boolean hasAsym) throws Exception {
        logBegin(id, Integer.valueOf(msg.length));
        CryptoAlgorithm alg = CryptoAlgorithms.require(id);

        if (hasSym) {
            SecretKey sk = tryGenerateSecretWithDefaultSpec(alg);
            if (sk != null) {
                conflux.CtxInterface session = conflux.Ctx.INSTANCE.getContext("encdec-" + System.nanoTime());

                EncryptionContext enc = CatalogContractTest.session.createContext(id, KeyUsage.ENCRYPT, sk, null);
                if (enc instanceof zeroecho.core.spi.ContextAware ca) {
                    ca.setContext(session);
                }
                byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
                enc.close();

                EncryptionContext dec = CatalogContractTest.session.createContext(id, KeyUsage.DECRYPT, sk, null);
                if (dec instanceof zeroecho.core.spi.ContextAware ca2) {
                    ca2.setContext(session);
                }
                byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
                dec.close();

                assertArrayEquals(msg, pt, "decrypt mismatch (symmetric) for " + id);
                logEnd();
                return;
            }
        }

        if (hasAsym) {
            KeyPair kp = tryKeyPairWithDefaultSpec(alg);
            if (kp != null) {
                EncryptionContext enc = session.createContext(id, KeyUsage.ENCRYPT, kp.getPublic(), null);
                byte[] ct = readAll(enc.attach(new ByteArrayInputStream(msg)));
                enc.close();

                EncryptionContext dec = session.createContext(id, KeyUsage.DECRYPT, kp.getPrivate(), null);
                byte[] pt = readAll(dec.attach(new ByteArrayInputStream(ct)));
                dec.close();

                assertArrayEquals(msg, pt, "decrypt mismatch (asymmetric) for " + id);
            }
        }
        logEnd();
    }

    // ---------- Helpers: KEM ----------

    private void tryKem(String id, byte[] msg) throws Exception { // msg unused; kept for symmetry/logging
        logBegin(id);
        KeyPair kp = tryKeyPairWithDefaultSpec(CryptoAlgorithms.require(id));
        if (kp == null) {
            logEnd();
            return;
        }

        KemContext pub = session.createContext(id, KeyUsage.ENCAPSULATE, kp.getPublic(), null);
        KemContext prv = session.createContext(id, KeyUsage.DECAPSULATE, kp.getPrivate(), null);

        KemContext.KemResult res = pub.encapsulate();
        byte[] ss = prv.decapsulate(res.ciphertext());

        assertArrayEquals(res.sharedSecret(), ss, "KEM shared secret mismatch");

        pub.close();
        prv.close();
        logEnd();
    }

    // ---------- Helpers: DIGEST (streaming via trailer) ----------

    private void tryDigest(String id, byte[] msg) throws Exception {
        logBegin(id, Integer.valueOf(msg.length));

        DigestContext dctx = session.createContext(id, KeyUsage.DIGEST, NullKey.INSTANCE, null);
        final byte[][] digestHolder = new byte[1][];
        final int tagLen = dctx.tagLength();

        // Produce digest as trailer and capture
        try (InputStream in = new TailStrippingInputStream(dctx.wrap(new ByteArrayInputStream(msg)), tagLen, 8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                digestHolder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            assertArrayEquals(msg, readAll(in)); // passthrough body unchanged
        } finally {
            dctx.close();
        }

        byte[] digest = digestHolder[0];
        assertNotNull(digest);
        assertTrue(digest.length > 0);
        logEnd();
    }

    // ---------- Helpers: MAC (produce + verify) ----------

    private void tryMac(String id, byte[] msg) throws Exception {
        logBegin(id, Integer.valueOf(msg.length));

        SecretKey sk = tryGenerateSecretWithDefaultSpec(CryptoAlgorithms.require(id));
        if (sk == null) {
            logEnd();
            return;
        }

        // Produce tag: [body][tag], capture trailer
        MacContext mac = session.createContext(id, KeyUsage.MAC, sk, null);
        final byte[][] tagHolder = new byte[1][];
        final int tagLen = mac.tagLength();
        try (InputStream in = new TailStrippingInputStream(mac.wrap(new ByteArrayInputStream(msg)), tagLen, 8192) {
            @Override
            protected void processTail(byte[] tail) throws IOException {
                tagHolder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            assertArrayEquals(msg, readAll(in));
        } finally {
            mac.close();
        }
        byte[] tag = tagHolder[0];
        assertNotNull(tag);
        assertTrue(tag.length > 0);

        // Verify: provide expected tag and drain (throws on mismatch)
        MacContext ver = session.createContext(id, KeyUsage.MAC, sk, null);
        ver.setExpectedTag(tag);
        try (InputStream in = ver.wrap(new ByteArrayInputStream(msg))) {
            readAll(in);
        } finally {
            ver.close();
        }

        logEnd();
    }

    // ---------- Utility: readAll ----------

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    // ---------- Utility: discover default key material ----------

    private KeyPair tryKeyPairWithDefaultSpec(CryptoAlgorithm alg) {
        logBegin(alg.id());
        try {
            List<KeyOperationInfo> infos = alg.keyOperations().stream()
                    .filter(info -> info.operation() == KeyOperation.ASYMMETRIC_KEY_PAIR_GENERATE).toList();
            if (infos.isEmpty()) {
                System.out.println("no asymmetric builder info");
                logEnd();
                return null;
            }

            for (KeyOperationInfo bi : infos) {
                if (bi.defaultSpec() == null) {
                    continue;
                }
                try {
                    @SuppressWarnings("unchecked")
                    Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) bi.specType();
                    AlgorithmKeySpec spec = bi.defaultSpec();

                    AsymmetricKeyPairGenerator<AlgorithmKeySpec> builder = alg.asymmetricKeyPairGenerator(specType);
                    System.out.println("...building with " + specType.getName());
                    KeyPair kp = builder.generateKeyPair(spec);
                    if (kp != null) {
                        logEnd();
                        return kp;
                    }
                } catch (Throwable t) {
                    System.out.println("builder " + bi.specType().getSimpleName() + " failed to generate keypair: "
                            + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }

            System.out.println("no builder with working default keygen");
            logEnd();
            return null;
        } catch (Throwable t) {
            System.out.println("...*** SKIP *** keyPair cannot be generated: " + t);
            return null;
        }
    }

    private SecretKey tryGenerateSecretWithDefaultSpec(CryptoAlgorithm alg) {
        logBegin(alg.id());
        try {
            List<KeyOperationInfo> infos = alg.keyOperations().stream()
                    .filter(info -> info.operation() == KeyOperation.SYMMETRIC_GENERATE).toList();
            if (infos.isEmpty()) {
                System.out.println("no symmetric builder info");
                logEnd();
                return null;
            }

            for (KeyOperationInfo bi : infos) {
                if (bi.defaultSpec() == null) {
                    continue;
                }
                try {
                    @SuppressWarnings("unchecked")
                    Class<AlgorithmKeySpec> specType = (Class<AlgorithmKeySpec>) bi.specType();
                    AlgorithmKeySpec spec = bi.defaultSpec();

                    SymmetricKeyGenerator<AlgorithmKeySpec> builder = alg.symmetricKeyGenerator(specType);
                    SecretKey sk = builder.generateSecret(spec);
                    if (sk != null) {
                        logEnd();
                        return sk;
                    }
                } catch (Throwable t) {
                    System.out.println("symmetric builder " + bi.specType().getSimpleName()
                            + " failed to generate secret: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }

            System.out.println("no builder with working default secret generation");
            logEnd();
            return null;
        } catch (Throwable t) {
            System.out.println("...*** SKIP *** secret cannot be generated: " + t);
            return null;
        }
    }
}
