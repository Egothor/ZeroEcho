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
package zeroecho.sdk.hybrid.signature;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.ed25519.Ed25519KeyGenSpec;
import zeroecho.core.alg.rsa.RsaKeyGenSpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.ContextSpec;
import zeroecho.sdk.builders.TagTrailerDataContentBuilder;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.core.DataContentBuilder;
import zeroecho.sdk.builders.core.DataContentChainBuilder;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.util.BouncyCastleActivator;

/**
 * End-to-end tests for hybrid signatures (classic + PQC) across:
 * <ul>
 * <li>{@link HybridSignatureProfile.VerifyRule#AND} and
 * {@link HybridSignatureProfile.VerifyRule#OR}</li>
 * <li>direct streaming use via {@link SignatureContext#wrap(InputStream)}</li>
 * <li>integration via {@link TagTrailerDataContentBuilder} and
 * {@link DataContentChainBuilder}</li>
 * </ul>
 *
 * <p>
 * Tests focus on practical combinations: Ed25519 + SPHINCS+, and
 * RSA-PSS(SHA-256) + SPHINCS+ (if registered).
 * </p>
 */
public class HybridSignatureTest {

    @BeforeAll
    static void setup() {
        // Optional: enable BC if you use BC-only modes in KEM payloads (EAX/OCB/CCM,
        // etc.)
        try {
            BouncyCastleActivator.init();
        } catch (Throwable ignore) {
            // keep tests runnable without BC if not present
        }
    }

    // ---------- boilerplate logging ----------
    private static void logBegin(Object... params) {
        String thisClass = HybridSignatureTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logBegin"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "(" + Arrays.deepToString(params) + ")");
    }

    private static void logEnd() {
        String thisClass = HybridSignatureTest.class.getName();
        String method = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
                .walk(frames -> frames
                        .dropWhile(f -> !f.getClassName().equals(thisClass) || f.getMethodName().equals("logEnd"))
                        .findFirst().map(StackWalker.StackFrame::getMethodName).orElse("<?>"));
        System.out.println(method + "...ok");
    }

    private static void requireAlgOrSkip(String id) {
        if (!CryptoAlgorithms.available().contains(id)) {
            System.out.println("...*** SKIP *** " + id + " not registered");
            Assumptions.assumeTrue(false);
        }
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        Random r = new Random(123456789L); // deterministic
        r.nextBytes(b);
        return b;
    }

    private static byte[] readAll(InputStream in) throws Exception {
        try (InputStream closeMe = in) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            closeMe.transferTo(out);
            return out.toByteArray();
        }
    }

    private static String hexShort(byte[] b) {
        if (b == null) {
            return "null";
        }
        int max = Math.min(b.length, 24);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < max; i++) {
            sb.append(String.format("%02x", Integer.valueOf(b[i] & 0xff)));
        }
        if (b.length > max) {
            sb.append("...");
        }
        return sb.toString();
    }

    private static byte[] flipOneBit(byte[] in, int index) {
        byte[] out = in.clone();
        out[index] = (byte) (out[index] ^ 0x01);
        return out;
    }

    private static byte[] sub(byte[] b, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, off, out, 0, len);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int tagLen(String algoId, KeyUsage role, Key key, ContextSpec specOrNull) throws Exception {
        try (SignatureContext ctx = new zeroecho.sdk.ZeroEchoSession().createContext(algoId, role, key, specOrNull)) {
            return ctx.tagLength();
        }
    }

    private static byte[] signTrailer(SignatureContext signer, byte[] body) throws Exception {
        int tagLen = signer.tagLength();
        final byte[][] holder = new byte[1][];

        try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(body)), tagLen, 8192) {
            @Override
            protected void processTail(byte[] tail) {
                holder[0] = (tail == null ? null : tail.clone());
            }
        }) {
            byte[] pt = readAll(in);
            assertArrayEquals(body, pt, "sign passthrough mismatch");
        }

        if (holder[0] == null) {
            throw new IllegalStateException("Signature trailer missing");
        }
        return holder[0];
    }

    /**
     * Minimal source builder for DataContent chains (same shape as other tests).
     */
    private static final class BytesSourceBuilder implements DataContentBuilder<PlainContent> {
        private final byte[] data;

        private BytesSourceBuilder(byte[] data) {
            this.data = data.clone();
        }

        static BytesSourceBuilder of(byte[] data) {
            return new BytesSourceBuilder(data);
        }

        @Override
        public PlainContent build(boolean encrypt) {
            return new PlainContent() {
                @Override
                public void setInput(DataContent input) {
                    /* no upstream for sources */
                }

                @Override
                public InputStream getStream() {
                    return new ByteArrayInputStream(data);
                }
            };
        }
    }

    // ======================================================================
    // 1) DIRECT streaming tests (SignatureContext.wrap + transferTo)
    // ======================================================================

    @Test
    void hybrid_ed25519_sphincsplus_direct_and_or_negative() throws Exception {
        final int size = 64 * 1024 + 13;
        logBegin("direct", "Ed25519+SPHINCS+", Integer.valueOf(size));

        requireAlgOrSkip("Ed25519");
        requireAlgOrSkip("SPHINCS+");

        byte[] msg = randomBytes(size);
        System.out.println("...msg=" + msg.length + " bytes");

        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair ed = session.keyBuilders().asymmetric().generateKeyPair("Ed25519",
                Ed25519KeyGenSpec.defaultSpec());
        KeyPair spx = session.keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());

        int edLen = tagLen("Ed25519", KeyUsage.SIGN, ed.getPrivate(), null);
        int spxLen = tagLen("SPHINCS+", KeyUsage.SIGN, spx.getPrivate(), null);
        System.out.println("...classicTagLen=" + edLen + ", pqcTagLen=" + spxLen);

        // ---- AND ----
        HybridSignatureProfile andProfile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        byte[] sigAnd;
        try (SignatureContext signer = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), andProfile, ed.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {
            sigAnd = signTrailer(signer, msg);
        }
        System.out.println("...sig(AND).len=" + sigAnd.length + ", head=" + hexShort(sigAnd));

        // verify OK
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), andProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(sigAnd);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }
        System.out.println("...verify(AND)=ok");

        // corrupt classic => must fail
        byte[] badClassic = concat(flipOneBit(sub(sigAnd, 0, edLen), 0), sub(sigAnd, edLen, spxLen));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), andProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(badClassic);
            assertThrows(java.io.IOException.class, () -> {
                try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                    in.transferTo(OutputStream.nullOutputStream());
                }
            });
        }
        System.out.println("...verify(AND) bad classic -> throws");

        // corrupt pqc => must fail
        byte[] badPqc = concat(sub(sigAnd, 0, edLen), flipOneBit(sub(sigAnd, edLen, spxLen), 0));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), andProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(badPqc);
            assertThrows(java.io.IOException.class, () -> {
                try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                    in.transferTo(OutputStream.nullOutputStream());
                }
            });
        }
        System.out.println("...verify(AND) bad pqc -> throws");

        // ---- OR ----
        HybridSignatureProfile orProfile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.OR);

        byte[] sigOr;
        try (SignatureContext signer = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), orProfile, ed.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {
            sigOr = signTrailer(signer, msg);
        }
        System.out.println("...sig(OR).len=" + sigOr.length + ", head=" + hexShort(sigOr));

        // corrupt classic => OR must pass
        byte[] orBadClassic = concat(flipOneBit(sub(sigOr, 0, edLen), 0), sub(sigOr, edLen, spxLen));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), orProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(orBadClassic);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }
        System.out.println("...verify(OR) bad classic -> ok");

        // corrupt pqc => OR must pass
        byte[] orBadPqc = concat(sub(sigOr, 0, edLen), flipOneBit(sub(sigOr, edLen, spxLen), 0));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), orProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(orBadPqc);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }
        System.out.println("...verify(OR) bad pqc -> ok");

        // corrupt both => OR must fail
        byte[] orBadBoth = concat(flipOneBit(sub(sigOr, 0, edLen), 0), flipOneBit(sub(sigOr, edLen, spxLen), 0));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), orProfile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(orBadBoth);
            assertThrows(java.io.IOException.class, () -> {
                try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                    in.transferTo(OutputStream.nullOutputStream());
                }
            });
        }
        System.out.println("...verify(OR) bad both -> throws");

        logEnd();
    }

    @Test
    void hybrid_rsa_sphincsplus_direct_and_roundtrip() throws Exception {
        final int size = 96 * 1024 + 3;
        logBegin("direct", "RSA+SPHINCS+", Integer.valueOf(size));

        requireAlgOrSkip("RSA");
        requireAlgOrSkip("SPHINCS+");

        byte[] msg = randomBytes(size);
        System.out.println("...msg=" + msg.length + " bytes");

        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair rsa = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        KeyPair spx = session.keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());

        int rsaLen = tagLen("RSA", KeyUsage.SIGN, rsa.getPrivate(), null);
        int spxLen = tagLen("SPHINCS+", KeyUsage.SIGN, spx.getPrivate(), null);
        System.out.println("...classicTagLen=" + rsaLen + ", pqcTagLen=" + spxLen);

        HybridSignatureProfile profile = new HybridSignatureProfile("RSA", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        byte[] sig;
        try (SignatureContext signer = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile, rsa.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {
            sig = signTrailer(signer, msg);
        }
        System.out.println("...sig.len=" + sig.length + ", head=" + hexShort(sig));

        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, rsa.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(sig);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
        }
        System.out.println("...verify(AND)=ok");

        // negative sanity: corrupt classic => must fail (AND)
        byte[] badClassic = concat(flipOneBit(sub(sig, 0, rsaLen), 0), sub(sig, rsaLen, spxLen));
        try (SignatureContext verifier = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, rsa.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            verifier.setVerificationApproach(verifier.getVerificationCore().getThrowOnMismatch());
            verifier.setExpectedTag(badClassic);
            assertThrows(java.io.IOException.class, () -> {
                try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                    in.transferTo(OutputStream.nullOutputStream());
                }
            });
        }
        System.out.println("...verify(AND) bad classic -> throws");

        logEnd();
    }

    // ======================================================================
    // 2) TagTrailer integration tests (DataContentChainBuilder + TagTrailer)
    // ======================================================================

    @Test
    void hybrid_ed25519_sphincsplus_via_tagtrailer_and_roundtrip() throws Exception {
        final int size = 32 * 1024 + 7;
        logBegin("TagTrailer", "AND", "Ed25519+SPHINCS+", Integer.valueOf(size));

        requireAlgOrSkip("Ed25519");
        requireAlgOrSkip("SPHINCS+");

        byte[] msg = randomBytes(size);
        System.out.println("...msg=" + msg.length + " bytes");

        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair ed = session.keyBuilders().asymmetric().generateKeyPair("Ed25519",
                Ed25519KeyGenSpec.defaultSpec());
        KeyPair spx = session.keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());

        HybridSignatureProfile profile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        byte[] out;
        int tagLen;

        try (SignatureContext tagEnc = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {

            DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagEnc).bufferSize(8192)).build();

            out = readAll(enc.getStream());
            tagLen = tagEnc.tagLength();
        }

        System.out.println("...out=" + out.length + " bytes");

        try (SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

            // IMPORTANT: TagTrailerDataContentBuilder supplies expectedTag internally
            // during streaming.
            // HybridSignatureContext.wrap must NOT require expectedTag pre-set.
            DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(out))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                    .build();

            byte[] pt = readAll(dec.getStream());
            assertArrayEquals(msg, pt, "hybrid TagTrailer AND roundtrip mismatch");
        }

        System.out.println("...tagLen=" + tagLen);
        logEnd();
    }

    @Test
    void hybrid_ed25519_sphincsplus_via_tagtrailer_or_negative() throws Exception {
        final int size = 24 * 1024 + 9;
        logBegin("TagTrailer", "OR", "Ed25519+SPHINCS+", Integer.valueOf(size));

        requireAlgOrSkip("Ed25519");
        requireAlgOrSkip("SPHINCS+");

        byte[] msg = ("zeroecho-hybrid-or-negative-").getBytes(StandardCharsets.UTF_8);
        msg = Arrays.copyOf(msg, size);
        System.out.println("...msg=" + msg.length + " bytes");

        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair ed = session.keyBuilders().asymmetric().generateKeyPair("Ed25519",
                Ed25519KeyGenSpec.defaultSpec());
        KeyPair spx = session.keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());

        int edLen = tagLen("Ed25519", KeyUsage.SIGN, ed.getPrivate(), null);
        int spxLen = tagLen("SPHINCS+", KeyUsage.SIGN, spx.getPrivate(), null);
        System.out.println("...classicTagLen=" + edLen + ", pqcTagLen=" + spxLen);

        HybridSignatureProfile profile = new HybridSignatureProfile("Ed25519", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.OR);

        byte[] out;
        int tagLen;

        try (SignatureContext tagEnc = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {

            DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagEnc).bufferSize(8192)).build();

            out = readAll(enc.getStream());
            tagLen = tagEnc.tagLength();
        }

        byte[] body = sub(out, 0, out.length - tagLen);
        byte[] tag = sub(out, out.length - tagLen, tagLen);

        System.out.println("...tag.len=" + tag.length + ", head=" + hexShort(tag));

        // Corrupt ONLY classic part => OR must still PASS
        byte[] badClassic = concat(flipOneBit(sub(tag, 0, edLen), 0), sub(tag, edLen, spxLen));
        byte[] outBadClassic = concat(body, badClassic);

        try (SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

            DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(outBadClassic))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                    .build();

            byte[] pt = readAll(dec.getStream());
            assertArrayEquals(msg, pt, "OR should accept when only classic signature is corrupted");
        }

        System.out.println("...OR verify with bad classic -> ok");

        // Corrupt ONLY pqc part => OR must still PASS
        byte[] badPqc = concat(sub(tag, 0, edLen), flipOneBit(sub(tag, edLen, spxLen), 0));
        byte[] outBadPqc = concat(body, badPqc);

        try (SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

            DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(outBadPqc))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                    .build();

            byte[] pt = readAll(dec.getStream());
            assertArrayEquals(msg, pt, "OR should accept when only PQC signature is corrupted");
        }

        System.out.println("...OR verify with bad pqc -> ok");

        // Corrupt BOTH => OR must FAIL
        byte[] badBoth = concat(flipOneBit(sub(tag, 0, edLen), 0), flipOneBit(sub(tag, edLen, spxLen), 0));
        byte[] outBadBoth = concat(body, badBoth);

        try (SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, ed.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

            DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(outBadBoth))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                    .build();

            assertThrows(java.io.IOException.class, () -> readAll(dec.getStream()));
        }

        System.out.println("...OR verify with bad both -> throws");
        System.out.println("...tagLen=" + tagLen);

        logEnd();
    }

    @Test
    void hybrid_rsa_sphincsplus_via_tagtrailer_and_roundtrip() throws Exception {
        final int size = 40 * 1024 + 1;
        logBegin("TagTrailer", "AND", "RSA+SPHINCS+", Integer.valueOf(size));

        requireAlgOrSkip("RSA");
        requireAlgOrSkip("SPHINCS+");

        byte[] msg = randomBytes(size);
        System.out.println("...msg=" + msg.length + " bytes");

        ZeroEchoSession session = new ZeroEchoSession();
        KeyPair rsa = session.keyBuilders().asymmetric().generateKeyPair("RSA", RsaKeyGenSpec.rsa2048());
        KeyPair spx = session.keyBuilders().asymmetric().generateKeyPair("SPHINCS+",
                SphincsPlusKeyGenSpec.defaultSpec());

        HybridSignatureProfile profile = new HybridSignatureProfile("RSA", "SPHINCS+", null, null,
                HybridSignatureProfile.VerifyRule.AND);

        byte[] out;

        try (SignatureContext tagEnc = HybridSignatureContexts.sign(new zeroecho.sdk.ZeroEchoSession(), profile, rsa.getPrivate(), spx.getPrivate(),
                2 * 1024 * 1024)) {

            DataContent enc = DataContentChainBuilder.encrypt().add(BytesSourceBuilder.of(msg))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagEnc).bufferSize(8192)).build();

            out = readAll(enc.getStream());
        }

        System.out.println("...out=" + out.length + " bytes");

        try (SignatureContext tagDec = HybridSignatureContexts.verify(new zeroecho.sdk.ZeroEchoSession(), profile, rsa.getPublic(), spx.getPublic(),
                2 * 1024 * 1024)) {
            tagDec.setVerificationApproach(tagDec.getVerificationCore().getThrowOnMismatch());

            DataContent dec = DataContentChainBuilder.decrypt().add(BytesSourceBuilder.of(out))
                    .add(new TagTrailerDataContentBuilder<Signature>(tagDec).bufferSize(8192).throwOnMismatch())
                    .build();

            byte[] pt = readAll(dec.getStream());
            assertArrayEquals(msg, pt, "hybrid TagTrailer AND (RSA+SPHINCS+) roundtrip mismatch");
        }

        logEnd();
    }
}
