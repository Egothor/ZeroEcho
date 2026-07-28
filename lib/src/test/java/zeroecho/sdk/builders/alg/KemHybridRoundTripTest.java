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
package zeroecho.sdk.builders.alg;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.alg.bike.BikeKeyGenSpec;
import zeroecho.core.alg.cmce.CmceKeyGenSpec;
import zeroecho.core.alg.frodo.FrodoKeyGenSpec;
import zeroecho.core.alg.hqc.HqcKeyGenSpec;
import zeroecho.core.alg.kyber.KyberKeyGenSpec;
import zeroecho.core.alg.ntru.NtruKeyGenSpec;
import zeroecho.core.alg.ntruprime.NtrulPrimeKeyGenSpec;
import zeroecho.core.alg.ntruprime.SntruPrimeKeyGenSpec;
import zeroecho.core.alg.saber.SaberKeyGenSpec;
import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;
import zeroecho.sdk.util.Kdf;

/**
 * Round-trip tests for KEM + symmetric envelope using the new
 * {@link KemDataContentBuilder} that first configures the KEM and then
 * delegates to an explicit AES/ChaCha builder.
 *
 * <p>
 * This replaces the older ad-hoc payload builders (GcmBuilder/CcmBuilder/etc.).
 * Modes exercised here are those implemented by {@link AesDataContentBuilder}
 * and {@link ChaChaDataContentBuilder}: AES-GCM, AES-CBC, AES-CTR, and
 * ChaCha20-Poly1305.
 * </p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.MethodName.class)
class KemHybridRoundTripTest {

    @BeforeAll
    void setupProviders() {
        // PQC providers (required by most KEM impls)
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new BouncyCastleProvider());
    }

    // Only modes supported by the concrete AES/ChaCha builders
    private static final String[] MODES = new String[] { "GCM", "CBC", "CTR", "CHACHA20-POLY1305" };

    // Non-empty AAD to force AEAD path for ChaCha20-Poly1305 and also exercise GCM
    // AAD
    private static final byte[] AAD = new byte[] { 0x01 };

    // Nicely print a spec
    private static String labelOf(AlgorithmKeySpec spec) {
        if (spec instanceof Describable d) {
            return d.description();
        }
        return spec.getClass().getSimpleName();
    }

    // --- generic vectors over all KEMs we support (compile-time known) ---
    static Stream<Arguments> vectors() {
        List<Arguments> out = new ArrayList<>();

        // 1) ML-KEM (Kyber)
        var kybers = new KyberKeyGenSpec[] { KyberKeyGenSpec.kyber512(), KyberKeyGenSpec.kyber768(),
                KyberKeyGenSpec.kyber1024() };
        for (var spec : kybers) {
            for (var m : MODES) {
                out.add(Arguments.of("ML-KEM", spec, m, "ML-KEM:" + labelOf(spec) + " · " + m));
            }
        }

        // 2) NTRU (HPS/HRSS)
        var ntrus = new NtruKeyGenSpec[] { NtruKeyGenSpec.hps2048_509(), NtruKeyGenSpec.hps2048_677(),
                NtruKeyGenSpec.hps4096_821(), NtruKeyGenSpec.hps4096_1229(), NtruKeyGenSpec.hrss701(),
                NtruKeyGenSpec.hrss1373() };
        for (var spec : ntrus) {
            for (var m : MODES) {
                out.add(Arguments.of("NTRU", spec, m, "NTRU:" + labelOf(spec) + " · " + m));
            }
        }

        // 3) Classic McEliece (CMCE)
        var cmces = new CmceKeyGenSpec[] { CmceKeyGenSpec.mceliece348864(), CmceKeyGenSpec.mceliece348864f(),
                CmceKeyGenSpec.mceliece460896(), CmceKeyGenSpec.mceliece460896f(), CmceKeyGenSpec.mceliece6688128(),
                CmceKeyGenSpec.mceliece6688128f(), CmceKeyGenSpec.mceliece6960119(), CmceKeyGenSpec.mceliece6960119f(),
                CmceKeyGenSpec.mceliece8192128(), CmceKeyGenSpec.mceliece8192128f() };
        for (var spec : cmces) {
            for (var m : MODES) {
                out.add(Arguments.of("CMCE", spec, m, "CMCE:" + labelOf(spec) + " · " + m));
            }
        }

        // 4) FrodoKEM
        var frodos = new FrodoKeyGenSpec[] { FrodoKeyGenSpec.frodo640aes(), FrodoKeyGenSpec.frodo640shake(),
                FrodoKeyGenSpec.frodo976aes(), FrodoKeyGenSpec.frodo976shake(), FrodoKeyGenSpec.frodo1344aes(),
                FrodoKeyGenSpec.frodo1344shake() };
        for (var spec : frodos) {
            for (var m : MODES) {
                out.add(Arguments.of("Frodo", spec, m, "Frodo:" + labelOf(spec) + " · " + m));
            }
        }

        // 5) SABER
        var sabers = new SaberKeyGenSpec[] { SaberKeyGenSpec.lightsaberkem128r3(), SaberKeyGenSpec.saberkem128r3(),
                SaberKeyGenSpec.firesaberkem128r3(), SaberKeyGenSpec.lightsaberkem192r3(),
                SaberKeyGenSpec.saberkem192r3(), SaberKeyGenSpec.firesaberkem192r3(),
                SaberKeyGenSpec.lightsaberkem256r3(), SaberKeyGenSpec.saberkem256r3(),
                SaberKeyGenSpec.firesaberkem256r3() };
        for (var spec : sabers) {
            for (var m : MODES) {
                out.add(Arguments.of("SABER", spec, m, "SABER:" + labelOf(spec) + " · " + m));
            }
        }

        // 6) BIKE
        var bikes = new BikeKeyGenSpec[] { BikeKeyGenSpec.bike128(), BikeKeyGenSpec.bike192(),
                BikeKeyGenSpec.bike256() };
        for (var spec : bikes) {
            for (var m : MODES) {
                out.add(Arguments.of("BIKE", spec, m, "BIKE:" + labelOf(spec) + " · " + m));
            }
        }

        // 7) HQC
        var hqcs = new HqcKeyGenSpec[] { HqcKeyGenSpec.hqc128(), HqcKeyGenSpec.hqc192(), HqcKeyGenSpec.hqc256() };
        for (var spec : hqcs) {
            for (var m : MODES) {
                out.add(Arguments.of("HQC", spec, m, "HQC:" + labelOf(spec) + " · " + m));
            }
        }

        // 8) SNTRU Prime
        var sntrus = new SntruPrimeKeyGenSpec[] { SntruPrimeKeyGenSpec.sntrup653(), SntruPrimeKeyGenSpec.sntrup761(),
                SntruPrimeKeyGenSpec.sntrup857(), SntruPrimeKeyGenSpec.sntrup953(), SntruPrimeKeyGenSpec.sntrup1013(),
                SntruPrimeKeyGenSpec.sntrup1277() };
        for (var spec : sntrus) {
            for (var m : MODES) {
                out.add(Arguments.of("SNTRUPrime", spec, m, "SNTRUPrime:" + labelOf(spec) + " · " + m));
            }
        }

        // 9) NTRU LPRime
        var ntrul = new NtrulPrimeKeyGenSpec[] { NtrulPrimeKeyGenSpec.ntrulpr653(), NtrulPrimeKeyGenSpec.ntrulpr761(),
                NtrulPrimeKeyGenSpec.ntrulpr857(), NtrulPrimeKeyGenSpec.ntrulpr953(),
                NtrulPrimeKeyGenSpec.ntrulpr1013(), NtrulPrimeKeyGenSpec.ntrulpr1277() };
        for (var spec : ntrul) {
            for (var m : MODES) {
                out.add(Arguments.of("NTRULPRime", spec, m, "NTRULPRime:" + labelOf(spec) + " · " + m));
            }
        }

        return out.stream();
    }

    @ParameterizedTest(name = "{3}")
    @MethodSource("vectors")
    @zeroecho.core.annotation.DisplayName("KEM→symmetric (AES/ChaCha, single-thread) round-trip — generic")
    void kemRoundTripGeneric(String kemId, AlgorithmKeySpec keyGenSpec, String mode, String pretty) throws Exception {
        System.out.println("kemRoundTrip(" + pretty + ")");

        // produce a pseudo-random payload
        final int size = (128 * 1024) + 7;
        final byte[] input = new byte[size];
        new Random(123456789L).nextBytes(input);

        // keypair via generic registry path
        KeyPair kp = new zeroecho.sdk.ZeroEchoSession().keyBuilders().asymmetric().generateKeyPair(kemId, keyGenSpec);

        // encrypt
        DataContent enc = encryptStage(kemId, kp, mode);
        enc.setInput(new BytesContent(input));
        final byte[] encrypted;
        try (InputStream is = enc.getStream()) {
            encrypted = is.readAllBytes();
        }

        // decrypt
        DataContent dec = decryptStage(kemId, kp, mode);
        dec.setInput(new BytesContent(encrypted));
        final byte[] decrypted;
        try (InputStream is = dec.getStream()) {
            decrypted = is.readAllBytes();
        }

        System.out.println("... input size:     " + input.length);
        System.out.println("... encrypted size: " + encrypted.length);
        System.out.println("... decrypted size: " + decrypted.length);
        assertArrayEquals(input, decrypted, "round-trip mismatch");
        System.out.println("...ok");
    }

    private static DataContent encryptStage(String kemId, KeyPair kp, String mode) {
        KemDataContentBuilder kem = KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).kem(kemId).recipientPublic(kp.getPublic())
                .derivedKeyBytes(32); // AES-256 or ChaCha20 key

        switch (mode) {
            case "GCM": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader().withAad(AAD);
                return kem.withAes(aes).build(true);
            }
            case "CBC": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();
                return kem.withAes(aes).build(true);
            }
            case "CTR": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCtr().withHeader();
                return kem.withAes(aes).build(true);
            }
            case "CHACHA20-POLY1305": {
                ChaChaDataContentBuilder ch = ChaChaDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withAad(AAD) // non-empty → AEAD
                                                                                              // variant
                        .withHeader(); // carry nonce
                return kem.withChaCha(ch).build(true);
            }
            default:
                throw new IllegalArgumentException("Unknown mode: " + mode);
        }
    }

    private static DataContent decryptStage(String kemId, KeyPair kp, String mode) {
        KemDataContentBuilder kem = KemDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).kem(kemId).recipientPrivate(kp.getPrivate())
                .derivedKeyBytes(32);

        switch (mode) {
            case "GCM": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeGcm(128).withHeader().withAad(AAD);
                return kem.withAes(aes).build(false);
            }
            case "CBC": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCbcPkcs5().withHeader();
                return kem.withAes(aes).build(false);
            }
            case "CTR": {
                AesDataContentBuilder aes = AesDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).modeCtr().withHeader();
                return kem.withAes(aes).build(false);
            }
            case "CHACHA20-POLY1305": {
                ChaChaDataContentBuilder ch = ChaChaDataContentBuilder.builder(new zeroecho.sdk.ZeroEchoSession()).withAad(AAD).withHeader();
                return kem.withChaCha(ch).build(false);
            }
            default:
                throw new IllegalArgumentException("Unknown mode: " + mode);
        }
    }

    /** Simple byte-array source for the pipeline. */
    private static final class BytesContent implements PlainContent {
        private final byte[] data;

        BytesContent(byte[] data) {
            this.data = data;
        }

        @Override
        public InputStream getStream() throws IOException {
            return new ByteArrayInputStream(data);
        }
    }

    // Sanity: HKDF provider is available (exercise earlier utility)
    @org.junit.jupiter.api.Test
    void hkdfAvailable() {
        assertDoesNotThrow(() -> Kdf.hkdfSha256(new byte[] { 1, 2, 3 }, null, null, 32));
    }
}
