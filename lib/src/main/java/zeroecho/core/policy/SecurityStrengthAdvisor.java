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
package zeroecho.core.policy;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;

/**
 * Estimates conservative security strength in bits for a given algorithm
 * identifier and key.
 *
 * <p>
 * {@code SecurityStrengthAdvisor} normalizes an algorithm family name (for
 * example, "RSA", "AES", "HMAC", "ML-KEM", "SPHINCS+") and inspects the
 * provided key to infer an approximate strength in bits. The mappings are
 * deliberately coarse and favor safe lower bounds over optimistic assumptions.
 * </p>
 *
 * <h2>How estimation works</h2>
 * <ul>
 * <li><b>RSA / ElGamal (FF-DL):</b> uses the modulus size to map to NIST-like
 * strengths (for example, 2048 -> ~112, 3072 -> ~128, 7680 -> ~192, 15360 ->
 * ~256).</li>
 * <li><b>AES:</b> uses the secret key size (128/192/256) when available;
 * otherwise assumes 128.</li>
 * <li><b>HMAC:</b> strength is {@code min(key bits, hash output bits)};
 * attempts to parse the underlying SHA variant from {@code key.getAlgorithm()}
 * (for example, HmacSHA256 -> 256 output bits). If unknown or opaque, caps at a
 * conservative 256.</li>
 * <li><b>Post-quantum KEMs (ML-KEM/Kyber, FrodoKEM, Saber, BIKE, HQC, CMCE,
 * NTRU families):</b> tries to extract parameters either from numeric hints in
 * {@code key.getAlgorithm()} (for example, 512, 768, 1024 for ML-KEM;
 * 640/976/1344 for FrodoKEM) or from NIST security levels labeled as L1/L3/L5.
 * If neither is present, defaults to 128.</li>
 * <li><b>ML-DSA</b>: estimated from the parameter set markers (44/65/87 mapped
 * to 128/192/256, or L1/L3/L5).</li>
 * <li><b>SLH-DSA:</b> parse 128/192/256 from {@code key.getAlgorithm()}
 * similarly to SPHINCS+; else default 128.</li>
 * <li><b>SPHINCS+:</b> parses the parameter size 128/192/256 from the algorithm
 * string; otherwise defaults to 128.</li>
 * <li><b>EdDSA:</b> returns fixed strengths (Ed25519 -> 128, Ed448 ->
 * 224).</li>
 * <li><b>Digest-only and unknown families:</b> returns a conservative 128.</li>
 * </ul>
 *
 * <h2>Inputs and parsing</h2>
 * <ul>
 * <li>The {@code algoId} argument selects the family mapping. It should be a
 * stable id such as "RSA", "AES", "HMAC", "ML-KEM", "SPHINCS+".</li>
 * <li>When applicable, {@code key.getAlgorithm()} is scanned for numeric tokens
 * or level markers like "L1", "L3", "L5" to refine the estimate.</li>
 * <li>Opaque keys or provider-specific names may limit visibility; in such
 * cases, the result intentionally errs on the conservative side.</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>These values are heuristic, implementation-agnostic estimates for policy
 * gating and coarse comparisons. They are not a substitute for a full
 * cryptographic review.</li>
 * <li>When in doubt, the advisor returns at least 128 bits to avoid accidental
 * underestimation in modern deployments.</li>
 * </ul>
 *
 * <h2>Examples</h2> <pre>{@code
 * // AES-256 secret key
 * int s1 = SecurityStrengthAdvisor.estimateBits("AES", secretKey256);   // -> 256
 *
 * // RSA 3072-bit public key
 * int s2 = SecurityStrengthAdvisor.estimateBits("RSA", rsa3072Pub);     // -> 128
 *
 * // ML-KEM-768 (Kyber768) as indicated in key algorithm string
 * int s3 = SecurityStrengthAdvisor.estimateBits("ML-KEM", kemKey768);   // -> 192
 *
 * // HmacSHA256 with a 160-bit key (not recommended)
 * int s4 = SecurityStrengthAdvisor.estimateBits("HMAC", shortHmacKey);  // -> min(160, 256) = 160
 * }</pre>
 *
 * <h2>Thread-safety</h2> This utility is stateless and thread-safe.
 *
 * @since 1.0
 */
public final class SecurityStrengthAdvisor { // NOPMD

    private static final Pattern NUMBER_PATTERN = Pattern.compile("(\\d{2,5})");
    private static final Pattern LEVEL_PATTERN = Pattern.compile("(?:^|[^A-Za-z])(L[135])(?:[^A-Za-z]|$)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SPHINCS_STRENGTH_PATTERN = Pattern.compile("(128|192|256)");
    private static final Pattern HMAC_SHA_PATTERN = Pattern.compile("HMAC(?:-)?SHA(?:-)?(1|224|256|384|512)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SLHDSA_STRENGTH_PATTERN = Pattern.compile("(128|192|256)");
    private static final Pattern MLDSA_SET_PATTERN = Pattern.compile("(44|65|87)");

    private SecurityStrengthAdvisor() {
    }

    /**
     * Estimates the security strength in bits for a given algorithm family id and
     * key.
     *
     * <p>
     * The method first normalizes {@code algoId} to select a family-specific
     * mapping. It then inspects the {@code key} (for example, modulus bit length
     * for RSA; encoded length for AES {@code SecretKey}; hash output size inferred
     * from HMAC algorithm name; parameter levels for post-quantum schemes) to
     * compute a conservative estimate.
     * </p>
     *
     * @param algoId algorithm family identifier such as "RSA", "AES", "HMAC",
     *               "ML-KEM", "SPHINCS+"
     * @param key    key instance to inspect; may be opaque for some providers
     * @return estimated security strength in bits; never negative
     */
    public static int estimateBits(String algoId, Key key) { // NOPMD
        final String id = (algoId == null ? "" : algoId).toUpperCase(Locale.ROOT);

        return switch (id) {
            case "RSA", "ELGAMAL" -> rsaLikeStrength(modulusBits(key));
            case "AES" -> aesStrengthBits(key);
            case "HMAC" -> hmacStrengthBits(key);
            case "ED25519" -> 128;
            case "ED448" -> 224;
            case "ML-KEM" -> kyberStrength(key);
            case "ML-DSA", "MLDSA" -> mldsaStrength(key);
            case "BIKE" -> mapByNistLevel(key, 128, 192, 256);
            case "HQC" -> mapByNistLevel(key, 128, 192, 256);
            case "FRODO" -> frodoStrength(key);
            case "SABER" -> saberStrength(key);
            case "CMCE" -> mcelieceStrength(key);
            case "NTRU" -> ntruStrength(key);
            case "SNTRUPRIME" -> sntruPrimeStrength(key);
            case "NTRULPRIME" -> ntruLPrimeStrength(key);
            case "SLH-DSA", "SLHDSA" -> slhDsaStrength(key);
            case "SPHINCS+", "SPHINCSPLUS" -> sphincsPlusStrength(key);
            case "DIGEST" -> 128;
            default -> 128;
        };
    }

    private static int modulusBits(Key key) {
        return switch (key) {
            case RSAPublicKey r -> r.getModulus().bitLength();
            case RSAPrivateKey r -> r.getModulus().bitLength();
            case null, default -> 0;
        };
    }

    private static int rsaLikeStrength(int nBits) {
        // Coarse NIST-like mapping for RSA/FF-DL:
        // 2048 -> ~112, 3072 -> ~128, 7680 -> ~192, 15360 -> ~256
        return (nBits >= 15_360) ? 256
                : (nBits >= 7680) ? 192 : (nBits >= 3072) ? 128 : (nBits >= 2048) ? 112 : (nBits >= 1024) ? 80 : 64;
    }

    private static int aesStrengthBits(Key key) {
        int kb = secretKeyBitsOrZero(key);
        // If we cannot see the key bytes or it is non-standard, assume conservative 128
        return (kb >= 256) ? 256 : (kb >= 192) ? 192 : (kb >= 128) ? 128 : 128;
    }

    private static int hmacStrengthBits(Key key) {
        // Strength ≈ min(key bits, hash output bits). Try to detect the hash from
        // algorithm name.
        final int keyBits = secretKeyBitsOrZero(key);

        final String algo = (key != null && key.getAlgorithm() != null) ? key.getAlgorithm() : "";
        final Matcher m = HMAC_SHA_PATTERN.matcher(algo);

        int hashOut = 0;
        if (m.find()) {
            final String grp = m.group(1);
            hashOut = switch (grp) {
                case "1" -> 160; // SHA-1
                case "224" -> 224;
                case "256" -> 256;
                case "384" -> 384;
                case "512" -> 512;
                default -> 0; // unknown/other SHA size, fall back below
            };
        }

        if (hashOut == 0) {
            // Unknown underlying hash; assume 256-bit output for modern HMACs
            hashOut = 256;
        }

        if (keyBits == 0) {
            // If key length is opaque, cap by 256 (typical)
            return Math.min(256, hashOut);
        }
        return Math.min(keyBits, hashOut);
    }

    private static int kyberStrength(Key key) {
        // Try to parse ML-KEM-512/768/1024 from key.getAlgorithm()
        String a = safeAlgo(key);
        Matcher m = NUMBER_PATTERN.matcher(a);
        while (m.find()) {
            int v = parseIntSafe(m.group(1));
            switch (v) {
                case 512:
                    return 128; // NIST Level 1
                case 768:
                    return 192; // NIST Level 3
                case 1024:
                    return 256; // NIST Level 5
                default: // keep searching / fall back later
            }
        }

        // Fall back to L-level if present
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }

        // Conservative fallback
        return 128;
    }

    private static int frodoStrength(Key key) {
        // Common FrodoKEM sizes: 640 (L1 ~128), 976 (L3 ~192), 1344 (L5 ~256)
        String a = safeAlgo(key);
        Matcher m = NUMBER_PATTERN.matcher(a);
        while (m.find()) {
            int v = parseIntSafe(m.group(1));
            switch (v) {
                case 640:
                    return 128; // Level 1
                case 976:
                    return 192; // Level 3
                case 1344:
                    return 256; // Level 5
                default: // keep scanning further matches
            }
        }
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }
        return 128;
    }

    private static int saberStrength(Key key) {
        // LightSaber (L1 128), Saber (L3 192), FireSaber (L5 256)
        String a = safeAlgo(key);
        String lower = a.toLowerCase(Locale.ROOT);
        if (lower.contains("lightsaber")) {
            return 128;
        }
        if (lower.contains("firesaber")) {
            return 256;
        }
        if (lower.contains("saber")) {
            return 192; // plain "Saber"
        }
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }
        return 128;
    }

    private static int mcelieceStrength(Key key) {
        // Classic McEliece parameter sets target L1/L3/L5; default 128 without detail.
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }
        return 128;
    }

    private static int ntruStrength(Key key) {
        // Heuristic: many NTRU variants map to L1/L3/L5 families.
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }

        // Try to parse numeric hints like 509/677/701 (commonly L1/L3/L5-ish across
        // families)
        String a = safeAlgo(key);
        Matcher m = NUMBER_PATTERN.matcher(a);
        while (m.find()) {
            int v = parseIntSafe(m.group(1));
            switch (v) {
                case 509:
                    return 128; // L1-ish
                case 677:
                    return 192; // L3-ish
                case 701:
                    return 256; // L5-ish
                default: // keep scanning other numbers
            }
        }

        // Conservative default
        return 128;
    }

    private static int sntruPrimeStrength(Key key) {
        // SNTRU Prime families also align to L1/L3/L5; prefer explicit levels if
        // present.
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        return (byLevel == 0) ? 128 : byLevel;
    }

    private static int ntruLPrimeStrength(Key key) {
        // NTRU LPRime: map by L1/L3/L5 when present, else conservative.
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        return (byLevel == 0) ? 128 : byLevel;
    }

    private static int sphincsPlusStrength(Key key) {
        // Try to parse 128/192/256 from the parameter set name (e.g.,
        // SPHINCS+-SHA2-128s, -192f, -256s)
        String a = safeAlgo(key);
        Matcher m = SPHINCS_STRENGTH_PATTERN.matcher(a);
        if (m.find()) {
            int v = parseIntSafe(m.group(1));
            if (v == 128 || v == 192 || v == 256) {
                return v;
            }
        }
        // Fallback if the parameter size is unknown
        return 128;
    }

    private static int slhDsaStrength(Key key) {
        // Provider strings observed: "SLH-DSA-SHAKE-128S", "slh-dsa-sha2-192f",
        // sometimes with separators or additional tokens. We normalize and then parse.
        String a = safeAlgo(key);
        String normalized = a.toLowerCase(Locale.ROOT).replace('_', '-');

        // Prefer explicit numeric strength markers (128/192/256) in the algorithm name.
        Matcher m = SLHDSA_STRENGTH_PATTERN.matcher(normalized);
        if (m.find()) {
            int v = parseIntSafe(m.group(1));
            if (v == 128 || v == 192 || v == 256) {
                return v;
            }
        }

        // Fall back to L1/L3/L5 markers when present.
        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }

        // Conservative default.
        return 128;
    }

    private static int mapByNistLevel(Key key, int l1, int l3, int l5) {
        String a = safeAlgo(key);

        // Try explicit L1/L3/L5 markers
        Matcher lm = LEVEL_PATTERN.matcher(a);
        if (lm.find()) {
            String lvl = lm.group(1).toUpperCase(Locale.ROOT);
            switch (lvl) {
                case "L1":
                    return l1;
                case "L3":
                    return l3;
                case "L5":
                    return l5;
                default:
                    // no action, continue with numeric fallback
            }
        }

        // Also consider bare numbers sometimes used instead of 'Lx'
        Matcher nm = NUMBER_PATTERN.matcher(a);
        while (nm.find()) {
            int v = parseIntSafe(nm.group(1));
            switch (v) {
                case 1, 128:
                    return l1;
                case 3, 192:
                    return l3;
                case 5, 256:
                    return l5;
                default:
                    // keep scanning
            }
        }

        return 0;
    }

    private static int secretKeyBitsOrZero(Key key) {
        if (key instanceof SecretKey) {
            byte[] enc = key.getEncoded();
            if (enc != null) {
                return enc.length * 8;
            }
        }
        return 0;
    }

    private static String safeAlgo(Key key) {
        String algo = (key != null && key.getAlgorithm() != null) ? key.getAlgorithm() : "";
        return algo == null ? "" : algo;
    }

    private static int parseIntSafe(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static int mldsaStrength(Key key) {
        String a = safeAlgo(key);
        String normalized = a.toLowerCase(Locale.ROOT).replace('_', '-');

        Matcher m = MLDSA_SET_PATTERN.matcher(normalized);
        if (m.find()) {
            int set = parseIntSafe(m.group(1));
            return switch (set) {
                case 44 -> 128;
                case 65 -> 192;
                case 87 -> 256;
                default -> 128;
            };
        }

        int byLevel = mapByNistLevel(key, 128, 192, 256);
        if (byLevel != 0) {
            return byLevel;
        }

        return 128;
    }
}
