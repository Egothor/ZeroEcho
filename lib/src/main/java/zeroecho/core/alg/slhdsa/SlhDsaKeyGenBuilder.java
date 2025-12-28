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
package zeroecho.core.alg.slhdsa;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Locale;
import java.util.Objects;

import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * Key pair builder for SLH-DSA (FIPS 205) using the Bouncy Castle PQC provider.
 *
 * <p>
 * This builder maps {@link SlhDsaKeyGenSpec} to the appropriate
 * {@code org.bouncycastle.jcajce.spec.SLHDSAParameterSpec} constant. Reflection
 * is used to avoid a hard dependency on any particular set of parameter
 * constants across provider versions.
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaKeyGenBuilder implements AsymmetricKeyBuilder<SlhDsaKeyGenSpec> {

    private static final String ALG = "SLH-DSA";

    @Override
    public KeyPair generateKeyPair(SlhDsaKeyGenSpec spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec");
        Object bcParamSpec = resolveBcParameterSpec(spec);

        KeyPairGenerator kpg = (spec.providerName() == null) ? KeyPairGenerator.getInstance(ALG)
                : KeyPairGenerator.getInstance(ALG, spec.providerName());

        if (bcParamSpec != null) {
            kpg.initialize((java.security.spec.AlgorithmParameterSpec) bcParamSpec);
        }
        return kpg.generateKeyPair();
    }

    @Override
    public java.security.PublicKey importPublic(SlhDsaKeyGenSpec spec) {
        throw new UnsupportedOperationException("Use SlhDsaPublicKeySpec to import a public key.");
    }

    @Override
    public java.security.PrivateKey importPrivate(SlhDsaKeyGenSpec spec) {
        throw new UnsupportedOperationException("Use SlhDsaPrivateKeySpec to import a private key.");
    }

    private static Object resolveBcParameterSpec(SlhDsaKeyGenSpec spec) throws GeneralSecurityException {
        if (spec.explicitParamConstant() != null) {
            Object c = fetchStaticField("org.bouncycastle.jcajce.spec.SLHDSAParameterSpec",
                    spec.explicitParamConstant());
            if (c != null) {
                return c;
            }
            throw new GeneralSecurityException("Unknown SLHDSAParameterSpec constant: " + spec.explicitParamConstant());
        }

        String fam = (spec.hash() == SlhDsaKeyGenSpec.Hash.SHA2) ? "sha2" : "shake";
        String bits = Integer.toString(spec.security().bits);
        String v = (spec.variant() == SlhDsaKeyGenSpec.Variant.FAST) ? "f" : "s";

        // Base constant name: slh_dsa_{sha2|shake}_{128|192|256}{f|s}
        String base = "slh_dsa_" + fam + "_" + bits + v;

        // Optional pre-hash suffix used by BC:
        // _with_sha256/_with_sha512/_with_shake128/_with_shake256
        String suffix = "";
        if (spec.preHash() != SlhDsaKeyGenSpec.PreHash.NONE) {
            suffix = "_with_" + spec.preHash().name().toLowerCase(Locale.ROOT);
        }

        String name = base + suffix;

        // Validate supported combinations (fail fast with a clear message).
        validateCombination(spec);

        Object c = fetchStaticField("org.bouncycastle.jcajce.spec.SLHDSAParameterSpec", name);
        if (c != null) {
            return c;
        }

        // As a fallback, attempt base (no pre-hash), then fail.
        if (!suffix.isEmpty()) {
            Object baseC = fetchStaticField("org.bouncycastle.jcajce.spec.SLHDSAParameterSpec", base);
            if (baseC != null) {
                return baseC;
            }
        }

        throw new GeneralSecurityException("Cannot resolve SLHDSAParameterSpec constant: " + name);
    }

    private static void validateCombination(SlhDsaKeyGenSpec spec) throws GeneralSecurityException {
        SlhDsaKeyGenSpec.Hash h = spec.hash();
        int bits = spec.security().bits;
        SlhDsaKeyGenSpec.PreHash p = spec.preHash();

        if (p == SlhDsaKeyGenSpec.PreHash.NONE) {
            return;
        }

        if (h == SlhDsaKeyGenSpec.Hash.SHA2) {
            if (bits == 128 && p != SlhDsaKeyGenSpec.PreHash.SHA256) {
                throw new GeneralSecurityException("SLH-DSA SHA2-128 supports only PreHash.SHA256.");
            }
            if ((bits == 192 || bits == 256) && p != SlhDsaKeyGenSpec.PreHash.SHA512) {
                throw new GeneralSecurityException("SLH-DSA SHA2-192/256 support only PreHash.SHA512.");
            }
        } else {
            if (bits == 128 && p != SlhDsaKeyGenSpec.PreHash.SHAKE128) {
                throw new GeneralSecurityException("SLH-DSA SHAKE-128 supports only PreHash.SHAKE128.");
            }
            if ((bits == 192 || bits == 256) && p != SlhDsaKeyGenSpec.PreHash.SHAKE256) {
                throw new GeneralSecurityException("SLH-DSA SHAKE-192/256 support only PreHash.SHAKE256.");
            }
        }
    }

    private static Object fetchStaticField(String className, String field) {
        try {
            Class<?> cls = Class.forName(className);
            Field f = cls.getField(field);
            return f.get(null);
        } catch (ReflectiveOperationException e) {
            return null;
        }
    }
}