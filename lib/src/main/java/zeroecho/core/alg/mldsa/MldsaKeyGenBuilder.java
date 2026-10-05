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
package zeroecho.core.alg.mldsa;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Locale;
import java.util.Objects;

import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * Key pair builder for ML-DSA (FIPS 204) using the Bouncy Castle provider.
 *
 * <p>
 * This builder maps {@link MldsaKeyGenSpec} to the appropriate
 * {@code org.bouncycastle.jcajce.spec.MLDSAParameterSpec} constant. Reflection
 * is used to avoid a hard dependency on any particular set of parameter
 * constants across provider versions.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaKeyGenBuilder implements AsymmetricKeyPairGenerator<MldsaKeyGenSpec> {

    private static final String ALG_PURE = "MLDSA";
    private static final String ALG_SHA512 = "SHA512withMLDSA";

    /** Creates a stateless ML-DSA key-pair generator. */
    public MldsaKeyGenBuilder() {
        // Stateless generator.
    }

    /**
     * Generates a key pair according to the given specification.
     *
     * @param spec key generation specification
     * @return generated key pair
     * @throws GeneralSecurityException if the JCA engine cannot be initialized or
     *                                  the parameter set is unknown
     */
    @Override
    public KeyPair generateKeyPair(MldsaKeyGenSpec spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec");
        Object bcParamSpec = resolveBcParameterSpec(spec);

        String kpgAlg = (spec.preHash() == MldsaKeyGenSpec.PreHash.SHA512) ? ALG_SHA512 : ALG_PURE;

        KeyPairGenerator kpg = (spec.providerName() == null) ? KeyPairGenerator.getInstance(kpgAlg)
                : KeyPairGenerator.getInstance(kpgAlg, spec.providerName());

        if (bcParamSpec != null) {
            kpg.initialize((java.security.spec.AlgorithmParameterSpec) bcParamSpec);
        }
        return kpg.generateKeyPair();
    }

    private static Object resolveBcParameterSpec(MldsaKeyGenSpec spec) throws GeneralSecurityException {
        if (spec.explicitParamConstant() != null) {
            Object c = fetchStaticField("org.bouncycastle.jcajce.spec.MLDSAParameterSpec",
                    spec.explicitParamConstant());
            if (c != null) {
                return c;
            }
            throw new GeneralSecurityException("Unknown MLDSAParameterSpec constant: " + spec.explicitParamConstant());
        }

        String base = "ml_dsa_" + Integer.toString(spec.parameterSet().number);

        String suffix = "";
        if (spec.preHash() != MldsaKeyGenSpec.PreHash.NONE) {
            suffix = "_with_" + spec.preHash().name().toLowerCase(Locale.ROOT);
        }

        String name = base + suffix;

        // Fail fast if we detect clearly unsupported pre-hash requests.
        validateCombination(spec);

        Object c = fetchStaticField("org.bouncycastle.jcajce.spec.MLDSAParameterSpec", name);
        if (c != null) {
            return c;
        }

        // Fallback: attempt base (no pre-hash), then fail.
        if (!suffix.isEmpty()) {
            Object baseC = fetchStaticField("org.bouncycastle.jcajce.spec.MLDSAParameterSpec", base);
            if (baseC != null) {
                return baseC;
            }
        }

        throw new GeneralSecurityException("Cannot resolve MLDSAParameterSpec constant: " + name);
    }

    private static void validateCombination(MldsaKeyGenSpec spec) throws GeneralSecurityException {
        if (spec.preHash() == MldsaKeyGenSpec.PreHash.NONE) {
            return;
        }
        if (spec.preHash() != MldsaKeyGenSpec.PreHash.SHA512) {
            throw new GeneralSecurityException("ML-DSA supports only PreHash.NONE or PreHash.SHA512.");
        }
    }

    private static Object fetchStaticField(String className, String field) {
        try {
            Class<?> cls = Class.forName(className);
            Field f = cls.getField(field);
            return f.get(null);
        } catch (ReflectiveOperationException e) {
            System.getLogger(MldsaKeyGenBuilder.class.getName()).log(System.Logger.Level.DEBUG,
                    "Static field {0}.{1} not found — provider may not support this algorithm parameter",
                    className, field);
            return null;
        }
    }
}
