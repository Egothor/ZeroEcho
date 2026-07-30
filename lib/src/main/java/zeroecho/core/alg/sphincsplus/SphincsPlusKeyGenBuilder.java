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
package zeroecho.core.alg.sphincsplus;

import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Locale;
import java.util.Objects;

import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * Key pair builder for the SPHINCS+ post-quantum signature scheme.
 *
 * <p>
 * {@code SphincsPlusKeyGenBuilder} integrates with the Bouncy Castle PQC
 * provider to generate key pairs for SPHINCS+. It maps high-level
 * {@link SphincsPlusKeyGenSpec} parameters (hash family, security level,
 * variant, and mode) to the appropriate
 * {@code org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec} constant.
 * Reflection is used to avoid a hard dependency on all parameter variants.
 * </p>
 *
 * <p>
 * The exact supported operation is
 * {@link #generateKeyPair(SphincsPlusKeyGenSpec)}. Public and private import
 * are registered separately for {@link SphincsPlusPublicKeySpec} and
 * {@link SphincsPlusPrivateKeySpec}.
 * </p>
 *
 * <h2>Example</h2> <pre>{@code
 * SphincsPlusKeyGenSpec spec =
 *     SphincsPlusKeyGenSpec.sphincsPlusSha2_128s_robust();
 *
 * KeyPair kp = new SphincsPlusKeyGenBuilder().generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusKeyGenBuilder implements AsymmetricKeyPairGenerator<SphincsPlusKeyGenSpec> {

    private static final String ALG = "SPHINCSPlus";

    /**
     * Generates a SPHINCS+ key pair using the given specification.
     *
     * <p>
     * The method resolves the corresponding Bouncy Castle
     * {@code SPHINCSPlusParameterSpec} constant via reflection and initializes a
     * {@link KeyPairGenerator}. If {@link SphincsPlusKeyGenSpec#providerName()} is
     * non-null, the generator is obtained from that provider.
     * </p>
     *
     * @param spec the key generation specification, including hash family, security
     *             level, variant, and mode
     * @return a freshly generated SPHINCS+ {@link KeyPair}
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws GeneralSecurityException if the parameter spec cannot be resolved or
     *                                  if the provider fails to generate a key pair
     */
    @Override
    public KeyPair generateKeyPair(SphincsPlusKeyGenSpec spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec");
        // Resolve BC SPHINCSPlusParameterSpec via reflection by constant name(s)
        Object bcParamSpec = resolveBcParameterSpec(spec);

        KeyPairGenerator kpg = (spec.providerName() == null) ? KeyPairGenerator.getInstance(ALG)
                : KeyPairGenerator.getInstance(ALG, spec.providerName());
        if (bcParamSpec != null) {
            kpg.initialize((java.security.spec.AlgorithmParameterSpec) bcParamSpec);
        }
        return kpg.generateKeyPair();
    }

    /**
     * Resolves the Bouncy Castle parameter spec constant that corresponds to the
     * given high-level {@link SphincsPlusKeyGenSpec}.
     *
     * <p>
     * Preferred constant names follow the convention:
     * {@code {sha2|shake|haraka}_{128|192|256}{f|s}_{robust|simple}}. Legacy names
     * without a suffix (e.g., {@code sha2_128f}) are also tried for robust mode.
     * </p>
     *
     * @param spec the key generation specification
     * @return a matching {@code SPHINCSPlusParameterSpec} instance
     * @throws GeneralSecurityException if no matching constant is found
     */
    private static Object resolveBcParameterSpec(SphincsPlusKeyGenSpec spec) throws GeneralSecurityException {
        // explicit override by constant name
        if (spec.explicitParamConstant() != null) {
            Object c = fetchStaticField("org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec",
                    spec.explicitParamConstant());
            if (c != null) {
                return c;
            }
            throw new GeneralSecurityException(
                    "Unknown SPHINCSPlusParameterSpec constant: " + spec.explicitParamConstant());
        }

        String fam = switch (spec.hash()) {
            case SHA2 -> "sha2";
            case SHAKE -> "shake";
            case HARAKA -> "haraka";
        };
        String bits = Integer.toString(spec.security().bits);
        String v = (spec.variant() == SphincsPlusKeyGenSpec.Variant.FAST) ? "f" : "s";

        // candidates in order
        final String[] names;
        if (spec.mode() == SphincsPlusKeyGenSpec.Mode.ROBUST) {
            names = new String[] { fam + "_" + bits + v + "_robust", // new (robust-explicit)
                    fam + "_" + bits + v // legacy (robust default)
            };
        } else {
            names = new String[] { fam + "_" + bits + v + "_simple" };
        }

        for (String n : names) {
            Object c = fetchStaticField("org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec", n);
            if (c != null) {
                return c;
            }
        }
        throw new GeneralSecurityException("Cannot resolve SPHINCSPlusParameterSpec for " + fam + "_" + bits + v + " ("
                + spec.mode().name().toLowerCase(Locale.ROOT) + ")");
    }

    /**
     * Attempts to fetch a static field by name from the given class.
     *
     * @param className fully qualified class name
     * @param field     the name of the static field to retrieve
     * @return the value of the field, or {@code null} if not found
     */
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
