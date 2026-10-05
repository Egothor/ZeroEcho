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
import java.util.Objects;

import zeroecho.core.alg.sphincsplus.SphincsPlusKeyGenSpec.Mode;

import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * Key pair builder for the SPHINCS+ post-quantum signature scheme.
 *
 * <p>
 * {@code SphincsPlusKeyGenBuilder} integrates with the Bouncy Castle BC
 * provider to generate pure SLH-DSA key pairs. It maps high-level
 * {@link SphincsPlusKeyGenSpec} parameters (hash family, security level,
 * variant, and mode) to the appropriate
 * {@code org.bouncycastle.jcajce.spec.SLHDSAParameterSpec} constant.
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
 *     SphincsPlusKeyGenSpec.of("BC", SphincsPlusKeyGenSpec.Hash.SHA2,
 *         SphincsPlusKeyGenSpec.Security.L1_128, SphincsPlusKeyGenSpec.Variant.SMALL,
 *         SphincsPlusKeyGenSpec.Mode.SIMPLE);
 *
 * KeyPair kp = new SphincsPlusKeyGenBuilder().generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusKeyGenBuilder implements AsymmetricKeyPairGenerator<SphincsPlusKeyGenSpec> {
    private static final String LEGACY_PROVIDER = "BCPQC";

    private static final String ALG = "SLH-DSA";

    /** Creates a stateless SPHINCS+ key-pair generator. */
    public SphincsPlusKeyGenBuilder() {
        // Stateless generator.
    }

    /**
     * Generates a pure SLH-DSA key pair for the SPHINCS+ compatibility binding.
     *
     * <p>
     * The method resolves the corresponding Bouncy Castle
     * {@code SLHDSAParameterSpec} constant via reflection and initializes a
     * {@link KeyPairGenerator}. If {@link SphincsPlusKeyGenSpec#providerName()} is
     * non-null, the generator is obtained from that provider.
     * </p>
     *
     * @param spec the key generation specification, including hash family, security
     *             level, variant, and mode
     * @return a freshly generated SPHINCS+ {@link KeyPair}
     * @throws NullPointerException     if {@code spec} is {@code null}
     * @throws IllegalArgumentException if ROBUST, HARAKA, BCPQC or an unsupported
     *                                  explicit parameter constant is requested
     * @throws GeneralSecurityException if the parameter spec cannot be resolved or
     *                                  if the provider fails to generate a key pair
     */
    @Override
    public KeyPair generateKeyPair(SphincsPlusKeyGenSpec spec) throws GeneralSecurityException {
        Objects.requireNonNull(spec, "spec");
        if (LEGACY_PROVIDER.equals(spec.providerName())) {
            throw new IllegalArgumentException("Legacy BCPQC SPHINCS+ generation is unsupported");
        }
        // Resolve BC SLHDSAParameterSpec via reflection by constant name(s)
        Object bcParamSpec = resolveBcParameterSpec(spec);

        KeyPairGenerator kpg = (spec.providerName() == null) ? KeyPairGenerator.getInstance(ALG)
                : KeyPairGenerator.getInstance(ALG, spec.providerName());
        if (bcParamSpec != null) {
            kpg.initialize((java.security.spec.AlgorithmParameterSpec) bcParamSpec);
        }
        return kpg.generateKeyPair();
    }

    /**
     * Resolves the Bouncy Castle {@code SLHDSAParameterSpec} constant that
     * corresponds to the given high-level {@link SphincsPlusKeyGenSpec}.
     *
     * <p>
     * SPHINCS+ was standardized as SLH-DSA (FIPS 205). The {@link Mode}
     * ROBUST construction and {@link SphincsPlusKeyGenSpec.Hash#HARAKA} have
     * no supported SLH-DSA mapping and are rejected, including with an override.
     * SIMPLE selects the current SLH-DSA compatibility binding, not a conversion
     * of legacy SPHINCS+ keys or signatures.
     * </p>
     *
     * <p>
     * If {@link SphincsPlusKeyGenSpec#explicitParamConstant()} is set, that field
     * name is looked up directly on {@code org.bouncycastle.jcajce.spec.SLHDSAParameterSpec}.
     * </p>
     *
     * @param spec the key generation specification
     * @return a matching {@code SLHDSAParameterSpec} instance
     * @throws IllegalArgumentException if a legacy mode or unsupported constant is requested
     * @throws GeneralSecurityException if no provider constant is found
     */
    private static Object resolveBcParameterSpec(SphincsPlusKeyGenSpec spec) throws GeneralSecurityException {
        if (spec.mode() != Mode.SIMPLE || spec.hash() == SphincsPlusKeyGenSpec.Hash.HARAKA) {
            throw new IllegalArgumentException("ROBUST and HARAKA are not supported by the SLH-DSA binding");
        }
        if (spec.explicitParamConstant() != null) {
            if (!spec.explicitParamConstant().matches("slh_dsa_(sha2|shake)_(128|192|256)[fs]")) {
                throw new IllegalArgumentException("Unsupported SLH-DSA parameter constant");
            }
            Object c = fetchStaticField("org.bouncycastle.jcajce.spec.SLHDSAParameterSpec",
                    spec.explicitParamConstant());
            if (c != null) {
                return c;
            }
            throw new GeneralSecurityException(
                    "Unknown SLHDSAParameterSpec constant: " + spec.explicitParamConstant());
        }

        String fam = (spec.hash() == SphincsPlusKeyGenSpec.Hash.SHA2) ? "sha2" : "shake";
        String bits = Integer.toString(spec.security().bits);
        String v = (spec.variant() == SphincsPlusKeyGenSpec.Variant.FAST) ? "f" : "s";
        // SIMPLE identifies the current pure SLH-DSA compatibility binding.
        String name = "slh_dsa_" + fam + "_" + bits + v;

        Object c = fetchStaticField("org.bouncycastle.jcajce.spec.SLHDSAParameterSpec", name);
        if (c != null) {
            return c;
        }
        throw new GeneralSecurityException("Cannot resolve SLHDSAParameterSpec constant: " + name);
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
