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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.VoidSpec;

/**
 * ML-DSA (FIPS 204) signature algorithm binding for the ZeroEcho framework.
 *
 * <p>
 * This binding exposes ML-DSA as a first-class algorithm identity while relying
 * on the provider's ML-DSA JCA implementations.
 * </p>
 *
 * <p>
 * This algorithm registers two roles:
 * </p>
 * <ul>
 * <li>{@link KeyUsage#SIGN}: produces ML-DSA signatures using a
 * {@link PrivateKey}.</li>
 * <li>{@link KeyUsage#VERIFY}: verifies ML-DSA signatures using a
 * {@link PublicKey}.</li>
 * </ul>
 *
 * <p>
 * Both roles are configured with {@link VoidSpec}, as ML-DSA requires no
 * runtime context parameters beyond the key material.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());

    /**
     * Creates a new ML-DSA algorithm instance and registers its capabilities.
     *
     * @throws IllegalArgumentException if a signature context cannot be initialized
     *                                  due to provider errors
     */
    public MldsaAlgorithm() {
        super("ML-DSA", "MLDSA");

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> {
                    try {
                        return new MldsaSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init ML-DSA signer", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new MldsaSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init ML-DSA verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(MldsaKeyGenSpec.class, new MldsaKeyGenBuilder(),
                MldsaKeyGenSpec::defaultSpec);
        registerPublicKeyImporter(MldsaPublicKeySpec.class, new MldsaPublicKeyBuilder());
        registerPrivateKeyImporter(MldsaPrivateKeySpec.class, new MldsaPrivateKeyBuilder());
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("ML-DSA-44", "ML-DSA-44 (NIST Level 2)", SecurityLevel.nist(2, 128), MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_44, MldsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("ML-DSA-65", "ML-DSA-65 (NIST Level 3)", SecurityLevel.nist(3, 192), MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_65, MldsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("ML-DSA-87", "ML-DSA-87 (NIST Level 5)", SecurityLevel.nist(5, 256), MldsaKeyGenSpec.of("BC", MldsaKeyGenSpec.ParameterSet.ML_DSA_87, MldsaKeyGenSpec.PreHash.NONE))
        );
    }

}
