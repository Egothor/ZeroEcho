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
package zeroecho.core.alg.slhdsa;

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
 * SLH-DSA (FIPS 205) signature algorithm binding for the ZeroEcho framework.
 *
 * <p>
 * SLH-DSA is the NIST-standardized profile of the SPHINCS+ stateless hash-based
 * signature scheme. This binding exposes SLH-DSA as a first-class algorithm
 * identity while relying on the provider's SLH-DSA JCA implementations.
 * </p>
 *
 * <p>
 * This algorithm registers two roles:
 * </p>
 * <ul>
 * <li>{@link KeyUsage#SIGN}: produces SLH-DSA signatures using a
 * {@link PrivateKey}.</li>
 * <li>{@link KeyUsage#VERIFY}: verifies SLH-DSA signatures using a
 * {@link PublicKey}.</li>
 * </ul>
 *
 * <p>
 * Both roles are configured with {@link VoidSpec}, as SLH-DSA requires no
 * runtime context parameters beyond the key material.
 * </p>
 *
 * @since 1.0
 */
public final class SlhDsaAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());

    /**
     * Creates a new SLH-DSA algorithm instance and registers its capabilities.
     *
     * @throws IllegalArgumentException if a signature context cannot be initialized
     *                                  due to provider errors
     */
    public SlhDsaAlgorithm() {
        super("SLH-DSA", "SLHDSA");

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> {
                    try {
                        return new SlhDsaSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init SLH-DSA signer", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new SlhDsaSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init SLH-DSA verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(SlhDsaKeyGenSpec.class, new SlhDsaKeyGenBuilder(),
                SlhDsaKeyGenSpec::defaultSpec);
        registerPublicKeyImporter(SlhDsaPublicKeySpec.class, new SlhDsaPublicKeyBuilder());
        registerPrivateKeyImporter(SlhDsaPrivateKeySpec.class, new SlhDsaPrivateKeyBuilder());
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-128f",  "SLH-DSA-SHA2-128f (NIST L1)",  SecurityLevel.nist(1, 128), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-128s",  "SLH-DSA-SHA2-128s (NIST L1)",  SecurityLevel.nist(1, 128), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-192f",  "SLH-DSA-SHA2-192f (NIST L3)",  SecurityLevel.nist(3, 192), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-192s",  "SLH-DSA-SHA2-192s (NIST L3)",  SecurityLevel.nist(3, 192), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-256f",  "SLH-DSA-SHA2-256f (NIST L5)",  SecurityLevel.nist(5, 256), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHA2-256s",  "SLH-DSA-SHA2-256s (NIST L5)",  SecurityLevel.nist(5, 256), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHA2,  SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f (NIST L1)", SecurityLevel.nist(1, 128), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s (NIST L1)", SecurityLevel.nist(1, 128), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L1_128, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f (NIST L3)", SecurityLevel.nist(3, 192), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s (NIST L3)", SecurityLevel.nist(3, 192), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L3_192, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f (NIST L5)", SecurityLevel.nist(5, 256), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.FAST,  SlhDsaKeyGenSpec.PreHash.NONE)),
            new ParameterSetDescriptor.Concrete<>("SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s (NIST L5)", SecurityLevel.nist(5, 256), SlhDsaKeyGenSpec.of("BC", SlhDsaKeyGenSpec.Hash.SHAKE, SlhDsaKeyGenSpec.Security.L5_256, SlhDsaKeyGenSpec.Variant.SMALL, SlhDsaKeyGenSpec.PreHash.NONE))
        );
    }

}
