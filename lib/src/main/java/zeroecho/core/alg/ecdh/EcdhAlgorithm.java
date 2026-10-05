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
package zeroecho.core.alg.ecdh;

import java.security.PrivateKey;
import java.security.interfaces.ECKey;

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.alg.common.agreement.GenericJcaAgreementContext;
import zeroecho.core.alg.common.agreement.GenericJcaMessageAgreementContext;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.alg.ecdsa.EcdsaCurveSpec;
import zeroecho.core.alg.ecdsa.EcdsaPrivateKeyBuilder;
import zeroecho.core.alg.ecdsa.EcdsaPrivateKeySpec;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeyBuilder;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeySpec;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;

/**
 * <h2>Elliptic Curve Diffie-Hellman (ECDH) Algorithm</h2>
 *
 * Implementation of the Elliptic Curve Diffie-Hellman key agreement scheme
 * within the ZeroEcho framework.
 *
 * <p>
 * ECDH allows two parties, each possessing an elliptic-curve key pair, to
 * derive a common shared secret over an insecure channel. Only the private key
 * of one party and the public key of the other are required to compute the same
 * shared value. This shared secret can then be expanded into symmetric session
 * keys.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>{@link AlgorithmFamily#AGREEMENT} with {@link KeyUsage#AGREEMENT}:
 * creates an {@link zeroecho.core.context.AgreementContext} from a local
 * {@link java.security.PrivateKey} and a peer's public key supplied through the
 * context.</li>
 * </ul>
 *
 * <h2>Key builders</h2>
 * <ul>
 * <li>{@link EcdhCurveSpec}: used to generate EC key pairs for ECDH; default is
 * {@code P-256}.</li>
 * <li>{@link EcdsaPublicKeySpec} and {@link EcdsaPrivateKeySpec}: reused for
 * importing elliptic-curve keys since ECDH and ECDSA share curve parameters and
 * encoding formats.</li>
 * </ul>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>The {@link EcdsaCurveSpec} parameter passed in the agreement capability
 * is currently ignored in this implementation (defaulting always to the curve
 * of the key itself). This is retained for API uniformity and may be enforced
 * in future versions.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Generate a key pair for Alice
 * KeyPair aliceKeys = session.keyBuilders().asymmetric().generateKeyPair("ECDH", EcdhCurveSpec.P256);
 *
 * // Generate a key pair for Bob
 * KeyPair bobKeys = session.keyBuilders().asymmetric().generateKeyPair("ECDH", EcdhCurveSpec.P256);
 *
 * // Alice computes shared secret using her private key
 * AgreementContext aliceCtx = session.createContext("ECDH",
 *         KeyUsage.AGREEMENT, aliceKeys.getPrivate(), EcdsaCurveSpec.P256);
 * byte[] aliceSecret = aliceCtx.derive(bobKeys.getPublic());
 *
 * // Bob computes shared secret using his private key
 * AgreementContext bobCtx = session.createContext("ECDH",
 *         KeyUsage.AGREEMENT, bobKeys.getPrivate(), EcdsaCurveSpec.P256);
 * byte[] bobSecret = bobCtx.derive(aliceKeys.getPublic());
 *
 * // aliceSecret and bobSecret will be identical
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdhAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs a new ECDH algorithm definition.
     *
     * <p>
     * This constructor registers the capabilities and key builders required for
     * Elliptic Curve Diffie-Hellman (ECDH) key agreement:
     * </p>
     *
     * <ul>
     * <li><b>Capability</b>: {@link AlgorithmFamily#AGREEMENT} with
     * {@link KeyUsage#AGREEMENT}, producing an
     * {@link zeroecho.core.context.AgreementContext} from a local
     * {@link java.security.PrivateKey} and a peer’s public key (supplied at
     * runtime).</li>
     *
     * <li><b>Asymmetric key builders</b>:
     * <ul>
     * <li>{@link EcdhCurveSpec} - generates EC key pairs suitable for ECDH
     * (default: {@code P-256}).</li>
     * <li>{@link EcdsaPublicKeySpec} - imports existing EC public keys.</li>
     * <li>{@link EcdsaPrivateKeySpec} - imports existing EC private keys.</li>
     * </ul>
     * </li>
     * </ul>
     *
     * <p>
     * Note: although an {@link EcdsaCurveSpec} is accepted as a context parameter,
     * the current implementation does not use it when constructing the
     * {@link zeroecho.core.context.AgreementContext}. The curve is inferred from
     * the provided key. This placeholder remains for API uniformity and may be
     * enforced in later revisions.
     * </p>
     *
     * @since 1.0
     */
    public EcdhAlgorithm() {
        super("ECDH", "ECDH");

        // AGREEMENT (our private key + peer public provided via context)
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, AgreementContext.class, PrivateKey.class,
                EcdsaCurveSpec.class,
                (PrivateKey k, EcdsaCurveSpec s) -> {
                    requireMatchingCurve(k, s);
                    return new GenericJcaAgreementContext(this, k, "ECDH", null);
                },
                () -> EcdsaCurveSpec.P256);
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, KeyPairKey.class,
                EcdsaCurveSpec.class, (KeyPairKey k, EcdsaCurveSpec s) -> new GenericJcaMessageAgreementContext(this, k,
                        "ECDH", null, "EC", null),
                () -> EcdsaCurveSpec.P256);

        // Reuse EC builders/importers
        registerAsymmetricKeyPairGenerator(EcdhCurveSpec.class, new EcdhKeyGenBuilder(), () -> EcdhCurveSpec.P256);
        registerPublicKeyImporter(EcdsaPublicKeySpec.class, new EcdsaPublicKeyBuilder());
        registerPrivateKeyImporter(EcdsaPrivateKeySpec.class, new EcdsaPrivateKeyBuilder());
    }

    private static void requireMatchingCurve(PrivateKey key, EcdsaCurveSpec requested) {
        if (!(key instanceof ECKey ecKey)) { return; }
        int actualFieldSize = ecKey.getParams().getCurve().getField().getFieldSize();
        int expectedFieldSize = switch (requested) {
            case P256 -> 256;
            case P384 -> 384;
            case P512 -> 521;
        };
        if (actualFieldSize != expectedFieldSize) {
            throw new IllegalArgumentException(
                    "ECDH key field size " + actualFieldSize + " does not match requested curve "
                    + requested.curveName() + " (expected field size " + expectedFieldSize + ")");
        }
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("ECDH-P256", "ECDH P-256 (128-bit)", SecurityLevel.classical(128), EcdhCurveSpec.P256),
            new ParameterSetDescriptor.Concrete<>("ECDH-P384", "ECDH P-384 (192-bit)", SecurityLevel.classical(192), EcdhCurveSpec.P384),
            new ParameterSetDescriptor.Concrete<>("ECDH-P521", "ECDH P-521 (256-bit)", SecurityLevel.classical(256), EcdhCurveSpec.P512)
        );
    }

}
