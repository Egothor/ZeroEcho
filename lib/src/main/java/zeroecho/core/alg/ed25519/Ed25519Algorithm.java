/* *****************************************************************************
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
package zeroecho.core.alg.ed25519;

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
 * <h2>Ed25519 Digital Signature Algorithm</h2>
 *
 * Implementation of the Edwards-curve Digital Signature Algorithm (Ed25519).
 * This class integrates Ed25519 into the ZeroEcho cryptographic framework as an
 * {@link AbstractCryptoAlgorithm}.
 *
 * <p>
 * Ed25519 is a modern, high-security, high-performance signature scheme with
 * fixed-size keys and signatures. It is resistant to a wide class of
 * implementation pitfalls and side-channel attacks, making it a recommended
 * choice for new protocols.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>{@link KeyUsage#SIGN}: Creates a {@link SignatureContext} bound to a
 * {@link PrivateKey}. This context produces 64-byte Ed25519 signatures.</li>
 * <li>{@link KeyUsage#VERIFY}: Creates a {@link SignatureContext} bound to a
 * {@link PublicKey}. This context verifies 64-byte Ed25519 signatures.</li>
 * </ul>
 *
 * <h2>Key material</h2>
 * <ul>
 * <li>Generation via {@link Ed25519KeyGenSpec} and
 * {@link Ed25519KeyGenBuilder}.</li>
 * <li>Import of public keys via {@link Ed25519PublicKeySpec} and
 * {@link Ed25519PublicKeyBuilder}.</li>
 * <li>Import of private keys via {@link Ed25519PrivateKeySpec} and
 * {@link Ed25519PrivateKeyBuilder}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> This algorithm definition is immutable and safe to
 * share across threads. The created {@link SignatureContext} instances are not
 * guaranteed to be thread-safe.
 *
 * @since 1.0
 */
public final class Ed25519Algorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Constructs the Ed25519 algorithm definition and registers its roles and key
     * builders.
     *
     * <p>
     * This includes:
     * </p>
     * <ul>
     * <li>Binding SIGN (with {@link PrivateKey}) to
     * {@link Ed25519SignatureContext}.</li>
     * <li>Binding VERIFY (with {@link PublicKey}) to
     * {@link Ed25519SignatureContext}.</li>
     * <li>Registering key builders for generation and import of Ed25519 key
     * material.</li>
     * </ul>
     */
    public Ed25519Algorithm() {
        super("Ed25519", "Ed25519");

        // SIGN (private key)
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.SIGN, SignatureContext.class, PrivateKey.class, VoidSpec.class,
                (PrivateKey k, VoidSpec s) -> {
                    try {
                        return new Ed25519SignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init Ed25519 signer", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        // VERIFY (public key)
        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new Ed25519SignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init Ed25519 verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        // Key builders
        registerAsymmetricKeyPairGenerator(Ed25519KeyGenSpec.class, new Ed25519KeyGenBuilder(),
                Ed25519KeyGenSpec::defaultSpec);
        registerPublicKeyImporter(Ed25519PublicKeySpec.class, new Ed25519PublicKeyBuilder());
        registerPrivateKeyImporter(Ed25519PrivateKeySpec.class, new Ed25519PrivateKeyBuilder());
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("Ed25519", "Ed25519 (128-bit)", SecurityLevel.classical(128), Ed25519KeyGenSpec.defaultSpec())
        );
    }

}
