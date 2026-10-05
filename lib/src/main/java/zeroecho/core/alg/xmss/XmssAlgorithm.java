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
package zeroecho.core.alg.xmss;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.VoidSpec;

/**
 * Concrete {@link zeroecho.core.CryptoAlgorithm} for XMSS (eXtended Merkle
 * Signature Scheme).
 *
 * <h2>Overview</h2>
 * <p>
 * XMSS is a stateful hash-based signature scheme standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8391">RFC 8391</a>. Security
 * relies solely on the collision resistance of the underlying hash function and
 * is therefore considered quantum-safe.
 * </p>
 *
 * <h2>CRITICAL: Statefulness</h2>
 * <p>
 * <strong>XMSS private keys are stateful with a finite signing capacity.</strong>
 * Each signing operation consumes one Merkle-tree leaf and advances the
 * internal leaf index <strong>irreversibly</strong>. The updated private key
 * state must be persisted to non-volatile storage before and after each signing
 * operation. Reusing a key at the same index (e.g., after a crash without
 * persisting the update) breaks security. Durable signing requires an explicit
 * {@link zeroecho.core.storage.StatefulSigner}; generic signing is unavailable.
 * </p>
 * <p>
 * The default parameter set {@code SHA2_10_256} provides 2<sup>10</sup> = 1 024
 * signing operations. Choose a larger tree height if more capacity is required.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>Generic signing is unavailable; freshly enrolled keys may use
 * {@link zeroecho.core.storage.StatefulSigner}.</li>
 * <li>{@link KeyUsage#VERIFY}: verifies XMSS signatures using a
 * {@link PublicKey}.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * {@code XmssAlgorithm} instances are immutable and safe to share. Created
 * {@link SignatureContext} objects are not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class XmssAlgorithm extends AbstractCryptoAlgorithm {
    private static final String TEXT_XMSS = "XMSS";


    private static final String PROVIDER = "BCPQC";

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());

    /**
     * Creates the XMSS algorithm instance and registers its capabilities and the
     * default key-pair generator ({@code SHA2_10_256}).
     */
    public XmssAlgorithm() {
        super(TEXT_XMSS, TEXT_XMSS);

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new XmssSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init XMSS verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(XmssKeyGenSpec.class, spec -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(TEXT_XMSS, PROVIDER);
            kpg.initialize(new XMSSParameterSpec(10, "SHA256"));
            return kpg.generateKeyPair();
        }, () -> XmssKeyGenSpec.DEFAULT);

        registerPublicKeyImporter(XmssPublicKeySpec.class, spec -> {
            KeyFactory kf = KeyFactory.getInstance(TEXT_XMSS, PROVIDER);
            return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
        });

        registerPrivateKeyImporter(XmssPrivateKeySpec.class, spec -> {
            KeyFactory kf = KeyFactory.getInstance(TEXT_XMSS, PROVIDER);
            byte[] encoded = spec.pkcs8();
            try {
                return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        });
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>(TEXT_XMSS, "XMSS (SHA2_10_256)", SecurityLevel.classical(128), XmssKeyGenSpec.DEFAULT)
        );
    }

    @Override
    public boolean requiresStatefulSigning() {
        return true;
    }

}
