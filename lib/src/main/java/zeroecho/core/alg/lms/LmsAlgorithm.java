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
package zeroecho.core.alg.lms;

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

import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.spec.VoidSpec;

/**
 * Concrete {@link zeroecho.core.CryptoAlgorithm} for LMS (Leighton–Micali
 * Signatures).
 *
 * <h2>Overview</h2>
 * <p>
 * LMS is a stateful hash-based one-time signature scheme standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8554">RFC 8554</a>. It is
 * considered quantum-safe. Security depends on the security of the underlying
 * hash function (SHA-256 in the default parameter set) rather than on
 * computational hardness assumptions.
 * </p>
 *
 * <h2>CRITICAL: Statefulness</h2>
 * <p>
 * <strong>LMS private keys are stateful with a finite signing capacity.</strong>
 * Each signing operation consumes one Winternitz OTS leaf, and the updated key
 * state must be persisted to non-volatile storage before and after each signing.
 * Reusing a key state (e.g., after a crash) breaks security. An LMS key with
 * the default parameter set {@code lms_sha256_n32_h5} has exactly
 * 2<sup>5</sup> = 32 uses. Durable signing requires an explicit
 * {@link zeroecho.core.storage.StatefulSigner}; generic signing is unavailable.
 * </p>
 *
 * <h2>Capabilities</h2>
 * <ul>
 * <li>Generic signing is unavailable; freshly enrolled keys may use
 * {@link zeroecho.core.storage.StatefulSigner}.</li>
 * <li>{@link KeyUsage#VERIFY}: verifies LMS signatures using a
 * {@link PublicKey}.</li>
 * </ul>
 *
 * <h2>Default parameters</h2>
 * <p>
 * The default key generation specification uses
 * {@code lms_sha256_n32_h5} (height 5, 32 leaves) with
 * {@code sha256_n32_w8} (Winternitz parameter w=8). Applications requiring
 * more signing capacity should use a larger tree height.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * {@code LmsAlgorithm} instances are immutable and safe to share. Created
 * {@link SignatureContext} objects are not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class LmsAlgorithm extends AbstractCryptoAlgorithm {
    private static final String TEXT_LMS = "LMS";


    private static final String PROVIDER = "BCPQC";

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());

    /**
     * Creates the LMS algorithm instance and registers its capabilities and the
     * default key-pair generator.
     */
    public LmsAlgorithm() {
        super(TEXT_LMS, TEXT_LMS);

        capability(AlgorithmFamily.ASYMMETRIC, KeyUsage.VERIFY, SignatureContext.class, PublicKey.class, VoidSpec.class,
                (PublicKey k, VoidSpec s) -> {
                    try {
                        return new LmsSignatureContext(this, k);
                    } catch (GeneralSecurityException e) {
                        throw new IllegalArgumentException("Cannot init LMS verifier", e);
                    }
                }, () -> VoidSpec.INSTANCE);

        registerAsymmetricKeyPairGenerator(LmsKeyGenSpec.class, spec -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(TEXT_LMS, PROVIDER);
            kpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5,
                    LMOtsParameters.sha256_n32_w8));
            return kpg.generateKeyPair();
        }, () -> LmsKeyGenSpec.DEFAULT);

        registerPublicKeyImporter(LmsPublicKeySpec.class, spec -> {
            KeyFactory kf = KeyFactory.getInstance(TEXT_LMS, PROVIDER);
            return kf.generatePublic(new X509EncodedKeySpec(spec.x509()));
        });

        registerPrivateKeyImporter(LmsPrivateKeySpec.class, spec -> {
            KeyFactory kf = KeyFactory.getInstance(TEXT_LMS, PROVIDER);
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
            new ParameterSetDescriptor.Concrete<>(TEXT_LMS, "LMS (lms_sha256_n32_h5)", SecurityLevel.classical(128), LmsKeyGenSpec.DEFAULT)
        );
    }

    @Override
    public boolean requiresStatefulSigning() {
        return true;
    }

}
