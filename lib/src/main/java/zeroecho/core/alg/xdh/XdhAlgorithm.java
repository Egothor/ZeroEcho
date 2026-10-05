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
package zeroecho.core.alg.xdh;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import java.util.List;

import zeroecho.core.ParameterSetDescriptor;
import zeroecho.core.SecurityLevel;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.alg.common.agreement.GenericJcaAgreementContext;
import zeroecho.core.alg.common.agreement.GenericJcaMessageAgreementContext;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spi.PrivateKeyImporter;
import zeroecho.core.spi.PublicKeyImporter;

/**
 * Algorithm definition for XDH (elliptic curve Diffie-Hellman) key agreement,
 * backed by the JCA {@code KeyAgreement} API.
 *
 * <p>
 * This algorithm integrates the XDH family (currently X25519, optionally X448
 * in supporting providers) into the ZeroEcho registry. It exposes the
 * {@link KeyUsage#AGREEMENT} role and produces {@link AgreementContext}
 * instances using {@code GenericJcaAgreementContext}, which delegates to the
 * standard JCA {@code KeyAgreement} primitive (e.g., {@code "XDH"},
 * {@code "X25519"}).
 * </p>
 *
 * <h2>Behavior</h2>
 * <ul>
 * <li><b>Context type:</b> {@link AgreementContext} constructed as a
 * {@code GenericJcaAgreementContext}.</li>
 * <li><b>Keys:</b> Requires a local {@link java.security.PrivateKey}; the peer
 * {@link java.security.PublicKey} must be supplied via
 * {@link AgreementContext#setPeerPublic(java.security.PublicKey)} before
 * calling {@link AgreementContext#deriveSecret()}.</li>
 * <li><b>Secret material:</b> {@code deriveSecret()} returns the raw XDH shared
 * secret. Protocols must apply a KDF before deriving symmetric keys or other
 * session material.</li>
 * <li><b>Providers:</b> The context uses the default JCA provider lookup unless
 * a provider is explicitly configured in {@code GenericJcaAgreementContext}
 * (this algorithm passes {@code null}).</li>
 * <li><b>Default spec:</b> {@link XdhSpec#X25519} is used when no explicit spec
 * is provided.</li>
 * </ul>
 *
 * <h2>Key material and builders</h2>
 * <ul>
 * <li>Asymmetric key pairs are generated or imported via
 * {@link XdhKeyGenBuilder}, parameterized by {@link XdhSpec}.</li>
 * <li>The default builder spec is {@link XdhSpec#X25519}.</li>
 * <li>Additional asymmetric builders are registered for
 * {@link XdhPublicKeySpec} and {@link XdhPrivateKeySpec} to import encoded keys
 * directly via the JCA {@link java.security.KeyFactory} for "XDH".</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Discover the algorithm definition (via ServiceLoader or explicit construction)
 * CryptoAlgorithm xdh = new XdhAlgorithm();
 *
 * // Generate key pairs
 * KeyPair a = xdh.asymmetricKeyPairGenerator(XdhSpec.class).generateKeyPair(XdhSpec.X25519);
 * KeyPair b = xdh.asymmetricKeyPairGenerator(XdhSpec.class).generateKeyPair(XdhSpec.X25519);
 *
 * // Perform agreement on side A
 * AgreementContext ctxA = xdh.createContext(KeyUsage.AGREEMENT, a.getPrivate(), XdhSpec.X25519);
 * ctxA.setPeerPublic(b.getPublic());
 * byte[] secretA = ctxA.deriveSecret();
 *
 * // Perform agreement on side B
 * AgreementContext ctxB = xdh.createContext(KeyUsage.AGREEMENT, b.getPrivate(), XdhSpec.X25519);
 * ctxB.setPeerPublic(a.getPublic());
 * byte[] secretB = ctxB.deriveSecret();
 *
 * // secretA and secretB are equal; apply a KDF before using them
 * }</pre>
 *
 * @since 1.0
 */
public final class XdhAlgorithm extends AbstractCryptoAlgorithm {

    private static final List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> PARAMETER_SETS =
            ParameterSetDescriptor.snapshot(createParameterSets());
    /**
     * Creates a new XDH algorithm registration.
     *
     * <p>
     * This constructor performs the following registrations:
     * </p>
     * <ul>
     * <li>Binds the {@link KeyUsage#AGREEMENT} role under
     * {@link AlgorithmFamily#AGREEMENT} to produce {@link AgreementContext}
     * instances with {@link java.security.PrivateKey} keys and {@link XdhSpec}
     * specs, backed by {@code GenericJcaAgreementContext} with the JCA name from
     * {@link XdhSpec#keyAgreementName()}.</li>
     * <li>Registers the {@link XdhKeyGenBuilder} for key pair generation with
     * {@link XdhSpec}, defaulting to {@link XdhSpec#X25519}.</li>
     * <li>Registers asymmetric key builders for {@link XdhPublicKeySpec} and
     * {@link XdhPrivateKeySpec} to allow direct key import using
     * {@link java.security.KeyFactory} ("XDH").</li>
     * </ul>
     *
     * <p>
     * The bound contexts use the platform’s default JCA provider
     * ({@code provider = null}).
     * </p>
     */
    public XdhAlgorithm() {
        super("Xdh", "Xdh");

        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, AgreementContext.class, PrivateKey.class,
                XdhSpec.class,
                (PrivateKey k, XdhSpec s) -> new GenericJcaAgreementContext(this, k, s.keyAgreementName(), null),
                () -> XdhSpec.X25519);
        // New capability: MessageAgreementContext over KeyPair
        capability(AlgorithmFamily.AGREEMENT, KeyUsage.AGREEMENT, MessageAgreementContext.class, KeyPairKey.class,
                XdhSpec.class, (KeyPairKey k, XdhSpec s) -> new GenericJcaMessageAgreementContext(this, k,
                        s.keyAgreementName(), null, "XDH", null),
                () -> XdhSpec.X25519);

        registerAsymmetricKeyPairGenerator(XdhSpec.class, new XdhKeyGenBuilder(), () -> XdhSpec.X25519);
        registerPublicKeyImporter(XdhPublicKeySpec.class, new PublicKeyImporter<>() {

            @Override
            public PublicKey importPublic(XdhPublicKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("XDH");
                return kf.generatePublic(new X509EncodedKeySpec(spec.encoded()));
            }
        });
        registerPrivateKeyImporter(XdhPrivateKeySpec.class, new PrivateKeyImporter<>() {

            @Override
            public PrivateKey importPrivate(XdhPrivateKeySpec spec) throws GeneralSecurityException {
                KeyFactory kf = KeyFactory.getInstance("XDH");
                byte[] encoded = spec.encoded();
                try {
                    return kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            }
        });
    }

    @Override
    public List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> parameterSets() {
        return PARAMETER_SETS;
    }

    private static List<ParameterSetDescriptor<? extends zeroecho.core.spec.AlgorithmKeySpec>> createParameterSets() {
        return List.of(
            new ParameterSetDescriptor.Concrete<>("X25519", "X25519 (128-bit)", SecurityLevel.classical(128), XdhSpec.X25519),
            new ParameterSetDescriptor.Concrete<>("X448",   "X448 (224-bit)",   SecurityLevel.classical(224), XdhSpec.X448)
        );
    }

}
