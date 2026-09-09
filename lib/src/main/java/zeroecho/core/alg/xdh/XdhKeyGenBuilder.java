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
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * KeyPair generator for XDH curves using the JCA KeyPairGenerator SPI.
 *
 * <p>
 * This builder produces XDH key pairs (e.g., X25519, X448 depending on the
 * runtime provider) by instantiating a JCA {@code KeyPairGenerator} with the
 * algorithm name supplied by {@link XdhSpec#kpgName()}.
 * </p>
 *
 * <h2>Design and scope</h2>
 * <ul>
 * <li><b>Generation only:</b> This implementation exposes only the exact
 * key-pair generation capability; import operations are registered
 * separately.</li>
 * <li><b>Provider resolution:</b> The default JCA provider selection is used.
 * If a specific provider is required, supply or register one that exposes the
 * requested XDH algorithm name.</li>
 * <li><b>Thread-safety:</b> Instances are stateless and thread-safe.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Generate an X25519 key pair
 * XdhKeyGenBuilder builder = new XdhKeyGenBuilder();
 * KeyPair kp = builder.generateKeyPair(XdhSpec.X25519);
 * PublicKey pub = kp.getPublic();
 * PrivateKey prv = kp.getPrivate();
 * }</pre>
 *
 * @since 1.0
 */
public final class XdhKeyGenBuilder implements AsymmetricKeyPairGenerator<XdhSpec> {
    /** Creates a stateless XDH key-pair generator. */
    public XdhKeyGenBuilder() {
        // Stateless generator.
    }

    /**
     * Generates a new XDH key pair using the JCA
     * {@link java.security.KeyPairGenerator}.
     *
     * <p>
     * The generator instance is obtained via
     * {@link java.security.KeyPairGenerator#getInstance(String)} with
     * {@link XdhSpec#kpgName()} (for example, {@code "XDH"} or {@code "X25519"}).
     * No additional initialization parameters are supplied; providers are expected
     * to choose safe defaults for the requested curve.
     * </p>
     *
     * @param spec the XDH key specification indicating which XDH variant to use
     *             (e.g., {@code X25519})
     * @return a freshly generated {@link java.security.KeyPair} for the requested
     *         XDH variant
     * @throws GeneralSecurityException if the algorithm is not available, the
     *                                  provider rejects the request, or key
     *                                  generation fails
     */
    @Override
    public KeyPair generateKeyPair(XdhSpec spec) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.kpgName());
        return kpg.generateKeyPair();
    }
}
