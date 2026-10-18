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
package zeroecho.core.alg.dh;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.spec.DHParameterSpec;

import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * <h2>DH key pair builder</h2>
 *
 * Builds Diffie-Hellman key pairs using the JCA providers available at runtime.
 * This builder targets the JCA algorithm name {@code "DiffieHellman"} and
 * accepts a {@link DhSpec} describing the desired parameter set.
 *
 * <p>
 * <strong>How it works</strong>
 * </p>
 * <ul>
 * <li>If {@link DhSpec#params()} is non-null, those DH parameters are
 * used.</li>
 * <li>Otherwise, the builder creates parameters with
 * {@link java.security.AlgorithmParameterGenerator} for the requested bit
 * length, then initializes a {@link java.security.KeyPairGenerator} to produce
 * the key pair.</li>
 * </ul>
 *
 * <p>
 * <strong>Security note</strong>: Prefer named, vetted groups such as the RFC
 * 7919 FFDHE sets exposed by {@code DhSpec} (for example
 * {@code DhSpec.ffdhe2048()}) over ad-hoc parameter generation.
 * </p>
 *
 * <p>
 * <strong>Thread-safety</strong>: Instances are stateless and can be shared
 * across threads.
 * </p>
 *
 * <p>
 * <strong>Example</strong>
 * </p>
 * <pre>{@code
 * DhKeyGenBuilder builder = new DhKeyGenBuilder();
 *
 * // Use a standard FFDHE group
 * KeyPair kp1 = builder.generateKeyPair(DhSpec.ffdhe2048());
 *
 * // Or request parameters by size when DhSpec.params() is null
 * DhSpec sized = DhSpec.ofBits(3072); // example factory returning size-only spec
 * KeyPair kp2 = builder.generateKeyPair(sized);
 * }</pre>
 */
public final class DhKeyGenBuilder implements AsymmetricKeyPairGenerator<DhSpec> {
    /** Creates a stateless Diffie-Hellman key-pair generator. */
    public DhKeyGenBuilder() {
        // Stateless generator.
    }

    /**
     * Generates a Diffie-Hellman key pair for the given specification.
     *
     * <p>
     * If {@code spec.params()} is non-null, the contained
     * {@link javax.crypto.spec.DHParameterSpec} is used directly. Otherwise,
     * parameters are generated with
     * {@link java.security.AlgorithmParameterGenerator} using
     * {@code spec.sizeBits()}, and the resulting parameters are applied to a
     * {@link java.security.KeyPairGenerator} for {@code "DiffieHellman"}.
     * </p>
     *
     * <p>
     * <strong>Performance note</strong>: On some providers, ad-hoc parameter
     * generation can be slow for large sizes. When possible, pass a {@code DhSpec}
     * that supplies a known-good {@code DHParameterSpec}.
     * </p>
     *
     * <p>
     * <strong>Example</strong>
     * </p>
     * <pre>{@code
     * KeyPair kp = new DhKeyGenBuilder().generateKeyPair(DhSpec.ffdhe3072());
     * }</pre>
     *
     * @param spec the DH specification indicating either a concrete
     *             {@link DHParameterSpec} or the target bit length for parameter
     *             generation; must not be null
     * @return a newly generated DH {@link KeyPair}
     * @throws GeneralSecurityException if the JCA provider does not support
     *                                  Diffie-Hellman, parameter generation fails,
     *                                  or key pair generation cannot be completed
     */
    @Override
    public KeyPair generateKeyPair(DhSpec spec) throws GeneralSecurityException {
        DHParameterSpec dh = spec.params();
        if (dh == null) {
            AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance("DiffieHellman");
            apg.init(spec.sizeBits());
            AlgorithmParameters params = apg.generateParameters();
            dh = params.getParameterSpec(DHParameterSpec.class);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
        kpg.initialize(dh);
        return kpg.generateKeyPair();
    }
}
