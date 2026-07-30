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

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * Specification for X25519 and X448 Diffie-Hellman over Montgomery-form
 * elliptic curves.
 *
 * <p>
 * {@code XdhSpec} enumerates the parameter sets supported by the JCA "XDH"
 * interface: {@link #X25519} and {@link #X448}. Each constant binds a
 * {@code KeyPairGenerator} name (for key generation and import) and a
 * {@code KeyAgreement} name (for computing shared secrets).
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Generate a key pair for X25519
 * KeyPair kp = session.keyBuilders().asymmetric().generateKeyPair("XDH", XdhSpec.X25519);
 *
 * // Perform key agreement
 * AgreementContext ctx = session.createContext("XDH", KeyUsage.AGREEMENT,
 *                                                kp.getPrivate(), XdhSpec.X25519);
 * ctx.setPeerPublic(peerPublicKey);
 * byte[] sharedSecret = ctx.deriveSecret();
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Both variants share the JCA key-agreement name {@code "XDH"}, but have
 * distinct keypair generator names: {@code "X25519"} and {@code "X448"}.</li>
 * <li>The spec acts as a {@link zeroecho.core.spec.ContextSpec} to configure
 * context creation, and as an {@link zeroecho.core.spec.AlgorithmKeySpec} to
 * drive key generation.</li>
 * <li>Always apply a KDF to the raw shared secret before use as a symmetric
 * key.</li>
 * </ul>
 *
 * @since 1.0
 */
public enum XdhSpec implements ContextSpec, AlgorithmKeySpec, Describable {
    /** X25519 Diffie-Hellman over Curve25519. */
    X25519("X25519", "XDH"), // JCA: KeyAgreement "XDH"
    /** X448 Diffie-Hellman over Curve448. */
    X448("X448", "XDH");

    private final String kpgName; // KeyPairGenerator/KeyFactory name
    private final String kaName; // KeyAgreement name

    XdhSpec(String kpgName, String kaName) {
        this.kpgName = kpgName;
        this.kaName = kaName;
    }

    /**
     * Returns the canonical JCA name for {@link java.security.KeyPairGenerator}.
     *
     * @return generator name, e.g. {@code "X25519"} or {@code "X448"}
     */
    public String kpgName() {
        return kpgName;
    }

    /**
     * Returns the canonical JCA name for {@link javax.crypto.KeyAgreement}.
     *
     * @return agreement algorithm name, typically {@code "XDH"}
     */
    public String keyAgreementName() {
        return kaName;
    }

    /**
     * Returns a short, human-readable description of this object.
     *
     * <p>
     * The description should be concise and stable enough for logging or display
     * purposes, while avoiding exposure of any sensitive information.
     * </p>
     *
     * @return non-null descriptive string
     */
    @Override
    public String description() {
        return kpgName;
    }
}
