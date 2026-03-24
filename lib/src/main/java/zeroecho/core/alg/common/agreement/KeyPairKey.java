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
package zeroecho.core.alg.common.agreement;

import java.io.Serial;
import java.io.Serializable;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * A {@link Key} wrapper that carries a {@link KeyPair} through APIs that are
 * constrained to {@link Key} types.
 *
 * <p>
 * This type exists to support capabilities that require both private and public
 * components (e.g., message-oriented key agreement contexts), while preserving
 * backward-compatible capabilities that accept only a {@link PrivateKey}.
 * </p>
 *
 * <p>
 * The wrapper does not expose an encoding via {@link #getEncoded()} because
 * serializing private key material implicitly is dangerous and not required for
 * capability dispatch.
 * </p>
 *
 * @since 1.0
 */
public final class KeyPairKey implements Key, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final KeyPair keyPair;

    /**
     * Creates a wrapper around a {@link KeyPair}.
     *
     * @param keyPair key pair to wrap (must not be {@code null})
     * @throws NullPointerException if {@code keyPair} is {@code null}
     * @since 1.0
     */
    public KeyPairKey(KeyPair keyPair) {
        this.keyPair = Objects.requireNonNull(keyPair, "keyPair");
        Objects.requireNonNull(keyPair.getPrivate(), "keyPair.private");
        Objects.requireNonNull(keyPair.getPublic(), "keyPair.public");
    }

    /**
     * Returns the wrapped {@link KeyPair}.
     *
     * @return key pair
     * @since 1.0
     */
    public KeyPair keyPair() {
        return keyPair;
    }

    /**
     * Returns the wrapped private key.
     *
     * @return private key
     * @since 1.0
     */
    public PrivateKey privateKey() {
        return keyPair.getPrivate();
    }

    /**
     * Returns the wrapped public key.
     *
     * @return public key
     * @since 1.0
     */
    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    /**
     * Returns the algorithm name of the wrapped private key.
     *
     * @return algorithm name
     * @since 1.0
     */
    @Override
    public String getAlgorithm() {
        return privateKey().getAlgorithm();
    }

    /**
     * Returns {@code null}. This wrapper intentionally does not define a standard
     * encoding format.
     *
     * @return {@code null}
     * @since 1.0
     */
    @Override
    public String getFormat() {
        return null;
    }

    /**
     * Returns {@code null}. This wrapper intentionally does not expose a combined
     * encoding.
     *
     * @return {@code null}
     * @since 1.0
     */
    @Override
    public byte[] getEncoded() {
        return null; // NOPMD
    }
}
