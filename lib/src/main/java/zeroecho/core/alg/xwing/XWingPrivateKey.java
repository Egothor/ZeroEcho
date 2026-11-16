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
package zeroecho.core.alg.xwing;

import java.security.PrivateKey;
import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * JCA {@link PrivateKey} wrapper for an X-Wing private key.
 *
 * <p>
 * Stores the 32-byte seed produced by
 * {@code XWingPrivateKeyParameters.getSeed()}. The format is {@code "RAW"} and
 * the algorithm name is {@code "X-Wing"}.
 * </p>
 *
 * <p>
 * Implements {@link Destroyable} so that key material can be zeroed when it is
 * no longer needed.
 * </p>
 *
 * <p>
 * This class is package-private and is only used internally by
 * {@link XWingKemContext} and {@link XWingAlgorithm}.
 * </p>
 *
 * @since 1.0
 */
final class XWingPrivateKey implements PrivateKey, Destroyable {
    private static final long serialVersionUID = 1L;

    private byte[] seed;
    private boolean destroyed;

    /**
     * Copies a raw X-Wing private seed into this destroyable key.
     *
     * @param seed exactly 32 seed bytes; must not be null
     * @throws NullPointerException if the seed is null
     * @throws IllegalArgumentException if the seed length is invalid
     */
    /* default */ XWingPrivateKey(byte[] seed) {
        java.util.Objects.requireNonNull(seed, "seed");
        if (seed.length != XWingPrivateKeySpec.SEED_LENGTH) {
            throw new IllegalArgumentException("Invalid X-Wing private seed length");
        }
        this.seed = seed.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAlgorithm() {
        return "X-Wing";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getEncoded() {
        checkAlive();
        return seed.clone();
    }

    /**
     * Returns an independently owned copy of the active private seed.
     *
     * @return a new array of 32 seed bytes; the caller must clear it after use
     * @throws IllegalStateException if this key has been destroyed
     */
    /* default */ byte[] rawSeed() {
        checkAlive();
        return seed.clone();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void destroy() {
        if (!destroyed) {
            Arrays.fill(seed, (byte) 0);
            seed = null;
            destroyed = true;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkAlive() {
        if (destroyed) {
            throw new IllegalStateException("X-Wing private key has been destroyed");
        }
    }
}
