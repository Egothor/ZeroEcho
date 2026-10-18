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

import java.security.PublicKey;

/**
 * JCA {@link PublicKey} wrapper for an X-Wing public key.
 *
 * <p>
 * Stores the raw encoding produced by
 * {@code XWingPublicKeyParameters.getEncoded()}. The format is {@code "RAW"}
 * and the algorithm name is {@code "X-Wing"}.
 * </p>
 *
 * <p>
 * This class is package-private and is only used internally by
 * {@link XWingKemContext} and {@link XWingAlgorithm}.
 * </p>
 *
 * @since 1.0
 */
final class XWingPublicKey implements PublicKey {
    private static final long serialVersionUID = 1L;

    private final byte[] encoded;

    /* default */ XWingPublicKey(byte[] encoded) {
        java.util.Objects.requireNonNull(encoded, "encoded");
        if (encoded.length != XWingPublicKeySpec.RAW_LENGTH) {
            throw new IllegalArgumentException("Invalid X-Wing public key length");
        }
        this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
        return "X-Wing";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return encoded.clone();
    }

    /* default */ byte[] rawEncoded() {
        return encoded.clone();
    }
}
