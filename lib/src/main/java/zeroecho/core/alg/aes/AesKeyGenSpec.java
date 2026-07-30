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
package zeroecho.core.alg.aes;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key generation parameters for AES.
 *
 * <p>
 * Instances of this record specify the size of an AES key in bits. Valid values
 * are 128, 192, and 256. A {@code AesKeyGenSpec} is consumed by the registered
 * AES key builder to create a new {@link javax.crypto.SecretKey}.
 * </p>
 *
 * <p>
 * Objects of this type are immutable and thread-safe.
 * </p>
 *
 * @param keySizeBits the AES key size in bits (128, 192, or 256)
 *
 * @since 1.0
 */
public record AesKeyGenSpec(int keySizeBits) implements AlgorithmKeySpec, Describable {
    /**
     * Creates a new spec and validates the key size.
     *
     * @throws IllegalArgumentException if {@code keySizeBits} is not one of 128,
     *                                  192, or 256
     */
    public AesKeyGenSpec {
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException("AES keySizeBits must be 128/192/256, got " + keySizeBits);
        }
    }

    /**
     * Constructs a spec for generating a 128-bit AES key.
     *
     * @return a specification for AES-128
     */
    public static AesKeyGenSpec aes128() {
        return new AesKeyGenSpec(128);
    }

    /**
     * Constructs a spec for generating a 192-bit AES key.
     *
     * @return a specification for AES-192
     */
    public static AesKeyGenSpec aes192() {
        return new AesKeyGenSpec(192);
    }

    /**
     * Constructs a spec for generating a 256-bit AES key.
     *
     * @return a specification for AES-256
     */
    public static AesKeyGenSpec aes256() {
        return new AesKeyGenSpec(256);
    }

    /**
     * Provides a short textual description of the key size. For example,
     * {@code "256bits"}.
     *
     * @return a human-readable description
     */
    @Override
    public String description() {
        return keySizeBits() + "bits";
    }
}
