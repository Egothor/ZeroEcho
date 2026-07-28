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
package zeroecho.core.alg.hmac;

import java.util.Objects;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>Specification for HMAC operation parameters</h2>
 *
 * {@code HmacSpec} identifies the HMAC variant (digest family) to be used in a
 * {@link zeroecho.core.context.MacContext}. It does not include key material;
 * keys are provided separately via {@link javax.crypto.SecretKey}.
 *
 * <h2>Fields</h2>
 * <ul>
 * <li>{@code macName}: the canonical algorithm name as understood by the JCA
 * (e.g., {@code "HmacSHA256"}, {@code "HmacSHA384"},
 * {@code "HmacSHA512"}).</li>
 * </ul>
 *
 * <h2>Usage</h2> This spec is passed when creating a new HMAC context:
 * <pre>{@code
 * SecretKey key = session.keyBuilders().symmetric().generate("HMAC",
 *     HmacKeyGenSpec.sha256(256));
 *
 * MacContext ctx = session.createContext("HMAC",
 *     KeyUsage.MAC, key, HmacSpec.sha256());
 *
 * ctx.update(data);
 * byte[] tag = ctx.doFinal();
 * }</pre>
 *
 * <h2>Defaults</h2> Convenience factories are provided for the most common
 * variants:
 * <ul>
 * <li>{@link #sha256()} - HMAC with SHA-256</li>
 * <li>{@link #sha384()} - HMAC with SHA-384</li>
 * <li>{@link #sha512()} - HMAC with SHA-512</li>
 * </ul>
 *
 * @since 1.0
 */
public final class HmacSpec implements ContextSpec, Describable {
    private final String macName; // e.g., "HmacSHA256", "HmacSHA384", "HmacSHA512"

    /**
     * Constructs a new HMAC spec for the given algorithm.
     *
     * @param macName canonical algorithm name (e.g., {@code "HmacSHA256"})
     * @throws NullPointerException if {@code macName} is {@code null}
     */
    public HmacSpec(String macName) {
        this.macName = Objects.requireNonNull(macName, "macName must not be null");
    }

    /**
     * Returns the canonical JCA algorithm name of this spec.
     *
     * @return algorithm name (e.g., {@code "HmacSHA256"})
     */
    public String macName() {
        return macName;
    }

    /**
     * Convenience factory for HMAC-SHA256.
     *
     * @return new spec targeting {@code HmacSHA256}
     */
    public static HmacSpec sha256() {
        return new HmacSpec("HmacSHA256");
    }

    /**
     * Convenience factory for HMAC-SHA384.
     *
     * @return new spec targeting {@code HmacSHA384}
     */
    public static HmacSpec sha384() {
        return new HmacSpec("HmacSHA384");
    }

    /**
     * Convenience factory for HMAC-SHA512.
     *
     * @return new spec targeting {@code HmacSHA512}
     */
    public static HmacSpec sha512() {
        return new HmacSpec("HmacSHA512");
    }

    /**
     * Returns a human-readable description of this spec.
     *
     * <p>
     * The description is simply the algorithm name (e.g., {@code "HmacSHA256"}).
     * </p>
     *
     * @return algorithm name string
     */
    @Override
    public String description() {
        return macName;
    }

    /**
     * Returns a recommended key size (in bits) for this HMAC variant.
     *
     * <p>
     * HMAC is defined for keys of arbitrary length; this method therefore does not
     * express a strict requirement. It provides a conservative,
     * interoperability-friendly recommendation intended for default key derivation
     * and key generation paths, especially where the caller does not want to
     * manually select a key size.
     * </p>
     *
     * <p>
     * The recommendation follows common practice: use a key size at least equal to
     * the underlying hash output length. For the built-in variants this yields:
     * </p>
     * <ul>
     * <li>HmacSHA256 - 256 bits</li>
     * <li>HmacSHA384 - 384 bits</li>
     * <li>HmacSHA512 - 512 bits</li>
     * </ul>
     *
     * <p>
     * If this spec uses an unrecognized {@link #macName()} value, the method
     * returns {@code 256} bits as a safe default and to avoid failing existing
     * applications that rely on custom provider names. Applications with strict
     * requirements should enforce their own policy and/or explicitly specify a key
     * size.
     * </p>
     *
     * @return recommended key size in bits (positive, multiple of 8)
     * @since 1.0
     */
    public int recommendedKeyBits() {
        return recommendedKeyBitsForMacName(macName);
    }

    private static int recommendedKeyBitsForMacName(String macName) {
        return switch (macName) {
            case "HmacSHA256" -> 256;
            case "HmacSHA384" -> 384;
            case "HmacSHA512" -> 512;
            default -> 256;
        };
    }

}
