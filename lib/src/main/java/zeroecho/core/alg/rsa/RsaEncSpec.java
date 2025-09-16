/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.rsa;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import zeroecho.core.annotation.Describable;
import zeroecho.core.annotation.DisplayName;
import zeroecho.core.spec.ContextSpec;

/**
 * Specification of RSA encryption parameters including padding mode, hash
 * function, and optional OAEP label.
 *
 * <p>
 * This spec is used with {@link RsaCipherContext} to configure how RSA
 * encryption and decryption should be performed. It supports two padding
 * schemes:
 * </p>
 * <ul>
 * <li>{@link Padding#OAEP} with a configurable hash function and optional label
 * (as defined in PKCS#1 v2.2).</li>
 * <li>{@link Padding#PKCS1V15} (PKCS#1 v1.5 padding), without hash or
 * label.</li>
 * </ul>
 *
 * <h2>Construction</h2> Use the static factories to create a spec: <pre>{@code
 * // OAEP with SHA-256
 * RsaEncSpec oaep = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA256);
 *
 * // PKCS#1 v1.5
 * RsaEncSpec pkcs1 = RsaEncSpec.pkcs1v15();
 *
 * // OAEP with SHA-384 and custom UTF-8 label
 * RsaEncSpec labeled = RsaEncSpec.oaep(RsaEncSpec.Hash.SHA384)
 *                                .withLabelUtf8("context");
 * }</pre>
 *
 * <p>
 * Instances are immutable. Methods {@link #withLabel(byte[])} and
 * {@link #withLabelUtf8(String)} return new copies with the given label.
 * </p>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>OAEP with SHA-256 or stronger is recommended; PKCS#1 v1.5 is retained
 * only for interoperability and should be avoided for new designs.</li>
 * <li>Labels in OAEP can provide domain separation but are optional; most
 * applications leave them unset.</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("RSA encryption parameters")
public final class RsaEncSpec implements ContextSpec, Describable {
    /**
     * Supported RSA padding schemes.
     */
    public enum Padding {
        /** Optimal Asymmetric Encryption Padding (PKCS#1 OAEP). */
        OAEP,
        /** Legacy PKCS#1 v1.5 padding. */
        PKCS1V15
    }

    /**
     * Hash algorithms usable within OAEP padding.
     */
    public enum Hash {
        /** SHA-1 (deprecated, retained for compatibility). */
        SHA1,
        /** SHA-256. */
        SHA256,
        /** SHA-384. */
        SHA384,
        /** SHA-512. */
        SHA512
    } // used for OAEP only

    private final Padding padding;
    private final Hash hash; // OAEP only
    private final byte[] label; // OAEP optional label

    /**
     * Creates a new RSA encryption spec with the given parameters.
     *
     * @param padding padding scheme; must not be null
     * @param hash    hash function used for OAEP, or null if not applicable
     * @param label   optional OAEP label (copied defensively), or null if none
     * @throws NullPointerException     if {@code padding} is null
     * @throws IllegalArgumentException if {@code padding} is OAEP and {@code hash}
     *                                  is null, or if {@code padding} is PKCS1V15
     *                                  but {@code hash} or {@code label} are set
     */
    private RsaEncSpec(Padding padding, Hash hash, byte[] label) {
        this.padding = Objects.requireNonNull(padding, "padding must not be null");
        this.hash = hash;
        if (padding == Padding.OAEP && hash == null) {
            throw new IllegalArgumentException("OAEP requires a hash");
        }
        if (padding == Padding.PKCS1V15 && (hash != null || label != null)) {
            throw new IllegalArgumentException("PKCS1 v1.5 does not use hash/label");
        }
        this.label = (label == null ? null : Arrays.copyOf(label, label.length));
    }

    /**
     * Creates an OAEP spec with the given hash function and no label.
     *
     * @param h hash function for OAEP
     * @return new {@code RsaEncSpec} for OAEP
     */
    public static RsaEncSpec oaep(Hash h) {
        return new RsaEncSpec(Padding.OAEP, h, null);
    }

    /**
     * Creates a PKCS#1 v1.5 spec.
     *
     * @return new {@code RsaEncSpec} for PKCS#1 v1.5
     */
    public static RsaEncSpec pkcs1v15() {
        return new RsaEncSpec(Padding.PKCS1V15, null, null);
    }

    /**
     * Returns a copy of this spec with the given OAEP label.
     *
     * @param l label bytes (cloned); may be null to clear
     * @return new {@code RsaEncSpec} with the same padding/hash and new label
     */
    public RsaEncSpec withLabel(byte[] l) {
        return new RsaEncSpec(padding, hash, l);
    }

    /**
     * Returns a copy of this spec with the given UTF-8 OAEP label.
     *
     * @param s label string encoded in UTF-8; may be null to clear
     * @return new {@code RsaEncSpec} with the same padding/hash and new label
     */
    public RsaEncSpec withLabelUtf8(String s) {
        return new RsaEncSpec(padding, hash, s == null ? null : s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the padding scheme.
     *
     * @return padding scheme
     */
    public Padding padding() {
        return padding;
    }

    /**
     * Returns the hash function used in OAEP.
     *
     * @return OAEP hash function, or null if padding is PKCS#1 v1.5
     */
    public Hash hash() {
        return hash;
    }

    /**
     * Returns the OAEP label as a defensive copy.
     *
     * @return cloned OAEP label, or null if none
     */
    public byte[] label() {
        return label == null ? null : Arrays.copyOf(label, label.length);
    }

    /**
     * Returns a short human-readable description of this spec.
     *
     * <p>
     * Examples:
     * <ul>
     * <li>{@code "PKCS1v1.5"}</li>
     * <li>{@code "OAEP(SHA256,label=8B)"}</li>
     * </ul>
     *
     * @return description string
     */
    @Override
    public String description() {
        if (padding == Padding.PKCS1V15) {
            return "PKCS1v1.5";
        }
        return "OAEP(" + hash + (label != null ? ",label=" + label.length + "B" : "") + ")";
    }
}
