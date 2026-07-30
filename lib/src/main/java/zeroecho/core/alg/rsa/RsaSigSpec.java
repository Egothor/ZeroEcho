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
package zeroecho.core.alg.rsa;

import java.util.Objects;
import java.util.Optional;

import zeroecho.core.annotation.Describable;
import zeroecho.core.annotation.DisplayName;
import zeroecho.core.spec.ContextSpec;

/**
 * Specification of RSA signature parameters including padding mode, hash
 * function, and (for PSS) salt length.
 *
 * <p>
 * This spec is used with {@link RsaSignatureContext} to configure how RSA
 * signatures are created and verified. It supports two modes:
 * </p>
 * <ul>
 * <li>{@link Mode#PKCS1V15} — legacy PKCS#1 v1.5 signatures using a selected
 * hash.</li>
 * <li>{@link Mode#PSS} — probabilistic signatures with PSS padding using a
 * selected hash and configurable salt length.</li>
 * </ul>
 *
 * <h2>Construction</h2> Use the static factories to create a spec: <pre>{@code
 * // PKCS#1 v1.5 with SHA-256
 * RsaSigSpec pkcs1 = RsaSigSpec.pkcs1v15(RsaSigSpec.Hash.SHA256);
 *
 * // PSS with SHA-384 and salt length equal to digest length
 * RsaSigSpec pss = RsaSigSpec.pss(RsaSigSpec.Hash.SHA384, -1);
 *
 * // PSS with SHA-512 and explicit 32-byte salt
 * RsaSigSpec pss32 = RsaSigSpec.pss(RsaSigSpec.Hash.SHA512, 32);
 * }</pre>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>PSS is recommended over PKCS#1 v1.5 for new applications, as it provides
 * stronger provable security.</li>
 * <li>The default salt length of {@code -1} means “use the digest length”, as
 * recommended by PKCS#1.</li>
 * <li>PKCS#1 v1.5 signatures remain widely used for compatibility but are less
 * robust against certain attack classes.</li>
 * </ul>
 *
 * @since 1.0
 */
@DisplayName("RSA signature parameters")
public final class RsaSigSpec implements ContextSpec, Describable {
    /**
     * Signature padding modes supported by RSA.
     */
    public enum Mode {
        /** Legacy PKCS#1 v1.5 signature scheme. */
        PKCS1V15,
        /** Probabilistic Signature Scheme (PSS), recommended for new systems. */
        PSS
    }

    /**
     * Supported hash algorithms for RSA signatures.
     *
     * <p>
     * These values are common secure choices; SHA-1 is deliberately excluded.
     * </p>
     */
    public enum Hash {
        /** SHA-256 digest. */
        SHA256,
        /** SHA-384 digest. */
        SHA384,
        /** SHA-512 digest. */
        SHA512
    } // common secure choices

    private final Mode mode;
    private final Hash hash;
    private final int pssSaltLen; // for PSS: -1 means "use digest length"

    /**
     * Constructs an RSA signature specification.
     *
     * @param mode    signature mode (PKCS#1 v1.5 or PSS)
     * @param hash    hash function used in signature computation
     * @param saltLen PSS salt length; -1 means digest length, ignored for PKCS#1
     *                v1.5
     * @throws NullPointerException     if {@code mode} or {@code hash} is
     *                                  {@code null}
     * @throws IllegalArgumentException if PSS is selected and {@code saltLen < -1},
     *                                  or if PKCS#1 v1.5 is selected but
     *                                  {@code saltLen} is not -1
     */
    private RsaSigSpec(Mode mode, Hash hash, int saltLen) {
        this.mode = Objects.requireNonNull(mode, "mode must not be null");
        this.hash = Objects.requireNonNull(hash, "hash must not be null");
        if (mode == Mode.PSS && saltLen < -1) {
            throw new IllegalArgumentException("PSS salt length must be -1 (digest length) or >= 0");
        }
        if (mode == Mode.PKCS1V15 && saltLen != -1) {
            throw new IllegalArgumentException("PKCS1v1.5 does not use salt length");
        }
        this.pssSaltLen = saltLen;
    }

    /**
     * Creates a PKCS#1 v1.5 spec with the given hash.
     *
     * @param h hash algorithm
     * @return new {@code RsaSigSpec} instance for PKCS#1 v1.5
     */
    public static RsaSigSpec pkcs1v15(Hash h) {
        return new RsaSigSpec(Mode.PKCS1V15, h, -1);
    }

    /**
     * Creates a PSS spec with the given hash and salt length.
     *
     * <p>
     * A salt length of {@code -1} means “use digest length”, as recommended by
     * PKCS#1.
     * </p>
     *
     * @param h       hash algorithm
     * @param saltLen PSS salt length, or -1 for digest length
     * @return new {@code RsaSigSpec} instance for PSS
     */
    public static RsaSigSpec pss(Hash h, int saltLen) {
        return new RsaSigSpec(Mode.PSS, h, saltLen);
    }

    /**
     * Resolves a standard external signature algorithm identifier to an explicit
     * RSA signature specification.
     *
     * <p>
     * This helper is intended for interoperability with ecosystems that express RSA
     * signature semantics through integrated names such as {@code SHA256withRSA}.
     * The returned spec always preserves the caller-visible semantics instead of
     * relying on algorithm defaults.
     * </p>
     *
     * @param algorithmId canonical external signature algorithm identifier
     * @return matching RSA signature spec, or {@link Optional#empty()} when the
     *         identifier is not a supported RSA interop name
     */
    public static Optional<RsaSigSpec> fromSignatureAlgorithmId(String algorithmId) {
        if (algorithmId == null || algorithmId.isBlank()) {
            return Optional.empty();
        }
        return switch (algorithmId) {
            case "SHA256withRSA" -> Optional.of(pkcs1v15(Hash.SHA256));
            case "SHA384withRSA" -> Optional.of(pkcs1v15(Hash.SHA384));
            case "SHA512withRSA" -> Optional.of(pkcs1v15(Hash.SHA512));
            default -> Optional.empty();
        };
    }

    /**
     * Returns the signature mode.
     *
     * @return mode (PKCS#1 v1.5 or PSS)
     */
    public Mode mode() {
        return mode;
    }

    /**
     * Returns the hash algorithm.
     *
     * @return hash algorithm used for signing/verification
     */
    public Hash hash() {
        return hash;
    }

    /**
     * Returns the salt length for PSS.
     *
     * @return salt length in bytes, or -1 to indicate digest length
     */
    public int pssSaltLen() {
        return pssSaltLen;
    }

    /**
     * Returns a short human-readable description of this spec.
     *
     * <p>
     * Examples:
     * <ul>
     * <li>{@code "PKCS1v1.5(SHA256)"}</li>
     * <li>{@code "PSS(SHA512,salt=32)"}</li>
     * <li>{@code "PSS(SHA384,salt=digestLen)"}</li>
     * </ul>
     *
     * @return description string
     */
    @Override
    public String description() {
        if (mode == Mode.PKCS1V15) {
            return "PKCS1v1.5(" + hash + ")";
        }
        String salt = pssSaltLen == -1 ? "digestLen" : String.valueOf(pssSaltLen);
        return "PSS(" + hash + ",salt=" + salt + ")";
    }
}
