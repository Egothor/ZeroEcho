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
package zeroecho.core.alg.kyber;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key generation specification for the Kyber (ML-KEM) algorithm family.
 *
 * <p>
 * {@code KyberKeyGenSpec} captures the choice of Kyber parameter set when
 * generating a key pair. Kyber is a post-quantum key encapsulation mechanism
 * (KEM) standardized as ML-KEM. The three supported security levels are
 * represented by {@link Variant} values:
 * </p>
 * <ul>
 * <li>{@link Variant#KYBER512} - lowest cost, NIST level 1 security,</li>
 * <li>{@link Variant#KYBER768} - balanced choice, NIST level 3 security,</li>
 * <li>{@link Variant#KYBER1024} - strongest, NIST level 5 security.</li>
 * </ul>
 *
 * <h2>Usage</h2> Instances of this class are passed to the Kyber key builder to
 * select the desired parameter set: <pre>{@code
 * CryptoAlgorithm kyber = new KyberAlgorithm();
 * KeyPair kp = kyber.asymmetricKeyPairGenerator(KyberKeyGenSpec.class)
 *                   .generateKeyPair(KyberKeyGenSpec.kyber768());
 * }</pre>
 *
 * <p>
 * The spec is immutable and may be safely shared between threads.
 * </p>
 *
 * @see KyberAlgorithm
 * @see zeroecho.sdk.KeyBuilders.Asymmetric#generateKeyPair(String,
 *      AlgorithmKeySpec)
 */
public final class KyberKeyGenSpec implements AlgorithmKeySpec, Describable {
    /**
     * Enumerates the supported Kyber parameter sets.
     */
    public enum Variant {
        /** Kyber-512, NIST level 1 security strength. */
        KYBER512,
        /** Kyber-768, NIST level 3 security strength. */
        KYBER768,
        /** Kyber-1024, NIST level 5 security strength. */
        KYBER1024
    }

    private final Variant variant;

    private KyberKeyGenSpec(Variant v) {
        this.variant = v;
    }

    /**
     * Creates a specification for Kyber-512 key generation.
     *
     * @return a new spec bound to {@link Variant#KYBER512}
     */
    public static KyberKeyGenSpec kyber512() {
        return new KyberKeyGenSpec(Variant.KYBER512);
    }

    /**
     * Creates a specification for Kyber-768 key generation.
     *
     * @return a new spec bound to {@link Variant#KYBER768}
     */
    public static KyberKeyGenSpec kyber768() {
        return new KyberKeyGenSpec(Variant.KYBER768);
    }

    /**
     * Creates a specification for Kyber-1024 key generation.
     *
     * @return a new spec bound to {@link Variant#KYBER1024}
     */
    public static KyberKeyGenSpec kyber1024() {
        return new KyberKeyGenSpec(Variant.KYBER1024);
    }

    /**
     * Returns the variant associated with this specification.
     *
     * @return the Kyber parameter set
     */
    public Variant variant() {
        return variant;
    }

    /**
     * Returns a human-readable description of this spec.
     *
     * <p>
     * The description is the variant name, e.g., {@code "KYBER768"}.
     * </p>
     *
     * @return string description of the spec
     */
    @Override
    public String description() {
        return variant.toString();
    }
}
