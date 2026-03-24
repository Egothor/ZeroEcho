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
package zeroecho.core.alg.dh;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.DHParameters;

import zeroecho.core.annotation.Describable;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;

/**
 * <h2>Diffie-Hellman parameter specification</h2>
 *
 * Immutable container for Diffie-Hellman (DH) group parameters and their
 * effective key size.
 *
 * <p>
 * A {@code DhSpec} acts both as a {@link zeroecho.core.spec.ContextSpec} for
 * agreement contexts and as an {@link zeroecho.core.spec.AlgorithmKeySpec} for
 * key generation. Instances wrap a standard
 * {@link javax.crypto.spec.DHParameterSpec} with a declared bit length. They
 * are typically constructed via the provided factory methods for the RFC 7919
 * finite-field DH (FFDHE) groups.
 * </p>
 *
 * <h2>Predefined groups</h2>
 * <ul>
 * <li>{@link #ffdhe2048()} - ~112-bit security, suitable minimum baseline.</li>
 * <li>{@link #ffdhe3072()} - ~128-bit security, recommended
 * general-purpose.</li>
 * <li>{@link #ffdhe4096()} - ~150-bit security.</li>
 * <li>{@link #ffdhe6144()} - ~176-bit security.</li>
 * <li>{@link #ffdhe8192()} - ~192-bit security, high-assurance
 * environments.</li>
 * </ul>
 *
 * <p>
 * These correspond exactly to the safe-prime groups defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7919">RFC 7919</a>. Using
 * well-standardized groups avoids parameter negotiation pitfalls and ensures
 * interoperability.
 * </p>
 *
 * <h2>Thread-safety</h2> {@code DhSpec} instances are immutable and can be
 * shared freely.
 *
 * <h2>Example</h2> <pre>{@code
 * // Create a key pair in the FFDHE-3072 group
 * KeyPair kp = CryptoAlgorithms.keyPair("DH", DhSpec.ffdhe3072());
 *
 * // Establish an agreement context
 * AgreementContext ctx = CryptoAlgorithms.create(
 *     "DH", KeyUsage.AGREEMENT, kp.getPrivate(), DhSpec.ffdhe3072());
 * }</pre>
 *
 * @since 1.0
 */
public final class DhSpec implements ContextSpec, AlgorithmKeySpec, Describable {
    private final int sizeBits; // e.g., 2048
    private final DHParameterSpec params;
    private final String desc;

    private DhSpec(int sizeBits, DHParameterSpec params, String desc) {
        this.sizeBits = sizeBits;
        this.params = params;
        this.desc = desc;
    }

    /**
     * Returns the standard FFDHE-2048 group.
     *
     * <p>
     * Provides ~112-bit classical security, the minimum acceptable baseline for
     * modern use per RFC 7919.
     * </p>
     *
     * @return a {@code DhSpec} wrapping FFDHE-2048 parameters
     */
    public static DhSpec ffdhe2048() {
        DHParameters p = DHStandardGroups.rfc7919_ffdhe2048;
        return new DhSpec(2048, new DHParameterSpec(p.getP(), p.getG()), "rfc7919_ffdhe2048");
    }

    /**
     * Returns the standard FFDHE-3072 group.
     *
     * <p>
     * Provides ~128-bit classical security, recommended for general-purpose
     * long-term deployments.
     * </p>
     *
     * @return a {@code DhSpec} wrapping FFDHE-3072 parameters
     */
    public static DhSpec ffdhe3072() {
        DHParameters p = DHStandardGroups.rfc7919_ffdhe3072;
        return new DhSpec(3072, new DHParameterSpec(p.getP(), p.getG()), "rfc7919_ffdhe3072");
    }

    /**
     * Returns the standard FFDHE-4096 group.
     *
     * <p>
     * Provides ~150-bit classical security. Chosen when a moderate increase over
     * 128-bit strength is required.
     * </p>
     *
     * @return a {@code DhSpec} wrapping FFDHE-4096 parameters
     */
    public static DhSpec ffdhe4096() {
        DHParameters p = DHStandardGroups.rfc7919_ffdhe4096;
        return new DhSpec(4096, new DHParameterSpec(p.getP(), p.getG()), "rfc7919_ffdhe4096");
    }

    /**
     * Returns the standard FFDHE-6144 group.
     *
     * <p>
     * Provides ~176-bit classical security, suitable for high-value environments
     * requiring extra margin.
     * </p>
     *
     * @return a {@code DhSpec} wrapping FFDHE-6144 parameters
     */
    public static DhSpec ffdhe6144() {
        DHParameters p = DHStandardGroups.rfc7919_ffdhe6144;
        return new DhSpec(6144, new DHParameterSpec(p.getP(), p.getG()), "rfc7919_ffdhe6144");
    }

    /**
     * Returns the standard FFDHE-8192 group.
     *
     * <p>
     * Provides ~192-bit classical security, rarely used but suitable for
     * maximum-assurance deployments.
     * </p>
     *
     * @return a {@code DhSpec} wrapping FFDHE-8192 parameters
     */
    public static DhSpec ffdhe8192() {
        DHParameters p = DHStandardGroups.rfc7919_ffdhe8192;
        return new DhSpec(8192, new DHParameterSpec(p.getP(), p.getG()), "rfc7919_ffdhe8192");
    }

    /**
     * Returns the underlying JCA {@link DHParameterSpec}.
     *
     * @return the DH parameters (prime modulus and generator)
     */
    public DHParameterSpec params() {
        return params;
    }

    /**
     * Returns the effective bit length of this group.
     *
     * <p>
     * This value reflects the size of the prime modulus {@code p}.
     * </p>
     *
     * @return size of the group modulus in bits
     */
    public int sizeBits() {
        return sizeBits;
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
        return desc;
    }
}
