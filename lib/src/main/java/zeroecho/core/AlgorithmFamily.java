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
package zeroecho.core;

/**
 * High-level classification of cryptographic algorithms.
 * <p>
 * Each {@code AlgorithmFamily} groups primitives with similar lifecycle
 * constraints, key properties, and safe usage patterns.
 *
 * <h2>Families</h2>
 * <ul>
 * <li>{@link #ASYMMETRIC}: Public-key algorithms such as signature schemes
 * (Ed25519, RSA) or public-key encryption.</li>
 * <li>{@link #SYMMETRIC}: Shared-key algorithms such as block/stream ciphers
 * and message authentication codes.</li>
 * <li>{@link #KEM}: Key encapsulation mechanisms, including post-quantum
 * schemes.</li>
 * <li>{@link #DIGEST}: Unkeyed hash functions and extendable-output functions
 * (e.g., SHA-2, SHA-3, BLAKE3).</li>
 * <li>{@link #AGREEMENT}: Key-agreement schemes (e.g., X25519, ECDH), distinct
 * from KEMs but with similar goals.</li>
 * </ul>
 *
 * <p>
 * <b>Usage:</b> Libraries and protocols can branch on this classification to
 * enforce correct API surfaces (e.g., demanding nonces for symmetric AEAD, or
 * key pairs for asymmetric operations).
 * </p>
 *
 * @since 1.0
 */
public enum AlgorithmFamily {
    /** Public-key primitives (signatures, RSA, etc.). */
    ASYMMETRIC,
    /** Shared-key primitives (ciphers, MACs). */
    SYMMETRIC,
    /** Key encapsulation mechanisms (encapsulate/decapsulate). */
    KEM,
    /** Unkeyed hash functions or XOFs. */
    DIGEST,
    /** Key-agreement schemes such as ECDH/X25519. */
    AGREEMENT
}
