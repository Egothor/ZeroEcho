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
package zeroecho.core;

/**
 * Declares the intended purpose(s) of a cryptographic key.
 * <p>
 * Keys should be bound to a specific {@code KeyUsage} at generation or import
 * time. Enforcing usage prevents accidental cross-purposes — e.g., reusing a
 * signing key for encryption, or using a MAC key for key agreement — which can
 * lead to serious vulnerabilities.
 *
 * <h2>Typical usages</h2>
 * <ul>
 * <li>{@link #SIGN}/{@link #VERIFY}: digital signature schemes (Ed25519, ECDSA,
 * RSA-PSS).</li>
 * <li>{@link #ENCRYPT}/{@link #DECRYPT}: confidentiality with symmetric or
 * asymmetric encryption.</li>
 * <li>{@link #ENCAPSULATE}/{@link #DECAPSULATE}: key encapsulation mechanisms
 * (KEM).</li>
 * <li>{@link #MAC}: keyed message authentication (e.g., HMAC, KMAC).</li>
 * <li>{@link #DIGEST}: unkeyed hashing (e.g., SHA-256, SHA3-512).</li>
 * <li>{@link #AGREEMENT}: key agreement (e.g., X25519, ECDH) to derive shared
 * secrets.</li>
 * </ul>
 *
 * <p>
 * <b>Security note:</b> Many real-world breaches trace back to cryptographic
 * keys being used outside their intended purpose. Libraries should validate
 * {@code KeyUsage} before performing operations.
 * </p>
 *
 * @since 1.0
 */
public enum KeyUsage {
    /** Create digital signatures. */
    SIGN,
    /** Verify digital signatures. */
    VERIFY,
    /** Encrypt data for confidentiality. */
    ENCRYPT,
    /** Decrypt data that was encrypted under the matching key/parameters. */
    DECRYPT,
    /** Encapsulate a shared secret in a KEM flow. */
    ENCAPSULATE,
    /** Decapsulate a shared secret in a KEM flow. */
    DECAPSULATE,
    /** Compute a keyed message authentication code (e.g., HMAC, KMAC). */
    MAC,
    /** Compute an unkeyed hash (e.g., SHA-256), pipeline-friendly. */
    DIGEST,
    /** Perform key agreement (e.g., X25519, ECDH). */
    AGREEMENT
}
