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
/**
 * Abstractions for cryptographic operation contexts.
 *
 * <p>
 * This package defines the context layer that models active cryptographic
 * operations. A context represents a live, single-use operation bound to a key
 * and an optional specification. Contexts cover both stream-oriented transforms
 * (for example, encryption, MAC, signatures, digests) and message-oriented
 * exchanges (for example, key agreement and key encapsulation).
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Provide a stable set of operation-specific interfaces that algorithms
 * implement when producing runnable contexts.</li>
 * <li>Unify lifecycle concepts across operations: creation by an algorithm for
 * a concrete {@link zeroecho.core.KeyUsage}, execution of the operation, and
 * explicit closure via {@link CryptoContext#close()}.</li>
 * <li>Support both streaming and non-streaming styles without leaking provider
 * details into application code.</li>
 * </ul>
 *
 * <h2>Context kinds</h2>
 * <ul>
 * <li>{@link DigestContext} - unkeyed digests and extendable-output
 * functions.</li>
 * <li>{@link MacContext} - message authentication codes producing or verifying
 * fixed-length tags.</li>
 * <li>{@link EncryptionContext} - symmetric or asymmetric encryption and
 * decryption over byte streams.</li>
 * <li>{@link SignatureContext} - streaming digital signatures for sign and
 * verify roles.</li>
 * <li>{@link AgreementContext} - key agreement deriving a shared secret from a
 * local private key and a peer public key.</li>
 * <li>{@link MessageAgreementContext} - agreement modeled as an exchange of
 * explicit peer messages.</li>
 * <li>{@link KemContext} - key encapsulation mechanisms for
 * encapsulate/decapsulate workflows.</li>
 * </ul>
 *
 * <h2>Lifecycle and safety</h2>
 * <ul>
 * <li>Contexts are typically single-use and not thread-safe; create one per
 * pipeline or exchange.</li>
 * <li>Implementations should avoid retaining sensitive byte arrays; callers are
 * expected to apply a KDF to shared secrets and clear temporary material
 * promptly.</li>
 * <li>Unkeyed operations may use {@link zeroecho.core.NullKey#INSTANCE} where
 * an API requires a key reference.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.context;
