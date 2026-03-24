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
/**
 * Hybrid key exchange (KEX) utilities combining a classic agreement and a
 * post-quantum KEM-style agreement into one derived shared secret.
 *
 * <p>
 * This package provides an SDK-level composition layer over existing core
 * contracts:
 * </p>
 * <ul>
 * <li>{@link zeroecho.core.context.AgreementContext} for classic DH-style
 * agreements (e.g. X25519, ECDH, DH), and</li>
 * <li>{@link zeroecho.core.context.MessageAgreementContext} for message-based
 * agreements (typically PQC KEM-style flows such as ML-KEM exposed via
 * {@code KeyUsage.AGREEMENT}).</li>
 * </ul>
 *
 * <h2>Wire model</h2>
 * <p>
 * A hybrid exchange needs explicit "to-be-sent" bytes. This package unifies the
 * model by emitting a single peer message containing two length-prefixed parts:
 * </p>
 * <ol>
 * <li>classic message (often empty for classic agreements that only require a
 * peer public key),</li>
 * <li>PQC message (typically KEM ciphertext produced by
 * {@link zeroecho.core.context.MessageAgreementContext}).</li>
 * </ol>
 *
 * <h2>Key derivation</h2>
 * <p>
 * The two underlying secrets are combined using HKDF-SHA256 (RFC 5869) via
 * {@link zeroecho.sdk.util.Kdf#hkdfSha256(byte[], byte[], byte[], int)} rather
 * than concatenation. Callers should treat raw intermediate secrets as
 * sensitive and clear them as soon as possible.
 * </p>
 *
 * <h2>Intended usage</h2>
 * <p>
 * Use {@link zeroecho.sdk.hybrid.kex.HybridKexContexts} to build initiator and
 * responder contexts and exchange
 * {@link zeroecho.sdk.hybrid.kex.HybridKexContext#getPeerMessage()} between
 * parties.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.sdk.hybrid.kex;
