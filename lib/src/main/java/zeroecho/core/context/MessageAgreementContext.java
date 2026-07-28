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
package zeroecho.core.context;

/**
 * Extension of {@link AgreementContext} for message-based key agreement
 * protocols.
 *
 * <p>
 * A {@code MessageAgreementContext} models algorithms where the two parties
 * must exchange explicit protocol messages in addition to providing a public
 * key. Examples include many KEM-based protocols where initiators send an
 * encapsulation and responders decapsulate it to derive the shared secret.
 * </p>
 *
 * <h2>Design</h2>
 * <ul>
 * <li>For Diffie–Hellman–style agreements (e.g., X25519, ECDH), no explicit
 * peer message is required. The peer’s public key is sufficient, and the
 * message-related methods are unused.</li>
 * <li>For KEM-based agreements (e.g., FrodoKEM, Kyber), the initiator generates
 * an encapsulation ciphertext to send, and the responder must receive and
 * decapsulate it. These flows rely on the {@link #setPeerMessage(byte[])} and
 * {@link #getPeerMessage()} methods.</li>
 * </ul>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Create a context via {@code ZeroEchoSession#createContext(...)} for the
 * {@link zeroecho.core.KeyUsage#AGREEMENT} role.</li>
 * <li>Initiators call {@link #getPeerMessage()} to obtain the message to send
 * to the responder, then invoke {@link AgreementContext#deriveSecret()}.</li>
 * <li>Responders call {@link #setPeerMessage(byte[])} to supply the received
 * encapsulation, then invoke {@link AgreementContext#deriveSecret()}.</li>
 * <li>Finally, call {@link #close()} to release any internal resources.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Shared secrets must be passed through a key derivation function (KDF)
 * immediately after computation; raw bytes should be cleared from memory once
 * used.</li>
 * <li>Malformed peer messages must be rejected without leaking side-channel
 * information (e.g., via constant-time checks).</li>
 * <li>As with other {@link CryptoContext} types, instances are not guaranteed
 * to be thread-safe.</li>
 * </ul>
 *
 * @since 1.0
 */
public interface MessageAgreementContext extends AgreementContext {
    /**
     * Supplies the peer’s message to this context.
     *
     * <p>
     * Typically used by a responder in KEM-based protocols to provide the
     * initiator’s encapsulation ciphertext. Diffie–Hellman contexts do not require
     * peer messages and may throw if this method is called.
     * </p>
     *
     * @param message the peer’s message (e.g., encapsulated ciphertext), may be
     *                {@code null} to reset
     * @throws IllegalStateException if the current role does not accept peer
     *                               messages
     */
    void setPeerMessage(byte[] message);

    /**
     * Retrieves the peer message produced by this context.
     *
     * <p>
     * Typically used by an initiator in KEM-based protocols to obtain the
     * encapsulation ciphertext that must be sent to the responder. Returns a clone
     * to prevent accidental modification of internal state.
     * </p>
     *
     * @return a clone of the message to send (never {@code null})
     * @throws IllegalStateException if the current role does not produce messages
     */
    byte[] getPeerMessage();
}
