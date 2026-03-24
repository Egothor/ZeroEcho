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
package zeroecho.core.alg.common.agreement;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;
import zeroecho.core.context.MessageAgreementContext;

/**
 * <h2>Adapter: using a KEM as a message-based agreement primitive</h2>
 *
 * {@code KemMessageAgreementAdapter} adapts a {@link KemContext} into a
 * {@link MessageAgreementContext}, making KEMs usable in higher-level protocols
 * that expect a two-party message agreement API.
 *
 * <h2>Roles</h2>
 * <ul>
 * <li>{@link Role#INITIATOR} - encapsulates to a peer’s public key, producing a
 * ciphertext (peer message) and shared secret.</li>
 * <li>{@link Role#RESPONDER} - receives a peer message (ciphertext),
 * decapsulates with their private key, and derives the shared secret.</li>
 * </ul>
 *
 * <h2>Lifecycle</h2>
 * <ol>
 * <li>Create via {@link Builder} with a bound {@link KemContext}.</li>
 * <li>Initiator calls {@link #getPeerMessage()} to obtain ciphertext to
 * transmit.</li>
 * <li>Responder calls {@link #setPeerMessage(byte[])} with received
 * ciphertext.</li>
 * <li>Both parties call {@link #deriveSecret()} to obtain the agreed
 * secret.</li>
 * </ol>
 *
 * <h2>Thread-safety</h2> Instances are not thread-safe; synchronize externally
 * if sharing across threads.
 *
 * @since 1.0
 */
public final class KemMessageAgreementAdapter implements MessageAgreementContext {
    /**
     * Role of the adapter: initiator or responder.
     */
    public enum Role {
        /** Initiator: produces a peer message via encapsulation. */
        INITIATOR,
        /** Responder: consumes a peer message via decapsulation. */
        RESPONDER
    }

    private final KemContext kem;
    private final Role role;

    private byte[] producedMessage; // initiator: ciphertext (encapsulation)
    private byte[] receivedMessage; // responder: ciphertext to decapsulate
    private byte[] derivedSecret; // memoized deriveSecret()

    private KemMessageAgreementAdapter(KemContext kem, Role role) {
        this.kem = Objects.requireNonNull(kem, "kem must not be null");
        this.role = Objects.requireNonNull(role, "role must not be null");
    }

    /**
     * Returns a new builder for constructing a {@code KemMessageAgreementAdapter}.
     *
     * @return builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link KemMessageAgreementAdapter}.
     */
    public static final class Builder {
        private KemContext kem;
        private Role role;

        /**
         * Binds this adapter to a KEM context.
         *
         * @param kem underlying KEM context
         * @return this builder
         */
        public Builder upon(KemContext kem) {
            this.kem = kem;
            return this;
        }

        /**
         * Configures the adapter as an initiator.
         *
         * @return this builder
         */
        public Builder asInitiator() {
            this.role = Role.INITIATOR;
            return this;
        }

        /**
         * Configures the adapter as a responder.
         *
         * @return this builder
         */
        public Builder asResponder() {
            this.role = Role.RESPONDER;
            return this;
        }

        /**
         * Builds the adapter.
         *
         * @return new adapter instance
         * @throws NullPointerException if no KEM context or role is set
         */
        public KemMessageAgreementAdapter build() {
            return new KemMessageAgreementAdapter(kem, role);
        }
    }

    /**
     * Stores the peer’s ciphertext for decapsulation.
     *
     * @param message ciphertext received from initiator
     * @throws IllegalStateException if called in initiator mode
     */
    @Override
    public void setPeerMessage(byte[] message) {
        if (role != Role.RESPONDER) {
            throw new IllegalStateException("setPeerMessage only valid for RESPONDER");
        }
        this.receivedMessage = (message == null ? null : message.clone());
    }

    /**
     * Returns the ciphertext produced by encapsulation.
     *
     * @return defensive copy of ciphertext to send
     * @throws IllegalStateException if called in responder mode
     */
    @Override
    public byte[] getPeerMessage() {
        if (role != Role.INITIATOR) {
            throw new IllegalStateException("getPeerMessage only valid for INITIATOR");
        }
        ensureEncapsulated();
        return producedMessage.clone();
    }

    /**
     * No-op for KEM-based contexts.
     *
     * <p>
     * Unlike Diffie–Hellman, KEMs are already bound to the correct key at
     * construction. This method exists for interface symmetry.
     * </p>
     *
     * @param peer ignored
     */
    @Override
    public void setPeerPublic(PublicKey peer) {
        // KEM already bound to the correct key at construction; nothing to do.
        // Provided for API symmetry; ignore or validate if you wish.
    }

    /**
     * Derives the shared secret from this exchange.
     *
     * @return defensive copy of the derived secret
     * @throws UncheckedIOException if encapsulation/decapsulation fails
     */
    @Override
    public byte[] deriveSecret() {
        if (derivedSecret != null) {
            return derivedSecret.clone();
        }

        try {
            if (role == Role.INITIATOR) {
                ensureEncapsulated(); // fills producedMessage + derivedSecret
            } else {
                if (receivedMessage == null) {
                    throw new IllegalStateException("Responder missing peer encapsulation message");
                }
                byte[] ss = kem.decapsulate(receivedMessage);
                derivedSecret = (ss == null ? new byte[0] : ss.clone());
            }
            return derivedSecret.clone();
        } catch (IOException e) {
            throw new UncheckedIOException("KEM deriveSecret failed", e);
        }
    }

    private void ensureEncapsulated() {
        if (producedMessage != null && derivedSecret != null) {
            return;
        }
        try {
            KemContext.KemResult res = kem.encapsulate();
            this.producedMessage = res.ciphertext().clone();
            this.derivedSecret = res.sharedSecret().clone();
        } catch (IOException e) {
            throw new UncheckedIOException("KEM encapsulate failed", e);
        }
    }

    /**
     * Returns the underlying algorithm descriptor.
     *
     * @return algorithm bound to this adapter
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return kem.algorithm();
    }

    /**
     * Returns the key bound to the underlying KEM context.
     *
     * @return encapsulation (public) or decapsulation (private) key
     */
    @Override
    public Key key() {
        return kem.key();
    }

    /**
     * Closes the underlying KEM context if it is closeable.
     *
     * @throws IOException if the wrapped context fails to close
     */
    @Override
    public void close() throws IOException {
        kem.close();
    }
}
