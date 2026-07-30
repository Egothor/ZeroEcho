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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.MessageAgreementContext;

/**
 * Message-oriented JCA key agreement context where the handshake message is a
 * public key encoding.
 *
 * <p>
 * This context provides a {@link MessageAgreementContext} view over a classical
 * JCA Diffie–Hellman style agreement (e.g., ECDH, XDH). The protocol
 * "to-be-sent" data for such agreements is the party's public key. This class
 * therefore maps:
 * </p>
 * <ul>
 * <li>{@link #getPeerMessage()} to the local public key encoding (X.509
 * SubjectPublicKeyInfo),</li>
 * <li>{@link #setPeerMessage(byte[])} to importing the peer public key and
 * binding it as the peer key.</li>
 * </ul>
 *
 * <h2>Encoding</h2>
 * <p>
 * The message format is the standard X.509 SubjectPublicKeyInfo encoding
 * returned by {@link java.security.PublicKey#getEncoded()}. This format is
 * stable, widely interoperable and avoids ad-hoc or algorithm-specific wire
 * formats.
 * </p>
 *
 * <h2>Algorithm and provider selection</h2>
 * <p>
 * The underlying key agreement algorithm name (for
 * {@link javax.crypto.KeyAgreement}) and the key factory algorithm name (for
 * {@link KeyFactory}) are supplied explicitly by the algorithm registration
 * code. This keeps algorithm-specific knowledge in {@code *Algorithm} classes
 * rather than embedding naming heuristics into shared code.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ol>
 * <li>Create the context with the local key pair wrapper.</li>
 * <li>Send {@link #getPeerMessage()} to the remote party.</li>
 * <li>Receive the remote party's message and call
 * {@link #setPeerMessage(byte[])}.</li>
 * <li>Derive the raw shared secret with {@link #deriveSecret()}.</li>
 * </ol>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>The message returned by {@link #getPeerMessage()} contains only public
 * key material.</li>
 * <li>The output of {@link #deriveSecret()} is a raw shared secret and must be
 * processed with a KDF by higher protocol layers before use as symmetric keying
 * material.</li>
 * <li>This class does not log, persist, or otherwise expose private key
 * material.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Instances are not thread-safe and are intended for single-use,
 * single-threaded protocol executions.
 * </p>
 *
 * @since 1.0
 */
public final class GenericJcaMessageAgreementContext implements MessageAgreementContext {

    private final GenericJcaAgreementContext agreement;
    private final PublicKey localPublic;
    private final String keyFactoryAlg;
    private final String keyFactoryProvider;

    /**
     * Creates a message-oriented agreement context over a JCA key agreement.
     *
     * <p>
     * The wrapped {@link KeyPairKey} supplies both local private and public key
     * components: the private key is used for the underlying agreement computation,
     * while the public key is exported as the handshake message via
     * {@link #getPeerMessage()}.
     * </p>
     *
     * @param alg                algorithm descriptor that owns this context
     * @param keyPairKey         local key pair wrapper; must contain both a private
     *                           and a public key
     * @param jcaAgreementName   JCA {@link javax.crypto.KeyAgreement} algorithm
     *                           name (e.g., {@code "ECDH"}, {@code "X25519"})
     * @param agreementProvider  optional JCA provider name for
     *                           {@link javax.crypto.KeyAgreement}, or {@code null}
     *                           for default provider selection
     * @param keyFactoryAlg      JCA {@link KeyFactory} algorithm name used to
     *                           import peer public keys (e.g., {@code "EC"},
     *                           {@code "XDH"})
     * @param keyFactoryProvider optional JCA provider name for {@link KeyFactory},
     *                           or {@code null} for default provider selection
     * @throws NullPointerException if any required argument is {@code null}
     * @since 1.0
     */
    public GenericJcaMessageAgreementContext(CryptoAlgorithm alg, KeyPairKey keyPairKey, String jcaAgreementName,
            String agreementProvider, String keyFactoryAlg, String keyFactoryProvider) {
        this.agreement = new GenericJcaAgreementContext(Objects.requireNonNull(alg, "alg"),
                Objects.requireNonNull(keyPairKey, "keyPairKey").privateKey(),
                Objects.requireNonNull(jcaAgreementName, "jcaAgreementName"), agreementProvider);
        this.localPublic = Objects.requireNonNull(keyPairKey.publicKey(), "keyPairKey.public");
        this.keyFactoryAlg = Objects.requireNonNull(keyFactoryAlg, "keyFactoryAlg");
        this.keyFactoryProvider = keyFactoryProvider;
    }

    /**
     * Returns the local party's handshake message.
     *
     * <p>
     * For DH/XDH-style agreements, the handshake message is the local public key
     * encoding. The returned array is a defensive copy and may be safely
     * transmitted over untrusted channels.
     * </p>
     *
     * <p>
     * The encoding is the standard X.509 SubjectPublicKeyInfo bytes returned by
     * {@link PublicKey#getEncoded()}.
     * </p>
     *
     * @return a defensive copy of the local public key encoding (never
     *         {@code null})
     * @throws IllegalStateException if the local public key does not provide an
     *                               encoding
     * @since 1.0
     */
    @Override
    public byte[] getPeerMessage() {
        byte[] encoded = localPublic.getEncoded();
        if (encoded == null) {
            throw new IllegalStateException("Local public key does not provide an encoding");
        }
        return encoded.clone();
    }

    /**
     * Supplies the peer party's handshake message.
     *
     * <p>
     * The provided message is interpreted as an X.509 SubjectPublicKeyInfo encoding
     * of the peer public key. The key is imported using {@link KeyFactory} and then
     * assigned as the peer key for the underlying agreement computation.
     * </p>
     *
     * <p>
     * Passing {@code null} resets the peer binding and makes
     * {@link #deriveSecret()} unusable until a new peer message is provided.
     * </p>
     *
     * @param message peer public key encoding (SPKI), or {@code null} to reset the
     *                peer state
     * @throws IllegalArgumentException if the message cannot be imported as a
     *                                  public key using the configured
     *                                  {@link KeyFactory} algorithm/provider
     * @since 1.0
     */
    @Override
    public void setPeerMessage(byte[] message) {
        if (message == null) {
            agreement.setPeerPublic(null);
            return;
        }

        PublicKey peerPublic = importPeerPublic(message);
        agreement.setPeerPublic(peerPublic);
    }

    /** {@inheritDoc} */
    @Override
    public void setPeerPublic(PublicKey peer) {
        agreement.setPeerPublic(peer);
    }

    /**
     * Imports a peer public key from an X.509 SubjectPublicKeyInfo encoding.
     *
     * <p>
     * This method performs no caching and always imports the key anew. The caller
     * is responsible for ensuring that the protocol-layer validation requirements
     * are met (e.g., checking that the received public key belongs to an expected
     * identity, or that the agreement mode requires ephemeral vs. static keys).
     * </p>
     *
     * @param spkiEncoded peer public key encoding (SPKI); must not be {@code null}
     * @return imported peer {@link PublicKey}
     * @throws IllegalArgumentException if the key cannot be imported
     */
    private PublicKey importPeerPublic(byte[] spkiEncoded) {
        try {
            KeyFactory keyFactory = (keyFactoryProvider == null) ? KeyFactory.getInstance(keyFactoryAlg)
                    : KeyFactory.getInstance(keyFactoryAlg, keyFactoryProvider);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(spkiEncoded);
            return keyFactory.generatePublic(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to import peer public key using KeyFactory " + keyFactoryAlg, e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] deriveSecret() {
        return agreement.deriveSecret();
    }

    /** {@inheritDoc} */
    @Override
    public CryptoAlgorithm algorithm() {
        return agreement.algorithm();
    }

    /** {@inheritDoc} */
    @Override
    public java.security.Key key() {
        return agreement.key();
    }

    /** {@inheritDoc} */
    @Override
    public void close() {
        agreement.close();
    }
}
