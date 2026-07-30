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
package zeroecho.sdk.hybrid.kex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.sdk.util.Kdf;

/**
 * Hybrid key exchange (KEX) context that combines a classic agreement and a
 * post-quantum KEM-style agreement.
 *
 * <p>
 * This context composes two independent shared secrets:
 * </p>
 * <ul>
 * <li><b>Classic leg</b>: a {@link AgreementContext} (e.g. X25519, ECDH, DH)
 * that derives a raw shared secret after the peer public key is
 * configured.</li>
 * <li><b>PQC leg</b>: a {@link MessageAgreementContext} (typically ML-KEM
 * exposed via core capabilities) whose "peer message" represents the
 * encapsulation/decapsulation payload (e.g. KEM ciphertext).</li>
 * </ul>
 *
 * <h2>Wire format</h2>
 * <p>
 * This class implements {@link MessageAgreementContext} to provide a single
 * hybrid message that can be transmitted between parties. The encoding is:
 * </p>
 * <pre>{@code
 * [int classicLen][classicBytes...][int pqcLen][pqcBytes...]
 * }</pre>
 *
 * <p>
 * For typical pairings such as {@code X25519 + ML-KEM}, the classic part is
 * empty because the classic leg is configured using the peer public key
 * out-of-band. If the classic leg itself is message-capable, the classic part
 * may be populated.
 * </p>
 *
 * <h2>Key derivation</h2>
 * <p>
 * The final keying material is derived using HKDF-SHA256 (RFC 5869):
 * </p>
 * <pre>{@code
 * classicSS = classic.deriveSecret()
 * pqcSS     = pqc.deriveSecret()
 * IKM       = classicSS || pqcSS
 * OKM       = HKDF-SHA256(IKM, salt, info, outLen)
 * }</pre>
 *
 * <p>
 * Intermediate raw secrets are treated as sensitive and are zeroized
 * (best-effort) once HKDF completes.
 * </p>
 *
 * <h2>CryptoContext identity</h2>
 * <p>
 * A hybrid exchange is inherently bound to multiple algorithms and keys. The
 * {@link #algorithm()} and {@link #key()} methods return representative values
 * from the classic leg to satisfy the
 * {@link zeroecho.core.context.CryptoContext} contract. Callers that require
 * full introspection should retain references to the underlying component
 * contexts.
 * </p>
 *
 * <h2>Error handling</h2>
 * <ul>
 * <li>Malformed hybrid messages cause {@link IllegalArgumentException} in
 * {@link #setPeerMessage(byte[])}.</li>
 * <li>HKDF failures are surfaced as {@link IllegalStateException} in
 * {@link #deriveSecret()}.</li>
 * <li>{@link #close()} closes both component contexts and aggregates
 * {@link IOException}s via suppressed exceptions.</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Instances are mutable and not thread-safe; use one instance per
 * handshake/session and thread.
 * </p>
 *
 * @since 1.0
 */
public final class HybridKexContext implements MessageAgreementContext {

    private static final Logger LOG = Logger.getLogger(HybridKexContext.class.getName());
    /* default */ static final int MAX_FRAME_BYTES = 65_536;
    private static final int FRAME_HEADER_BYTES = Integer.BYTES * 2;

    private final HybridKexProfile profile;
    private final AgreementContext classic;
    private final MessageAgreementContext pqc;
    private final SecretDeriver secretDeriver;

    private byte[] peerMessage;

    /**
     * Creates a hybrid KEX context by composing two underlying contexts.
     *
     * @param profile hybrid profile defining HKDF binding and output length
     * @param classic classic agreement context (must not be {@code null})
     * @param pqc     PQC message agreement context (must not be {@code null})
     * @throws NullPointerException if any argument is {@code null}
     * @since 1.0
     */
    public HybridKexContext(HybridKexProfile profile, AgreementContext classic, MessageAgreementContext pqc) {
        this(profile, classic, pqc, Kdf::hkdfSha256);
    }

    /* default */ HybridKexContext(HybridKexProfile profile, AgreementContext classic, MessageAgreementContext pqc,
            SecretDeriver secretDeriver) {
        this.profile = Objects.requireNonNull(profile, "profile");
        this.classic = Objects.requireNonNull(classic, "classic");
        this.pqc = Objects.requireNonNull(pqc, "pqc");
        this.secretDeriver = Objects.requireNonNull(secretDeriver, "secretDeriver");
    }

    /**
     * Returns the representative algorithm of this context.
     *
     * <p>
     * This is currently delegated to the classic leg. Hybrid constructions bind
     * multiple algorithms; callers that need full visibility should track both legs
     * explicitly.
     * </p>
     *
     * @return representative algorithm (classic leg)
     * @since 1.0
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return classic.algorithm();
    }

    /**
     * Returns the representative key of this context.
     *
     * <p>
     * This is delegated to the classic leg to satisfy the {@code CryptoContext}
     * contract. The hybrid KEX also depends on the PQC leg keys; callers should
     * store those keys separately if needed by the application.
     * </p>
     *
     * @return representative key (classic leg)
     * @since 1.0
     */
    @Override
    public Key key() {
        return classic.key();
    }

    /**
     * Sets the peer public key for the classic leg.
     *
     * <p>
     * This is the usual configuration step for classic DH-style agreements. The PQC
     * leg typically does not use peer public keys through this method; however, the
     * call is forwarded on a best-effort basis for implementations that accept it.
     * </p>
     *
     * @param peer peer public key for the classic agreement
     * @since 1.0
     */
    @Override
    public void setPeerPublic(PublicKey peer) {
        classic.setPeerPublic(peer);
        try {
            pqc.setPeerPublic(peer);
        } catch (RuntimeException ignore) { // NOPMD
            // KEM-style agreements usually do not accept peer public here.
        }
    }

    /**
     * Supplies the hybrid peer message received from the remote party.
     *
     * <p>
     * The message is decoded into its classic and PQC parts. The PQC part is always
     * forwarded to the PQC leg via
     * {@link MessageAgreementContext#setPeerMessage(byte[])}. The classic part is
     * forwarded only if the classic leg also implements
     * {@link MessageAgreementContext}; otherwise it is ignored.
     * </p>
     *
     * <p>
     * Passing {@code null} resets the peer-message related state of both legs
     * (best-effort).
     * </p>
     *
     * @param message hybrid message, or {@code null} to reset
     * @throws IllegalArgumentException if the provided message does not conform to
     *                                  the hybrid encoding
     * @since 1.0
     */
    @Override
    public void setPeerMessage(byte[] message) {
        if (message == null) {
            this.peerMessage = null;
            try {
                pqc.setPeerMessage(null);
            } catch (RuntimeException ignore) { // NOPMD
            }
            try {
                setClassicMessageIfSupported(null);
            } catch (RuntimeException ignore) { // NOPMD
            }
            return;
        }

        Parts parts;
        try {
            parts = decode(message);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid hybrid peer message encoding", e);
        }

        this.peerMessage = message.clone();

        try {
            setClassicMessageIfSupported(parts.classicPart());
        } catch (RuntimeException ignore) { // NOPMD
            // classic leg may be non-message agreement; ignore
        }

        byte[] pqcPart = parts.pqcPart();
        if (pqcPart != null && pqcPart.length > 0) {
            pqc.setPeerMessage(pqcPart);
        }
    }

    /**
     * Returns the hybrid message to be sent to the peer.
     *
     * <p>
     * The PQC leg typically produces a non-empty message (encapsulation ciphertext)
     * for initiator roles. The classic leg contributes an empty message unless it
     * supports message mode.
     * </p>
     *
     * @return encoded hybrid peer message
     * @throws IllegalStateException if encoding fails or the PQC leg cannot produce
     *                               a message in the current role
     * @since 1.0
     */
    @Override
    public byte[] getPeerMessage() {
        byte[] classicMsg = getClassicMessageIfSupported();
        byte[] pqcMsg;
        try {
            pqcMsg = pqc.getPeerMessage();
        } catch (RuntimeException e) { // NOPMD
            // Responder-side KEM leg typically does not produce an outbound message.
            pqcMsg = new byte[0];
        }

        try {
            byte[] msg = encode(classicMsg, pqcMsg);
            this.peerMessage = msg.clone();
            return msg;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to encode hybrid peer message", e);
        }
    }

    /**
     * Derives the final hybrid shared secret (OKM) using HKDF-SHA256.
     *
     * <p>
     * This method derives both component secrets and then performs HKDF over their
     * concatenation. Higher-level protocols should additionally bind
     * transcript/context data through the HKDF {@code info} parameter
     * ({@link HybridKexProfile#hkdfInfo()}).
     * </p>
     *
     * @return derived keying material (OKM) of length
     *         {@link HybridKexProfile#outLenBytes()}
     * @throws IllegalStateException if HKDF fails or underlying contexts are not
     *                               configured
     * @since 1.0
     */
    @Override
    public byte[] deriveSecret() {
        byte[] classicSs = null;
        byte[] pqcSs = null;
        byte[] ikm = null;
        try {
            classicSs = classic.deriveSecret();
            pqcSs = pqc.deriveSecret();
            int combinedLength = Math.addExact(classicSs.length, pqcSs.length);
            ikm = new byte[combinedLength];
            System.arraycopy(classicSs, 0, ikm, 0, classicSs.length);
            System.arraycopy(pqcSs, 0, ikm, classicSs.length, pqcSs.length);
            byte[] out = secretDeriver.derive(ikm, profile.hkdfSalt(), profile.hkdfInfo(), profile.outLenBytes());
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("HybridKexContext.deriveSecret(): derived OKM length=" + out.length);
            }
            return out;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-SHA256 failed", e);
        } catch (ArithmeticException e) {
            throw new IllegalStateException("Hybrid secret length exceeds supported array size", e);
        } finally {
            zeroize(classicSs);
            zeroize(pqcSs);
            zeroize(ikm);
        }
    }

    /**
     * Package-private derivation seam used to verify cleanup on KDF failure.
     */
    /* default */
    @FunctionalInterface
    interface SecretDeriver {
        /**
         * Derives the final output from owned temporary hybrid input.
         *
         * @param ikm          combined component secrets
         * @param salt         HKDF salt
         * @param info         HKDF context information
         * @param outputLength requested output length
         * @return derived output transferred to the caller
         * @throws GeneralSecurityException if derivation fails
         */
        byte[] derive(byte[] ikm, byte[] salt, byte[] info, int outputLength) throws GeneralSecurityException;
    }

    /**
     * Closes both underlying contexts.
     *
     * <p>
     * If closing the second context fails after the first one already failed, the
     * second failure is added as a suppressed exception on the first one.
     * </p>
     *
     * @throws IOException if closing either leg fails
     * @since 1.0
     */
    @Override
    public void close() throws IOException {
        IOException first = null;

        try {
            classic.close();
        } catch (IOException e) {
            first = e;
        }

        try {
            pqc.close();
        } catch (IOException e) {
            if (first == null) {
                first = e;
            } else {
                first.addSuppressed(e);
            }
        }

        if (first != null) {
            throw first;
        }
    }

    /**
     * Returns the last hybrid peer message that was produced or set on this
     * instance.
     *
     * <p>
     * This is intended for diagnostics and testing. The returned array is a
     * defensive copy.
     * </p>
     *
     * @return last hybrid message, or {@code null} if none has been produced or set
     * @since 1.0
     */
    public byte[] lastPeerMessageOrNull() {
        return (peerMessage == null) ? null : peerMessage.clone();
    }

    // -------------------------------------------------------------------------
    // Encoding helpers
    // -------------------------------------------------------------------------

    /* default */ static byte[] encode(byte[] classicMsg, byte[] pqcMsg) throws IOException {
        byte[] c = (classicMsg == null) ? new byte[0] : classicMsg;
        byte[] p = (pqcMsg == null) ? new byte[0] : pqcMsg;
        long frameLength = FRAME_HEADER_BYTES;
        frameLength += c.length;
        frameLength += p.length;
        if (frameLength > MAX_FRAME_BYTES) {
            throw new IOException("hybrid frame exceeds " + MAX_FRAME_BYTES + " bytes");
        }

        ByteBuffer output = ByteBuffer.allocate((int) frameLength);
        output.putInt(c.length);
        output.put(c);
        output.putInt(p.length);
        output.put(p);
        return output.array();
    }

    /* default */ static Parts decode(byte[] msg) throws IOException {
        Objects.requireNonNull(msg, "msg must not be null");
        if (msg.length > MAX_FRAME_BYTES) {
            throw new IOException("hybrid frame exceeds " + MAX_FRAME_BYTES + " bytes");
        }
        if (msg.length < FRAME_HEADER_BYTES) {
            throw new IOException("truncated hybrid frame header");
        }

        int cLen = ByteBuffer.wrap(msg, 0, Integer.BYTES).getInt();
        if (cLen < 0) {
            throw new IOException("negative classic length");
        }
        long pqcLengthOffset = Integer.BYTES;
        pqcLengthOffset += cLen;
        long payloadOffset = pqcLengthOffset + Integer.BYTES;
        if (payloadOffset > msg.length) {
            throw new IOException("truncated classic component");
        }

        int pLen = ByteBuffer.wrap(msg, (int) pqcLengthOffset, Integer.BYTES).getInt();
        if (pLen < 0) {
            throw new IOException("negative pqc length");
        }
        long expectedLength = payloadOffset + pLen;
        if (expectedLength > MAX_FRAME_BYTES) {
            throw new IOException("declared hybrid frame exceeds " + MAX_FRAME_BYTES + " bytes");
        }
        if (expectedLength > msg.length) {
            throw new IOException("truncated pqc component");
        }
        if (expectedLength < msg.length) {
            throw new IOException("trailing bytes in hybrid frame");
        }

        byte[] c = Arrays.copyOfRange(msg, Integer.BYTES, (int) pqcLengthOffset);
        byte[] p = Arrays.copyOfRange(msg, (int) payloadOffset, (int) expectedLength);
        return new Parts(c, p);
    }

    private static void zeroize(byte[] b) {
        if (b == null) {
            return;
        }
        for (int i = 0; i < b.length; i++) {
            b[i] = 0;
        }
    }

    private byte[] getClassicMessageIfSupported() {
        if (classic instanceof MessageAgreementContext) {
            try {
                return ((MessageAgreementContext) classic).getPeerMessage();
            } catch (RuntimeException ignore) { // NOPMD
                return new byte[0];
            }
        }
        return new byte[0];
    }

    private void setClassicMessageIfSupported(byte[] msg) {
        if (classic instanceof MessageAgreementContext) {
            ((MessageAgreementContext) classic).setPeerMessage(msg);
        }
    }

    /* default */ record Parts(byte[] classicPart, byte[] pqcPart) {
    }
}
