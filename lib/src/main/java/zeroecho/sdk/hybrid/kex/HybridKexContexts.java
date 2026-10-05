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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.CryptoContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Factory utilities for constructing hybrid key exchange (KEX) contexts.
 *
 * <p>
 * This class implements the SDK-level composition layer for hybrid key
 * exchange. It does not introduce new core contracts; instead, it composes
 * existing core contexts:
 * </p>
 * <ul>
 * <li>{@link AgreementContext} for the classic (pre-quantum) leg (e.g. X25519,
 * ECDH, DH), and</li>
 * <li>{@link MessageAgreementContext} for the post-quantum leg (typically a
 * KEM-style agreement, e.g. ML-KEM exposed as {@code KeyUsage.AGREEMENT}).</li>
 * </ul>
 *
 * <h2>Handshake model</h2>
 * <p>
 * The two legs have different wire semantics:
 * </p>
 * <ul>
 * <li><b>Classic leg</b> generally uses a peer public key supplied out-of-band
 * (certificate, directory, or a higher-level handshake message). This is
 * represented by
 * {@link AgreementContext#setPeerPublic(java.security.PublicKey)} and does not
 * necessarily produce any explicit "to-be-sent" bytes.</li>
 * <li><b>PQC leg</b> is message-based: the initiator produces an encapsulation
 * message (e.g. KEM ciphertext) via
 * {@link MessageAgreementContext#getPeerMessage()}, and the responder consumes
 * it via {@link MessageAgreementContext#setPeerMessage(byte[])}.</li>
 * </ul>
 *
 * <p>
 * {@link HybridKexContext} unifies these semantics by emitting and consuming a
 * single hybrid peer message that carries both legs (with the classic part
 * typically empty for classic-only public-key exchange).
 * </p>
 *
 * <h2>Error handling</h2>
 * <p>
 * Context construction is in-memory and reports configuration or provider
 * failures through the security exception model of {@link ZeroEchoSession}. I/O
 * failures remain associated with later stream processing.
 * </p>
 *
 * <h2>Thread safety</h2>
 * <p>
 * This factory is stateless and thread-safe. Produced contexts are mutable and
 * not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class HybridKexContexts {

    private HybridKexContexts() {
        // utility
    }

    /**
     * Creates an initiator-side hybrid KEX context.
     *
     * <p>
     * This method constructs:
     * </p>
     * <ul>
     * <li>a classic {@link AgreementContext} from the initiator's classic
     * {@link PrivateKey} and configures it with the peer's classic
     * {@link PublicKey}, and</li>
     * <li>a PQC {@link MessageAgreementContext} from the peer's PQC
     * {@link PublicKey} (encapsulation side).</li>
     * </ul>
     *
     * <p>
     * The returned {@link HybridKexContext} will typically produce a peer message
     * whose PQC part is non-empty (e.g. KEM ciphertext), while the classic part is
     * empty unless the chosen classic implementation itself supports message mode.
     * </p>
     *
     * @param session                 explicit policy and audit boundary
     * @param profile                 hybrid profile defining HKDF binding and
     *                                output length
     * @param classicAlgId            classic agreement algorithm identifier (for
     *                                example {@code "X25519"}, {@code "ECDH"},
     *                                {@code "DH"})
     * @param classicInitiatorPrivate initiator private key for the classic leg
     * @param classicPeerPublic       peer public key for the classic leg
     * @param classicSpec             optional classic context spec (may be
     *                                {@code null} if the algorithm supports a
     *                                default)
     * @param pqcAlgId                post-quantum agreement algorithm identifier
     *                                (for example {@code "ML-KEM"} exposed via
     *                                {@code KeyUsage.AGREEMENT})
     * @param pqcPeerPublic           peer public key for the PQC leg (encapsulation
     *                                side)
     * @param pqcSpec                 optional PQC context spec (may be {@code null}
     *                                if the algorithm supports a default)
     * @return initiator-side {@link HybridKexContext}
     * @throws NullPointerException if any required argument is {@code null}
     * @since 1.0
     */
    public static HybridKexContext initiator(ZeroEchoSession session, HybridKexProfile profile, String classicAlgId,
            PrivateKey classicInitiatorPrivate, PublicKey classicPeerPublic, ContextSpec classicSpec, String pqcAlgId,
            PublicKey pqcPeerPublic, ContextSpec pqcSpec) {

        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicAlgId, "classicAlgId");
        Objects.requireNonNull(classicInitiatorPrivate, "classicInitiatorPrivate");
        Objects.requireNonNull(classicPeerPublic, "classicPeerPublic");
        Objects.requireNonNull(pqcAlgId, "pqcAlgId");
        Objects.requireNonNull(pqcPeerPublic, "pqcPeerPublic");

        AgreementContext classic = null;
        MessageAgreementContext pqc = null;
        try {
            classic = session.createContext(classicAlgId, KeyUsage.AGREEMENT, classicInitiatorPrivate, classicSpec);
            classic.setPeerPublic(classicPeerPublic);
            pqc = session.createContext(pqcAlgId, KeyUsage.AGREEMENT, pqcPeerPublic, pqcSpec);
            return new HybridKexContext(profile, classic, pqc);
        } catch (RuntimeException | Error failure) { // NOPMD - close partial construction
            closeAfterFailure(pqc, failure);
            closeAfterFailure(classic, failure);
            throw failure;
        }
    }

    /**
     * Creates a responder-side hybrid KEX context.
     *
     * <p>
     * This method constructs:
     * </p>
     * <ul>
     * <li>a classic {@link AgreementContext} from the responder's classic
     * {@link PrivateKey} and configures it with the peer's classic
     * {@link PublicKey}, and</li>
     * <li>a PQC {@link MessageAgreementContext} from the responder's PQC
     * {@link PrivateKey} (decapsulation side).</li>
     * </ul>
     *
     * <p>
     * The returned {@link HybridKexContext} is typically used after receiving the
     * initiator's hybrid peer message and passing it to
     * {@link HybridKexContext#setPeerMessage(byte[])}.
     * </p>
     *
     * @param session                 explicit policy and audit boundary
     * @param profile                 hybrid profile defining HKDF binding and
     *                                output length
     * @param classicAlgId            classic agreement algorithm identifier
     * @param classicResponderPrivate responder private key for the classic leg
     * @param classicPeerPublic       peer public key for the classic leg
     * @param classicSpec             optional classic context spec (may be
     *                                {@code null})
     * @param pqcAlgId                post-quantum agreement algorithm identifier
     * @param pqcResponderPrivate     responder private key for the PQC leg
     *                                (decapsulation side)
     * @param pqcSpec                 optional PQC context spec (may be
     *                                {@code null})
     * @return responder-side {@link HybridKexContext}
     * @throws NullPointerException if any required argument is {@code null}
     * @since 1.0
     */
    public static HybridKexContext responder(ZeroEchoSession session, HybridKexProfile profile, String classicAlgId,
            PrivateKey classicResponderPrivate, PublicKey classicPeerPublic, ContextSpec classicSpec, String pqcAlgId,
            PrivateKey pqcResponderPrivate, ContextSpec pqcSpec) {

        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicAlgId, "classicAlgId");
        Objects.requireNonNull(classicResponderPrivate, "classicResponderPrivate");
        Objects.requireNonNull(classicPeerPublic, "classicPeerPublic");
        Objects.requireNonNull(pqcAlgId, "pqcAlgId");
        Objects.requireNonNull(pqcResponderPrivate, "pqcResponderPrivate");

        AgreementContext classic = null;
        MessageAgreementContext pqc = null;
        try {
            classic = session.createContext(classicAlgId, KeyUsage.AGREEMENT, classicResponderPrivate, classicSpec);
            classic.setPeerPublic(classicPeerPublic);
            pqc = session.createContext(pqcAlgId, KeyUsage.AGREEMENT, pqcResponderPrivate, pqcSpec);
            return new HybridKexContext(profile, classic, pqc);
        } catch (RuntimeException | Error failure) { // NOPMD - close partial construction
            closeAfterFailure(pqc, failure);
            closeAfterFailure(classic, failure);
            throw failure;
        }
    }

    /**
     * Creates an initiator-side hybrid KEX where the classic leg is message-based
     * (PAIR_MESSAGE).
     *
     * <p>
     * The classic message is the SPKI encoding of the initiator's classic public
     * key as produced by the underlying {@link MessageAgreementContext}. The PQC
     * message is the PQC encapsulation payload (typically KEM ciphertext).
     * </p>
     *
     * @param session                 explicit policy and audit boundary
     * @param profile                 hybrid profile defining HKDF binding and
     *                                output length
     * @param classicAlgId            classic agreement algorithm identifier (e.g.
     *                                "X25519", "ECDH", "DH")
     * @param classicInitiatorKeyPair classic initiator key pair wrapped as
     *                                {@code KeyPairKey}
     * @param classicSpec             classic context spec (may be {@code null} if
     *                                supported)
     * @param pqcAlgId                post-quantum agreement algorithm identifier
     *                                (e.g. "ML-KEM")
     * @param pqcPeerPublic           PQC peer public key (encapsulation side)
     * @param pqcSpec                 optional PQC context spec (may be
     *                                {@code null})
     * @return initiator-side {@link HybridKexContext}
     * @throws NullPointerException if any required argument is {@code null}
     * @since 1.0
     */
    public static HybridKexContext initiatorPairMessage(ZeroEchoSession session, HybridKexProfile profile,
            String classicAlgId, zeroecho.core.alg.common.agreement.KeyPairKey classicInitiatorKeyPair,
            ContextSpec classicSpec, String pqcAlgId, PublicKey pqcPeerPublic, ContextSpec pqcSpec) {

        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicAlgId, "classicAlgId");
        Objects.requireNonNull(classicInitiatorKeyPair, "classicInitiatorKeyPair");
        Objects.requireNonNull(pqcAlgId, "pqcAlgId");
        Objects.requireNonNull(pqcPeerPublic, "pqcPeerPublic");

        MessageAgreementContext classic = null;
        MessageAgreementContext pqc = null;
        try {
            classic = session.createContext(classicAlgId, KeyUsage.AGREEMENT, classicInitiatorKeyPair, classicSpec);
            pqc = session.createContext(pqcAlgId, KeyUsage.AGREEMENT, pqcPeerPublic, pqcSpec);
            return new HybridKexContext(profile, classic, pqc);
        } catch (RuntimeException | Error failure) { // NOPMD - close partial construction
            closeAfterFailure(pqc, failure);
            closeAfterFailure(classic, failure);
            throw failure;
        }
    }

    /**
     * Creates a responder-side hybrid KEX where the classic leg is message-based
     * (PAIR_MESSAGE).
     *
     * <p>
     * The responder must call {@link HybridKexContext#setPeerMessage(byte[])} with
     * the initiator's hybrid message before calling
     * {@link HybridKexContext#deriveSecret()}.
     * </p>
     *
     * @param session                 explicit policy and audit boundary
     * @param profile                 hybrid profile defining HKDF binding and
     *                                output length
     * @param classicAlgId            classic agreement algorithm identifier
     * @param classicResponderKeyPair classic responder key pair wrapped as
     *                                {@code KeyPairKey}
     * @param classicSpec             classic context spec (may be {@code null})
     * @param pqcAlgId                post-quantum agreement algorithm identifier
     * @param pqcResponderPrivate     PQC responder private key (decapsulation side)
     * @param pqcSpec                 optional PQC context spec (may be
     *                                {@code null})
     * @return responder-side {@link HybridKexContext}
     * @throws NullPointerException if any required argument is {@code null}
     * @since 1.0
     */
    public static HybridKexContext responderPairMessage(ZeroEchoSession session, HybridKexProfile profile,
            String classicAlgId, zeroecho.core.alg.common.agreement.KeyPairKey classicResponderKeyPair,
            ContextSpec classicSpec, String pqcAlgId, PrivateKey pqcResponderPrivate, ContextSpec pqcSpec) {

        Objects.requireNonNull(session, "session");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(classicAlgId, "classicAlgId");
        Objects.requireNonNull(classicResponderKeyPair, "classicResponderKeyPair");
        Objects.requireNonNull(pqcAlgId, "pqcAlgId");
        Objects.requireNonNull(pqcResponderPrivate, "pqcResponderPrivate");

        MessageAgreementContext classic = null;
        MessageAgreementContext pqc = null;
        try {
            classic = session.createContext(classicAlgId, KeyUsage.AGREEMENT, classicResponderKeyPair, classicSpec);
            pqc = session.createContext(pqcAlgId, KeyUsage.AGREEMENT, pqcResponderPrivate, pqcSpec);
            return new HybridKexContext(profile, classic, pqc);
        } catch (RuntimeException | Error failure) { // NOPMD - close partial construction
            closeAfterFailure(pqc, failure);
            closeAfterFailure(classic, failure);
            throw failure;
        }
    }

    private static void closeAfterFailure(CryptoContext context, Throwable failure) {
        if (context == null) {
            return;
        }
        try {
            context.close();
        } catch (IOException | RuntimeException closeFailure) { // NOPMD - preserve close failure
            failure.addSuppressed(closeFailure);
        }
    }
}
