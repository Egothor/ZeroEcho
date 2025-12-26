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
package zeroecho.sdk.builders;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import zeroecho.core.CryptoAlgorithms;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.common.agreement.KeyPairKey;
import zeroecho.core.context.AgreementContext;
import zeroecho.core.context.MessageAgreementContext;
import zeroecho.core.spec.ContextSpec;
import zeroecho.sdk.hybrid.kex.HybridKexContext;
import zeroecho.sdk.hybrid.kex.HybridKexExporter;
import zeroecho.sdk.hybrid.kex.HybridKexPolicy;
import zeroecho.sdk.hybrid.kex.HybridKexProfile;
import zeroecho.sdk.hybrid.kex.HybridKexTranscript;

/**
 * Fluent builder for constructing hybrid KEX contexts.
 *
 * <p>
 * The builder supports the two practical hybrid variants:
 * </p>
 * <ul>
 * <li><b>CLASSIC_AGREEMENT + KEM_ADAPTER</b> (classic peer public is provided
 * out-of-band)</li>
 * <li><b>PAIR_MESSAGE + KEM_ADAPTER</b> (classic public key is carried in the
 * hybrid message)</li>
 * </ul>
 *
 * <p>
 * The builder also supports transcript binding and optional policy enforcement
 * before returning the context.
 * </p>
 *
 * <h2>Usage sketch</h2> <pre>{@code
 * HybridKexContext ctx = HybridKexBuilder.builder()
 *     .profile(HybridKexProfile.defaultProfile(32))
 *     .transcript(new HybridKexTranscript().addUtf8("suite", "X25519+MLKEM768"))
 *     .policy(new HybridKexPolicy(128, 192, 32))
 *     .classicAgreement()
 *         .algorithm("Xdh").spec(XdhSpec.X25519)
 *         .privateKey(alicePriv).peerPublic(bobPub)
 *     .pqcKem()
 *         .algorithm("ML-KEM").peerPublic(bobPqcPub)
 *     .buildInitiator();
 * }</pre>
 *
 * <p>
 * Instances are mutable and not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class HybridKexBuilder {

    private HybridKexProfile profile;
    private HybridKexTranscript transcript;
    private HybridKexPolicy policy;

    private ClassicMode classicMode;

    private String classicAlgId;
    private ContextSpec classicSpec;
    private PrivateKey classicPrivate;
    private PublicKey classicPeerPublic;
    private KeyPairKey classicKeyPair;

    private String pqcAlgId;
    private ContextSpec pqcSpec;
    private PublicKey pqcPeerPublic;
    private PrivateKey pqcPrivate;

    private HybridKexBuilder() {
        // builder
    }

    /**
     * Creates a new builder instance.
     *
     * @return new builder
     */
    public static HybridKexBuilder builder() {
        return new HybridKexBuilder();
    }

    /**
     * Sets the hybrid profile (HKDF salt/info/output length).
     *
     * @param profile profile (must not be null)
     * @return this builder
     */
    public HybridKexBuilder profile(HybridKexProfile profile) {
        this.profile = Objects.requireNonNull(profile, "profile");
        return this;
    }

    /**
     * Optional transcript used to bind HKDF {@code info}.
     *
     * <p>
     * If provided, its bytes are concatenated to the profile {@code hkdfInfo} with
     * a single zero byte separator. This preserves the profile label as a domain
     * separator while incorporating handshake context.
     * </p>
     *
     * @param transcript transcript (may be null to clear)
     * @return this builder
     */
    public HybridKexBuilder transcript(HybridKexTranscript transcript) {
        this.transcript = transcript;
        return this;
    }

    /**
     * Optional hybrid policy enforcement.
     *
     * @param policy policy (may be null to clear)
     * @return this builder
     */
    public HybridKexBuilder policy(HybridKexPolicy policy) {
        this.policy = policy;
        return this;
    }

    /**
     * Selects the classic leg in {@link ClassicMode#CLASSIC_AGREEMENT} mode.
     *
     * <p>
     * In this mode, the classic peer public key is assumed to be available
     * out-of-band (for example via a certificate, a directory, or a higher-level
     * handshake message). The hybrid wire message therefore typically carries only
     * the PQC payload (KEM ciphertext), while the classic leg is configured via
     * {@link AgreementContext#setPeerPublic(PublicKey)}.
     * </p>
     *
     * <p>
     * Calling this method resets any previously configured {@code PAIR_MESSAGE}
     * inputs ({@link #classicKeyPair}) to prevent ambiguous configuration.
     * </p>
     *
     * @return classic agreement configurator
     * @since 1.0
     */
    public ClassicAgreement classicAgreement() {
        this.classicMode = ClassicMode.CLASSIC_AGREEMENT;
        this.classicKeyPair = null;
        return new ClassicAgreement(this);
    }

    /**
     * Selects the classic leg in {@link ClassicMode#PAIR_MESSAGE} mode.
     *
     * <p>
     * In this mode, the classic leg is message-capable: the public key is carried
     * as an explicit classic message (typically an SPKI encoding) and becomes part
     * of the hybrid peer message. This enables a fully message-oriented handshake
     * where both legs contribute to the wire payload (classic public-key message +
     * PQC ciphertext).
     * </p>
     *
     * <p>
     * Calling this method resets any previously configured
     * {@code CLASSIC_AGREEMENT} inputs ({@link #classicPrivate} and
     * {@link #classicPeerPublic}) to prevent ambiguous configuration.
     * </p>
     *
     * @return classic pair-message configurator
     * @since 1.0
     */
    public ClassicPairMessage classicPairMessage() {
        this.classicMode = ClassicMode.PAIR_MESSAGE;
        this.classicPrivate = null;
        this.classicPeerPublic = null;
        return new ClassicPairMessage(this);
    }

    /**
     * Selects configuration of the post-quantum leg (KEM adapter).
     *
     * <p>
     * The PQC leg is always treated as a message-based agreement:
     * </p>
     * <ul>
     * <li>Initiator is created from the recipient's PQC {@link PublicKey} and
     * produces a message (typically a ciphertext) via
     * {@link MessageAgreementContext#getPeerMessage()}.</li>
     * <li>Responder is created from the recipient's PQC {@link PrivateKey} and
     * consumes the peer message via
     * {@link MessageAgreementContext#setPeerMessage(byte[])}.</li>
     * </ul>
     *
     * @return PQC KEM configurator
     * @since 1.0
     */
    public PqcKem pqcKem() {
        return new PqcKem(this);
    }

    /**
     * Builds initiator-side context.
     *
     * @return initiator context
     * @throws IOException if underlying context creation fails
     */
    public HybridKexContext buildInitiator() throws IOException {
        validateCommon();

        AgreementContext classic;
        if (classicMode == ClassicMode.CLASSIC_AGREEMENT) {
            if (classicPrivate == null || classicPeerPublic == null) {
                throw new IllegalStateException(
                        "classic private key and peer public must be set for CLASSIC_AGREEMENT");
            }
            classic = CryptoAlgorithms.create(classicAlgId, KeyUsage.AGREEMENT, classicPrivate, classicSpec);
            classic.setPeerPublic(classicPeerPublic);
        } else if (classicMode == ClassicMode.PAIR_MESSAGE) {
            if (classicKeyPair == null) {
                throw new IllegalStateException("classic key pair must be set for PAIR_MESSAGE");
            }
            classic = CryptoAlgorithms.create(classicAlgId, KeyUsage.AGREEMENT, classicKeyPair, classicSpec);
        } else {
            throw new IllegalStateException("classic mode must be selected");
        }

        if (pqcPeerPublic == null) {
            throw new IllegalStateException("pqc peer public must be set for initiator");
        }
        MessageAgreementContext pqc = CryptoAlgorithms.create(pqcAlgId, KeyUsage.AGREEMENT, pqcPeerPublic, pqcSpec);

        HybridKexProfile effective = effectiveProfile();
        if (policy != null) {
            policy.enforce(effective, classic, pqc);
        }
        return new HybridKexContext(effective, classic, pqc);
    }

    /**
     * Builds responder-side context.
     *
     * @return responder context
     * @throws IOException if underlying context creation fails
     */
    public HybridKexContext buildResponder() throws IOException {
        validateCommon();

        AgreementContext classic;
        if (classicMode == ClassicMode.CLASSIC_AGREEMENT) {
            if (classicPrivate == null || classicPeerPublic == null) {
                throw new IllegalStateException(
                        "classic private key and peer public must be set for CLASSIC_AGREEMENT");
            }
            classic = CryptoAlgorithms.create(classicAlgId, KeyUsage.AGREEMENT, classicPrivate, classicSpec);
            classic.setPeerPublic(classicPeerPublic);
        } else if (classicMode == ClassicMode.PAIR_MESSAGE) {
            if (classicKeyPair == null) {
                throw new IllegalStateException("classic key pair must be set for PAIR_MESSAGE");
            }
            classic = CryptoAlgorithms.create(classicAlgId, KeyUsage.AGREEMENT, classicKeyPair, classicSpec);
        } else {
            throw new IllegalStateException("classic mode must be selected");
        }

        if (pqcPrivate == null) {
            throw new IllegalStateException("pqc private key must be set for responder");
        }
        MessageAgreementContext pqc = CryptoAlgorithms.create(pqcAlgId, KeyUsage.AGREEMENT, pqcPrivate, pqcSpec);

        HybridKexProfile effective = effectiveProfile();
        if (policy != null) {
            policy.enforce(effective, classic, pqc);
        }
        return new HybridKexContext(effective, classic, pqc);
    }

    /**
     * Creates an exporter seeded from a derived OKM value.
     *
     * @param okm derived OKM (for example {@link HybridKexContext#deriveSecret()})
     * @return exporter
     */
    public HybridKexExporter exporterFromOkm(byte[] okm) {
        validateCommon();
        HybridKexProfile effective = effectiveProfile();
        return new HybridKexExporter(okm, effective.hkdfSalt());
    }

    private void validateCommon() {
        if (profile == null) {
            throw new IllegalStateException("profile must be set");
        }
        if (classicMode == null) {
            throw new IllegalStateException("classic mode must be selected");
        }
        if (classicAlgId == null) {
            throw new IllegalStateException("classic algorithm id must be set");
        }
        if (pqcAlgId == null) {
            throw new IllegalStateException("pqc algorithm id must be set");
        }
    }

    private HybridKexProfile effectiveProfile() {
        byte[] info0 = profile.hkdfInfo();
        byte[] t = (transcript == null) ? null : transcript.toByteArray();

        if (t == null || t.length == 0) {
            return profile;
        }

        byte[] base = (info0 == null) ? new byte[0] : info0.clone();
        byte[] merged = new byte[base.length + 1 + t.length];
        System.arraycopy(base, 0, merged, 0, base.length);
        merged[base.length] = 0;
        System.arraycopy(t, 0, merged, base.length + 1, t.length);

        return new HybridKexProfile(profile.hkdfSalt(), merged, profile.outLenBytes());
    }

    /**
     * Determines how the classic (pre-quantum) agreement leg is wired into the
     * hybrid handshake.
     *
     * <p>
     * The classic leg is always an {@link AgreementContext}, but there are two
     * operational models:
     * </p>
     * <ul>
     * <li>{@link #CLASSIC_AGREEMENT}: the peer public key is supplied out-of-band
     * (not transported by the hybrid message). This corresponds to the traditional
     * DH/ECDH/XDH usage pattern where the protocol already has a mechanism to
     * convey or authenticate the peer public key (certificate, static key, or
     * separate handshake structure).</li>
     * <li>{@link #PAIR_MESSAGE}: the classic leg is message-capable and
     * emits/consumes a public-key message (typically SPKI) through
     * {@link MessageAgreementContext}. In this model, the classic public key
     * travels inside the hybrid peer message alongside the PQC payload, enabling a
     * fully message-oriented exchange.</li>
     * </ul>
     *
     * <p>
     * This enum is internal to the builder but is documented because it defines the
     * wire semantics of the resulting {@link HybridKexContext} and determines which
     * builder inputs are required.
     * </p>
     *
     * @since 1.0
     */
    private enum ClassicMode {

        /**
         * Classic agreement where the peer public key is provided out-of-band and
         * configured via {@link AgreementContext#setPeerPublic(PublicKey)}.
         *
         * @since 1.0
         */
        CLASSIC_AGREEMENT,

        /**
         * Classic agreement where the classic public key is carried in-band as a
         * message produced/consumed via
         * {@link MessageAgreementContext#getPeerMessage()} and
         * {@link MessageAgreementContext#setPeerMessage(byte[])}.
         *
         * @since 1.0
         */
        PAIR_MESSAGE
    }

    /**
     * Configurator for the classic leg in {@link ClassicMode#CLASSIC_AGREEMENT}
     * mode.
     *
     * <p>
     * Required inputs before building:
     * </p>
     * <ul>
     * <li>{@link #algorithm(String)} - classic algorithm id (for example
     * {@code "Xdh"})</li>
     * <li>{@link #privateKey(PrivateKey)} - local classic private key</li>
     * <li>{@link #peerPublic(PublicKey)} - peer classic public key
     * (out-of-band)</li>
     * </ul>
     *
     * <p>
     * Optional inputs:
     * </p>
     * <ul>
     * <li>{@link #spec(ContextSpec)} - algorithm-specific context spec (for example
     * {@code XdhSpec.X25519})</li>
     * </ul>
     *
     * <p>
     * After configuring the classic leg, continue with {@link #pqcKem()} to
     * configure the PQC leg.
     * </p>
     *
     * @since 1.0
     */
    public static final class ClassicAgreement {
        private final HybridKexBuilder parent;

        private ClassicAgreement(HybridKexBuilder parent) {
            this.parent = parent;
        }

        /**
         * Sets the classic agreement algorithm identifier.
         *
         * <p>
         * Example for X25519 in this project: use {@code "Xdh"} with
         * {@code XdhSpec.X25519}.
         * </p>
         *
         * @param algId algorithm id (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code algId} is null
         * @since 1.0
         */
        public ClassicAgreement algorithm(String algId) {
            parent.classicAlgId = Objects.requireNonNull(algId, "algId");
            return this;
        }

        /**
         * Sets the classic context spec (algorithm parameters).
         *
         * @param spec spec (may be null if the algorithm provides a default)
         * @return this configurator
         * @since 1.0
         */
        public ClassicAgreement spec(ContextSpec spec) {
            parent.classicSpec = spec;
            return this;
        }

        /**
         * Sets the local private key for the classic leg.
         *
         * @param key private key (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code key} is null
         * @since 1.0
         */
        public ClassicAgreement privateKey(PrivateKey key) {
            parent.classicPrivate = Objects.requireNonNull(key, "key");
            return this;
        }

        /**
         * Sets the peer public key for the classic leg.
         *
         * <p>
         * In {@link ClassicMode#CLASSIC_AGREEMENT} this key is assumed to be obtained
         * out-of-band.
         * </p>
         *
         * @param key peer public key (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code key} is null
         * @since 1.0
         */
        public ClassicAgreement peerPublic(PublicKey key) {
            parent.classicPeerPublic = Objects.requireNonNull(key, "key");
            return this;
        }

        /**
         * Continues with PQC (KEM adapter) leg configuration.
         *
         * @return PQC configurator
         * @since 1.0
         */
        public PqcKem pqcKem() {
            return parent.pqcKem();
        }
    }

    /**
     * Configurator for the classic leg in {@link ClassicMode#PAIR_MESSAGE} mode.
     *
     * <p>
     * Required inputs before building:
     * </p>
     * <ul>
     * <li>{@link #algorithm(String)} - classic algorithm id (for example
     * {@code "Xdh"})</li>
     * <li>{@link #keyPair(KeyPairKey)} - local classic key pair wrapped as
     * {@link KeyPairKey}</li>
     * </ul>
     *
     * <p>
     * Optional inputs:
     * </p>
     * <ul>
     * <li>{@link #spec(ContextSpec)} - algorithm-specific context spec (for example
     * {@code XdhSpec.X25519})</li>
     * </ul>
     *
     * <p>
     * In this mode, the classic leg contributes a public-key message (typically
     * SPKI bytes) to the hybrid peer message. The peer public key is therefore
     * learned from {@link HybridKexContext#setPeerMessage(byte[])} rather than
     * being supplied out-of-band.
     * </p>
     *
     * @since 1.0
     */
    public static final class ClassicPairMessage {
        private final HybridKexBuilder parent;

        private ClassicPairMessage(HybridKexBuilder parent) {
            this.parent = parent;
        }

        /**
         * Sets the classic agreement algorithm identifier.
         *
         * @param algId algorithm id (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code algId} is null
         * @since 1.0
         */
        public ClassicPairMessage algorithm(String algId) {
            parent.classicAlgId = Objects.requireNonNull(algId, "algId");
            return this;
        }

        /**
         * Sets the classic context spec (algorithm parameters).
         *
         * @param spec spec (may be null if the algorithm provides a default)
         * @return this configurator
         * @since 1.0
         */
        public ClassicPairMessage spec(ContextSpec spec) {
            parent.classicSpec = spec;
            return this;
        }

        /**
         * Sets the local classic key pair.
         *
         * <p>
         * The key pair is wrapped into {@link KeyPairKey} to match the
         * {@code PAIR_MESSAGE} capability registered in core.
         * </p>
         *
         * @param keyPair key pair wrapper (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code keyPair} is null
         * @since 1.0
         */
        public ClassicPairMessage keyPair(KeyPairKey keyPair) {
            parent.classicKeyPair = Objects.requireNonNull(keyPair, "keyPair");
            return this;
        }

        /**
         * Continues with PQC (KEM adapter) leg configuration.
         *
         * @return PQC configurator
         * @since 1.0
         */
        public PqcKem pqcKem() {
            return parent.pqcKem();
        }
    }

    /**
     * Configurator for the PQC leg (KEM adapter).
     *
     * <p>
     * Required inputs differ by role:
     * </p>
     * <ul>
     * <li><b>Initiator</b> requires {@link #peerPublic(PublicKey)} (recipient PQC
     * public key).</li>
     * <li><b>Responder</b> requires {@link #privateKey(PrivateKey)} (recipient PQC
     * private key).</li>
     * </ul>
     *
     * <p>
     * The PQC leg is always message-based: initiator produces a peer message
     * (ciphertext) and responder consumes it. The hybrid context transports this
     * payload as the PQC part of the hybrid message.
     * </p>
     *
     * @since 1.0
     */
    public static final class PqcKem {
        private final HybridKexBuilder parent;

        private PqcKem(HybridKexBuilder parent) {
            this.parent = parent;
        }

        /**
         * Sets the PQC algorithm identifier.
         *
         * @param algId algorithm id (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code algId} is null
         * @since 1.0
         */
        public PqcKem algorithm(String algId) {
            parent.pqcAlgId = Objects.requireNonNull(algId, "algId");
            return this;
        }

        /**
         * Sets the PQC context spec (algorithm parameters).
         *
         * @param spec spec (may be null if the algorithm provides a default)
         * @return this configurator
         * @since 1.0
         */
        public PqcKem spec(ContextSpec spec) {
            parent.pqcSpec = spec;
            return this;
        }

        /**
         * Sets the recipient PQC public key for initiator-side construction.
         *
         * @param key recipient public key (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code key} is null
         * @since 1.0
         */
        public PqcKem peerPublic(PublicKey key) {
            parent.pqcPeerPublic = Objects.requireNonNull(key, "key");
            return this;
        }

        /**
         * Sets the recipient PQC private key for responder-side construction.
         *
         * @param key recipient private key (must not be null)
         * @return this configurator
         * @throws NullPointerException if {@code key} is null
         * @since 1.0
         */
        public PqcKem privateKey(PrivateKey key) {
            parent.pqcPrivate = Objects.requireNonNull(key, "key");
            return this;
        }

        /**
         * Builds an initiator-side {@link HybridKexContext} using the current builder
         * configuration.
         *
         * @return initiator context
         * @throws IOException           if underlying context creation fails
         * @throws IllegalStateException if required configuration for initiator role is
         *                               missing
         * @since 1.0
         */
        public HybridKexContext buildInitiator() throws IOException {
            return parent.buildInitiator();
        }

        /**
         * Builds a responder-side {@link HybridKexContext} using the current builder
         * configuration.
         *
         * @return responder context
         * @throws IOException           if underlying context creation fails
         * @throws IllegalStateException if required configuration for responder role is
         *                               missing
         * @since 1.0
         */
        public HybridKexContext buildResponder() throws IOException {
            return parent.buildResponder();
        }
    }

}
