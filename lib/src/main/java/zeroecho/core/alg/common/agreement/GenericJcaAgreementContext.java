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
package zeroecho.core.alg.common.agreement;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.AgreementContext;

/**
 * <h2>Generic JCA-based Key Agreement Context</h2>
 *
 * An {@link AgreementContext} backed by the standard JCA {@link KeyAgreement}
 * API. This class supports elliptic-curve and modern Diffie-Hellman variants
 * such as ECDH, XDH (X25519, X448), and others provided by the runtime or
 * configured provider.
 *
 * <p>
 * Instances of this context are created with a local {@link PrivateKey}, and
 * require the peer’s {@link PublicKey} to be provided later via
 * {@link #setPeerPublic(PublicKey)} before deriving the shared secret.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ol>
 * <li>Construct with local private key and algorithm name.</li>
 * <li>Call {@link #setPeerPublic(PublicKey)} with the remote party’s key.</li>
 * <li>Invoke {@link #deriveSecret()} to compute the raw shared secret.</li>
 * <li>Optionally call {@link #close()} (no resources are held here).</li>
 * </ol>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>The derived secret is the raw key agreement output; protocols should
 * apply a KDF before using it as a symmetric key.</li>
 * <li>If {@code provider} is {@code null}, the default JCA provider lookup is
 * used; otherwise, the specific provider is requested.</li>
 * </ul>
 *
 * @since 1.0
 */
public class GenericJcaAgreementContext implements AgreementContext {
    private final CryptoAlgorithm algorithm;
    private final PrivateKey privateKey;
    private final String jcaName; // e.g., "ECDH" or "XDH" (or "X25519"/"X448")
    private final String provider; // null => default
    private PublicKey peer;

    /**
     * Creates a new JCA-based agreement context.
     *
     * @param alg      the enclosing {@link CryptoAlgorithm} definition
     * @param priv     the local private key used in the key agreement
     * @param jcaName  the JCA algorithm name (e.g., {@code "ECDH"},
     *                 {@code "X25519"})
     * @param provider optional JCA provider name, or {@code null} to use the
     *                 default
     * @throws NullPointerException if {@code alg}, {@code priv}, or {@code jcaName}
     *                              is {@code null}
     */
    public GenericJcaAgreementContext(CryptoAlgorithm alg, PrivateKey priv, String jcaName, String provider) {
        this.algorithm = alg;
        this.privateKey = priv;
        this.jcaName = jcaName;
        this.provider = provider;
    }

    /**
     * Returns the {@link CryptoAlgorithm} that created this context.
     *
     * @return the parent algorithm definition
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the local private key bound to this agreement context.
     *
     * @return the private {@link Key} used in the key agreement
     */
    @Override
    public Key key() {
        return privateKey;
    }

    /**
     * Assigns the peer’s public key for the key agreement.
     *
     * <p>
     * This must be called before {@link #deriveSecret()}, otherwise the context
     * cannot complete the protocol.
     * </p>
     *
     * @param peer the remote party’s public key
     */
    @Override
    public void setPeerPublic(PublicKey peer) {
        this.peer = peer;
    }

    /**
     * Computes the raw shared secret using the configured local private key and the
     * previously assigned peer public key.
     *
     * <p>
     * Internally this delegates to the JCA {@link KeyAgreement} API with the given
     * {@code jcaName} and optional provider.
     * </p>
     *
     * @return the raw shared secret as a byte array
     * @throws IllegalStateException    if the peer key has not been set
     * @throws IllegalArgumentException if key agreement fails due to invalid keys,
     *                                  unsupported parameters, or provider errors
     */
    @Override
    public byte[] deriveSecret() {
        if (peer == null) {
            throw new IllegalStateException("Peer public key not set");
        }
        try {
            KeyAgreement ka = (provider == null) ? KeyAgreement.getInstance(jcaName)
                    : KeyAgreement.getInstance(jcaName, provider);
            ka.init(privateKey);
            ka.doPhase(peer, true);
            return ka.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("KeyAgreement failed for " + jcaName, e);
        }
    }

    /**
     * Closes this context.
     *
     * <p>
     * For this implementation, there are no system resources to release, so the
     * method is a no-op. It exists to satisfy the {@link AgreementContext} contract
     * and for future compatibility.
     * </p>
     */
    @Override
    public void close() {
        /* nothing to release */
    }
}
