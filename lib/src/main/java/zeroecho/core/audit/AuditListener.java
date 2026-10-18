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
package zeroecho.core.audit;

import java.security.Key;
import java.security.KeyPair;
import java.util.Map;

import zeroecho.core.KeyUsage;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Listener for structured audit events emitted by audited crypto contexts.
 *
 * <p>
 * The listener receives lifecycle, progress, metadata, and failure callbacks
 * from proxies created by utilities such as {@code AuditedContexts}. All
 * default methods are no-ops so that implementors can override only the events
 * of interest.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * AuditListener listener = new AuditListener() {
 *     &#64;Override
 *     public void onProgress(String ctxId, long bodyBytes, long trailerBytes) {
 *         System.out.println("ctx=" + ctxId + " body=" + bodyBytes + " trailer=" + trailerBytes);
 *     }
 *     &#64;Override
 *     public void onFailure(String ctxId, String stage, String op, Throwable cause) {
 *         logger.warn("ctx={} stage={} op={}", ctxId, stage, op, cause);
 *     }
 * };
 * }</pre>
 *
 * <p>
 * Unless stated otherwise, all methods are best-effort and are not guaranteed
 * to be called for every possible code path. Implementations should be
 * defensive and tolerate repeated or missing events.
 * </p>
 */
public interface AuditListener {
    /**
     * Emitted after key pair generation via SPI.
     *
     * <p>
     * This event signals successful generation and provides the resulting pair.
     * Implementations must not persist private key material unless explicitly
     * required by policy.
     * </p>
     *
     * @param id       an algorithm or implementation identifier supplied by the
     *                 generator
     * @param provider a provider or vendor label
     * @param spec     the algorithm key specification used for generation; never
     *                 null
     * @param kp       the generated key pair; never null
     */
    default void onKeyGenerated(String id, String provider, AlgorithmKeySpec spec, KeyPair kp) {
        // empty
    }

    /**
     * Emitted after a key is constructed or imported.
     *
     * <p>
     * This event can be used to track import flows separately from on-device
     * generation.
     * </p>
     *
     * @param id       an algorithm or implementation identifier supplied by the
     *                 builder
     * @param provider a provider or vendor label
     * @param spec     the algorithm key specification used for construction; never
     *                 null
     * @param key      the constructed or imported key; never null
     */
    default void onKeyBuilt(String id, String provider, AlgorithmKeySpec spec, Key key) {
        // empty
    }

    /**
     * Emitted when a key was destroyed.
     *
     * <p>
     * Destruction is best-effort and may not be observable for all key types.
     * Receipt of this event does not guarantee secure erasure.
     * </p>
     *
     * @param id       an algorithm or implementation identifier related to the key
     * @param provider a provider or vendor label
     * @param key      the key being destroyed; may be null for non-extractable
     *                 handles
     */
    default void onKeyDestroyed(String id, String provider, Key key) {
        // empty
    }

    /**
     * Creation event with correlation id and non-secret specification metadata.
     *
     * <p>
     * The metadata map is a best-effort summary extracted from the specification
     * object and must not include secret values. Typical entries include mode, tag
     * length, IV length, and header codec id.
     * </p>
     *
     * @param ctxId          a generated correlation id unique to the wrapped
     *                       context instance
     * @param algoId         an algorithm or implementation identifier; never null
     *                       but may be "unknown"
     * @param provider       a provider or vendor label; never null but may be
     *                       "unknown"
     * @param role           the usage role associated with the context
     * @param keyFingerprint a short, non-reversible fingerprint of the key material
     *                       or "n/a"
     * @param specMeta       a map of non-secret specification attributes, or null
     *                       if unavailable
     */
    default void onContextCreatedMeta(String ctxId, String algoId, String provider, KeyUsage role, // NOPMD
            String keyFingerprint, Map<String, Object> specMeta) {
        // empty
    }

    /**
     * Streaming progress for a context, split into body and trailer bytes.
     *
     * <p>
     * For TagEngine-style streams, the trailer typically corresponds to an
     * authentication tag that is excluded from the body count.
     * </p>
     *
     * @param ctxId        the correlation id for the context instance
     * @param bodyBytes    cumulative number of body bytes observed so far
     * @param trailerBytes cumulative number of trailer bytes observed so far
     */
    default void onProgress(String ctxId, long bodyBytes, long trailerBytes) {
        // empty
    }

    /**
     * Notification that a tag or signature was produced at end of stream.
     *
     * <p>
     * This is typically emitted for SIGN, MAC, or DIGEST roles when the tag length
     * is known and no verification was requested.
     * </p>
     *
     * @param ctxId     the correlation id for the context instance
     * @param tagLength the length, in bytes, of the produced tag
     * @param policy    a string label describing the verification or emission
     *                  policy
     */
    default void onTagProduced(String ctxId, int tagLength, String policy) {
        // empty
    }

    /**
     * Verification outcome for contexts operating in verify mode.
     *
     * <p>
     * The expected tag source indicates how the verifier obtained the expected
     * value, for example provided directly by the caller, read from the stream
     * tail, or parsed from a header.
     * </p>
     *
     * @param ctxId          the correlation id for the context instance
     * @param ok             true if verification succeeded, false otherwise
     * @param policy         a string label describing the verification policy in
     *                       effect
     * @param expectedSource expected tag provenance, for example "provided",
     *                       "tail", or "header"
     * @param tagLength      the length, in bytes, of the expected tag
     */
    default void onVerifyResult(String ctxId, boolean ok, String policy, String expectedSource, int tagLength) {
        // empty
    }

    /**
     * Notification that a header was written to a stream.
     *
     * <p>
     * Only lengths are reported. No secret material is exposed.
     * </p>
     *
     * @param ctxId     the correlation id for the context instance
     * @param codecId   an identifier for the header codec used
     * @param headerLen total header length in bytes
     * @param ivLen     initialization vector length in bytes, or 0 if none
     * @param saltLen   salt length in bytes, or 0 if none
     * @param aadLen    associated data length in bytes, or 0 if none
     */
    default void onHeaderWritten(String ctxId, String codecId, int headerLen, int ivLen, int saltLen, int aadLen) {
        // empty
    }

    /**
     * Notification that a header was read from a stream.
     *
     * <p>
     * Only lengths are reported. No secret material is exposed.
     * </p>
     *
     * @param ctxId     the correlation id for the context instance
     * @param codecId   an identifier for the header codec used
     * @param headerLen total header length in bytes
     * @param ivLen     initialization vector length in bytes, or 0 if none
     * @param saltLen   salt length in bytes, or 0 if none
     * @param aadLen    associated data length in bytes, or 0 if none
     */
    default void onHeaderRead(String ctxId, String codecId, int headerLen, int ivLen, int saltLen, int aadLen) {
        // empty
    }

    /**
     * Notification about random material generation.
     *
     * <p>
     * Examples include IVs, nonces, salts, or keys created via a secure RNG.
     * </p>
     *
     * @param ctxId  the correlation id for the context instance
     * @param kind   a label describing the material kind, for example "iv", "salt",
     *               or "keygen"
     * @param rng    a label or provider name for the random source
     * @param length the number of bytes generated
     */
    default void onRandomMaterial(String ctxId, String kind, String rng, int length) {
        // empty
    }

    /**
     * Summary of key derivation function usage.
     *
     * <p>
     * Implementations can use this for parameter auditing and policy checks.
     * </p>
     *
     * @param ctxId      the correlation id for the context instance
     * @param kdf        the KDF identifier, for example "HKDF" or "PBKDF2"
     * @param saltLen    salt length in bytes, or 0 if none
     * @param infoLen    info/context length in bytes, or 0 if none
     * @param outLen     length in bytes of the derived output
     * @param iterations iteration count when applicable, or null if not applicable
     */
    default void onKdfUsed(String ctxId, String kdf, int saltLen, int infoLen, int outLen, Integer iterations) {
        // empty
    }

    /**
     * Failure during streaming or reflective invocation.
     *
     * <p>
     * The stage describes the processing phase, while the op gives a short
     * operation label such as "read" or "invoke:deriveSecret".
     * </p>
     *
     * @param ctxId the correlation id for the context instance
     * @param stage a coarse-grained stage label, for example "read" or "invoke"
     * @param op    a fine-grained operation label, for example "wrap", "attach", or
     *              "invoke:setPeerPublic"
     * @param cause the exception that caused the failure; never null
     */
    default void onFailure(String ctxId, String stage, String op, Throwable cause) {
        // empty
    }

    /**
     * Closure notification with totals and elapsed time.
     *
     * <p>
     * This event reports cumulative body and trailer byte counts and the duration
     * in milliseconds between creation and closure.
     * </p>
     *
     * @param ctxId          the correlation id for the context instance
     * @param bodyBytes      total body bytes processed
     * @param trailerBytes   total trailer bytes processed
     * @param durationMillis processing duration in milliseconds, minimum of 1
     */
    default void onContextClosed(String ctxId, long bodyBytes, long trailerBytes, long durationMillis) {
        // empty
    }

    /**
     * Notification that a peer public key was provided to an agreement context.
     *
     * <p>
     * The fingerprint is a short, non-reversible identifier suitable for logs.
     * </p>
     *
     * @param ctxId           the correlation id for the context instance
     * @param peerFingerprint a short, non-reversible fingerprint of the peer public
     *                        key
     */
    default void onAgreementPeerSet(String ctxId, String peerFingerprint) {
        // empty
    }

    /**
     * Notification that an agreement secret was derived.
     *
     * <p>
     * Only the length is reported. The secret value itself is never exposed.
     * </p>
     *
     * @param ctxId        the correlation id for the context instance
     * @param secretLength the derived secret length in bytes, or -1 if unknown
     */
    default void onAgreementDerived(String ctxId, int secretLength) {
        // empty
    }

    /**
     * Notification that a peer message was provided to a message agreement context.
     *
     * @param ctxId  the correlation id for the context instance
     * @param msgLen the provided message length in bytes
     */
    default void onAgreementPeerMessageSet(String ctxId, int msgLen) {
        // empty
    }

    /**
     * Notification that a peer message was retrieved from a message agreement
     * context.
     *
     * @param ctxId  the correlation id for the context instance
     * @param msgLen the retrieved message length in bytes, or -1 if unavailable
     */
    default void onAgreementPeerMessageGet(String ctxId, int msgLen) {
        // empty
    }

    /**
     * Legacy cumulative byte counter for any role.
     *
     * <p>
     * Prefer {@link #onProgress(String, long, long)} for trailer-aware accounting.
     * </p>
     *
     * @param role  the usage role associated with the counted bytes
     * @param count the cumulative number of bytes observed so far
     */
    default void onBytes(KeyUsage role, long count) {
        // empty
    }

    /**
     * Legacy KEM encapsulation event.
     *
     * <p>
     * Prefer id-scoped events such as
     * {@link #onContextCreatedMeta(String, String, String, KeyUsage, String, Map)}
     * combined with higher level KEM notifications when available.
     * </p>
     *
     * @param ciphertextLength   the length, in bytes, of the produced ciphertext,
     *                           or -1 if unknown
     * @param sharedSecretLength the length, in bytes, of the produced shared
     *                           secret, or -1 if unknown
     */
    default void onKemEncapsulated(int ciphertextLength, int sharedSecretLength) {
        // empty
    }

    /**
     * Legacy KEM decapsulation event.
     *
     * @param sharedSecretLength the length, in bytes, of the decapsulated shared
     *                           secret, or -1 if unknown
     */
    default void onKemDecapsulated(int sharedSecretLength) {
        // empty
    }

    /**
     * Returns a ready-to-use listener that performs no actions.
     *
     * <p>
     * This is convenient for tests and for configuring systems where auditing is
     * optional.
     * </p>
     *
     * @return a no-op listener instance
     */
    static AuditListener noop() {
        return new AuditListener() {
        };
    }
}
