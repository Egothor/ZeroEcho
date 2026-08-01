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
package zeroecho.pki.impl.framework.x509.bc;

import java.io.IOException;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.PkiSigningBus.SignContinuation;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.util.async.AsyncState;

/**
 * {@link ContentSigner} implementation that delegates the actual signature
 * operation to {@link PkiSigningBus}.
 *
 * <p>
 * This class adapts the synchronous Bouncy Castle {@link ContentSigner}
 * contract to the PKI runtime signing boundary represented by
 * {@link PkiSigningBus}. Bouncy Castle writes the to-be-signed bytes into the
 * output stream returned by {@link #getOutputStream()}, and when
 * {@link #getSignature()} is invoked this signer atomically completes the
 * file-backed content and submits its durable reference to the PKI signing bus.
 * </p>
 *
 * <p>
 * Although the underlying signing path is modeled as a durable asynchronous
 * workflow, this adapter exposes a synchronous caller experience required by
 * Bouncy Castle. It therefore blocks in {@link #getSignature()} until the
 * delegated workflow reaches a terminal state or until the configured
 * time-to-live expires.
 * </p>
 *
 * <h2>Execution model</h2>
 * <ul>
 * <li>The to-be-signed payload is streamed to the runtime-owned staged-content
 * store with {@code long} accounting.</li>
 * <li>A synthetic system owner and purpose are used to submit the signing
 * operation.</li>
 * <li>A fresh client operation identifier is generated for each signature
 * request and canonicalized by the signing bus.</li>
 * <li>The signer polls the bus by repeatedly calling
 * {@link PkiSigningBus#sweep(Instant)} and {@link PkiSigningBus#status(PkiId)}
 * until the workflow succeeds, fails, or times out.</li>
 * <li>Every submitted operation is retired through
 * {@link PkiSigningBus#retireSignOperation(PkiId, String)} before the method
 * returns or throws.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This class never accesses private key material directly.</li>
 * <li>The staged to-be-signed content and returned signature bytes are
 * operationally sensitive and must not be logged.</li>
 * <li>The generated operation identifier is an internal workflow handle and
 * must not be treated as a durable business identifier outside the signing
 * flow.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of this class are not thread-safe. Each instance owns one sequential
 * staged-content sink and is intended for one certificate or CRL signing flow.
 * </p>
 */
// PMD cannot infer that retaining provider causes would violate the redaction contract.
@SuppressWarnings("PMD.PreserveStackTrace")
public final class PkiBusContentSigner implements ContentSigner {

    private final PkiSigningBus bus;
    private final KeyRef keyRef;
    private final AlgorithmIdentity algorithmIdentity;
    private final X509ExecutionPlan<SignatureWorkflow> executionPlan;
    private final Duration ttl;

    private final ContentSink contentSink;
    private final OutputStream contentOutput;

    /**
     * Creates a signer that routes signature generation through the PKI signing
     * bus.
     *
     * @param bus         signing bus used to submit and track the delegated sign
     *                    workflow; must not be {@code null}
     * @param keyRef      signing key reference used by the downstream signing
     *                    boundary; must not be {@code null}
     * @param algorithmId non-blank signature algorithm identifier in JCA naming
     *                    form; must not be {@code null} or blank
     * @param ttl         positive maximum time to wait for delegated signing
     *                    completion; must not be {@code null}, zero, or negative
     * @throws IllegalArgumentException if any argument violates the described
     *                                  contract
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, String algorithmId, Duration ttl) {
        this(bus, keyRef, bus.authority().resolveIdentity(algorithmId), ttl);
    }

    /**
     * Creates a signer from an exact provider-independent signature identity.
     *
     * @param bus               signing bus
     * @param keyRef            signing key reference
     * @param algorithmIdentity exact signature identity
     * @param ttl               positive workflow time-to-live
     * @throws IllegalArgumentException if an argument violates the contract or no
     *                                  authoritative signature binding exists
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity, Duration ttl) {
        if (bus == null) {
            throw new IllegalArgumentException("bus must not be null");
        }
        if (keyRef == null) {
            throw new IllegalArgumentException("keyRef must not be null");
        }
        if (algorithmIdentity == null || algorithmIdentity.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("algorithmIdentity must be a signature identity");
        }
        if (ttl == null || ttl.isZero() || ttl.isNegative()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        this.bus = bus;
        this.keyRef = keyRef;
        X509ExecutionPlan<SignatureWorkflow> plan = bus.authority()
                .planSigning(algorithmIdentity.canonicalForm(), SignatureWorkflow.class);
        bus.authority().authorize(plan, plan.executor(),
                zeroecho.core.spi.AlgorithmExecutionCapability.Direction.SIGN);
        this.executionPlan = plan;
        this.algorithmIdentity = plan.selection().requested();
        this.ttl = ttl;
        this.contentSink = bus.beginSigningContent(Encoding.BINARY);
        try {
            this.contentOutput = contentSink.outputStream();
        } catch (IOException ex) {
            try {
                contentSink.close();
            } catch (IOException cleanupFailure) {
                ex.addSuppressed(cleanupFailure);
            }
            throw new PkiException("Signing content staging failed: code=SPOOL_STORAGE_FAILED");
        }
    }

    /**
     * Returns the ASN.1 algorithm identifier corresponding to the configured
     * signature algorithm name.
     *
     * <p>
     * This method is used by Bouncy Castle to encode signature algorithm metadata
     * into the produced signed object.
     * </p>
     *
     * @return ASN.1 signature algorithm identifier
     * @throws RuntimeException if Bouncy Castle cannot resolve the configured
     *                          signature algorithm identifier
     */
    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new BcX509AlgorithmAdapter(bus.authority().bindings()).encode(algorithmIdentity,
                X509AlgorithmRole.SIGNATURE_ALGORITHM);
    }

    /**
     * Returns the output stream used to collect the to-be-signed bytes.
     *
     * <p>
     * Data written to this stream is staged without aggregate heap buffering until
     * {@link #getSignature()} is called.
     * </p>
     *
     * @return sequential staged-content output stream
     */
    @Override
    public OutputStream getOutputStream() {
        return contentOutput;
    }

    /*
     * Package-local postconditions receive the exact live plan minted for this
     * signer. A public semantic fingerprint is intentionally insufficient.
     */
    /* default */ X509ExecutionPlan<SignatureWorkflow> executionPlan() {
        return executionPlan;
    }

    /**
     * Submits the buffered to-be-signed payload to the PKI signing bus and waits
     * for the resulting signature bytes.
     *
     * <p>
     * The method creates a synthetic system-owned signing workflow using purpose
     * {@code X509_SIGN}, submits it to {@link PkiSigningBus}, and then polls the
     * bus until one of the following terminal conditions occurs:
     * </p>
     * <ul>
     * <li>the workflow succeeds and produces a signature result,</li>
     * <li>the workflow fails,</li>
     * <li>the configured TTL expires before completion.</li>
     * </ul>
     *
     * <p>
     * On successful completion, the signature bytes contained in the workflow
     * result are returned. If the workflow reports success but no result is
     * available, the method fails explicitly. Every operation for which submission
     * is attempted is retired before the method returns or throws. Cleanup failures
     * are suppressed on the primary signing failure and otherwise become the
     * returned failure.
     * </p>
     *
     * <p>
     * This method does not retry with a new operation identifier and does not
     * attempt recovery from workflow inconsistency beyond raising a
     * {@link PkiException}.
     * </p>
     *
     * @return raw signature bytes produced by the delegated sign workflow
     * @throws PkiException if the signing workflow fails, if a successful workflow
     *                      produces no signature result, or if signing does not
     *                      complete within the configured TTL
     */
    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public byte[] getSignature() {
        byte[] consumedResult = null;
        PkiId opId = null;
        boolean retirementRequired = false;
        Throwable primaryFailure = null;
        try {
            DurableContentReference content = completeContent();
            Principal owner = new Principal("SYSTEM", "pki");
            opId = bus.newSubmissionId();

            AccessContext ac = new AccessContext(owner, new Purpose("X509_SIGN"), Optional.empty(), Optional.empty());
            String canonicalIdentity = algorithmIdentity.canonicalForm();
            SignContinuation cont = new SignContinuation(ac, canonicalIdentity, content, keyRef, Encoding.BINARY,
                    Optional.empty());

            retirementRequired = true;
            bus.submitSign(opId, owner, keyRef, canonicalIdentity, content, ttl, Optional.of(cont.encode()));
            consumedResult = awaitSignature(opId);
            return consumedResult.clone();
        } catch (RuntimeException failure) {
            PkiException sanitized = new PkiException("Signing workflow failed: code=SIGNING_WORKFLOW_FAILED");
            primaryFailure = sanitized;
            throw sanitized;
        } catch (Error failure) {
            primaryFailure = failure;
            throw failure;
        } finally {
            try {
                if (retirementRequired) {
                    retirePreservingFailure(opId, primaryFailure);
                }
            } finally {
                closeSink(primaryFailure);
                if (consumedResult != null) {
                    java.util.Arrays.fill(consumedResult, (byte) 0);
                }
            }
        }
    }

    private DurableContentReference completeContent() {
        try {
            return contentSink.complete();
        } catch (IOException ex) {
            throw new PkiException("Signing content staging failed: code=SPOOL_STORAGE_FAILED");
        }
    }

    private void closeSink(Throwable primaryFailure) {
        try {
            contentSink.close();
        } catch (IOException cleanupFailure) {
            if (primaryFailure == null) {
                throw new PkiException("Signing cleanup failed: code=SIGNING_CLEANUP_FAILED");
            }
        }
    }

    private byte[] awaitSignature(PkiId opId) {
        Instant deadline = Instant.now().plus(ttl);
        while (Instant.now().isBefore(deadline)) {
            bus.sweep(Instant.now());
            Optional<zeroecho.pki.util.async.AsyncStatus> status = bus.status(opId);
            if (status.isPresent() && status.get().state() == AsyncState.SUCCEEDED) {
                Optional<EncodedObject> result = bus.consumeResult(opId);
                if (result.isEmpty()) {
                    throw new PkiException("Missing signature result");
                }
                return result.get().bytes();
            }
            if (status.isPresent() && isTerminalFailure(status.get().state())) {
                throw new PkiException("Signing failed: " + status.get().state());
            }
            boundedWait(deadline);
        }
        throw new PkiException("Signing did not complete before TTL");
    }

    private static boolean isTerminalFailure(AsyncState state) {
        return state == AsyncState.FAILED || state == AsyncState.CANCELLED || state == AsyncState.EXPIRED;
    }

    @SuppressWarnings("PMD.DoNotUseThreads")
    private static void boundedWait(Instant deadline) {
        long remainingMillis = Duration.between(Instant.now(), deadline).toMillis();
        long waitMillis = Math.min(10L, Math.max(1L, remainingMillis));
        try {
            Thread.sleep(waitMillis);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new PkiException("Interrupted while awaiting signing", ex);
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void retirePreservingFailure(PkiId opId, Throwable primaryFailure) {
        try {
            bus.retireSignOperation(opId, primaryFailure == null ? "completed" : "failed-or-expired");
        } catch (RuntimeException cleanupFailure) {
            if (primaryFailure == null) {
                throw new PkiException("Signing cleanup failed: code=SIGNING_CLEANUP_FAILED");
            }
        }
    }

}
