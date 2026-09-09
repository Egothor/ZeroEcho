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
import java.util.Objects;
import java.util.Optional;

import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.sign.ContentSigner;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.async.PkiSigningBus.SignContinuation;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.core.async.DomainSigningRequest;
import zeroecho.pki.impl.core.async.ImmediateSigningPending;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.ContentSink;

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
 * The Bouncy Castle call is bounded: it performs at most the initial signing
 * step and one authoritative observation. Immediate completion returns the
 * signature. A delayed domain operation unwinds with its durable private
 * {@link PkiId}; an immediate-only capability fails after cancellation rather
 * than retaining the caller thread.
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
 * <li>No sleep, polling loop, callback owner, lease, or activity root is retained
 * by the foreground call.</li>
 * <li>Immediate terminal operations are retired before return. Delayed operations
 * are owned by the atomically linked domain continuation and later realm
 * reconciliation.</li>
 * </ul>
 *
 * <h2>Lifecycle and ownership</h2>
 * <p>
 * Each instance is a one-shot resource and must be closed. Closing before
 * {@link #getSignature()} aborts incomplete staging. Calling
 * {@code getSignature()} atomically consumes the instance: content completed
 * before bus submission remains signer-owned, while invoking
 * {@link PkiSigningBus#submitSign(PkiId, Principal, KeyRef, String, DurableContentReference, Duration, Optional)}
 * transfers disposition to the bus. The bus releases content only when it can
 * prove no durable intent exists; committed or durability-uncertain content is
 * retained for reconciliation.
 * </p>
 * <p>
 * Retirement removes disposable staged to-be-signed bytes and live workflow
 * continuation state. The store retains content-free terminal evidence, including
 * immutable content commitment metadata and any trustworthy on-time result,
 * through its configured signing horizon. Restart recovery reclaims orphaned
 * staged files without treating retained terminal evidence as live content.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This class never accesses private key material directly.</li>
 * <li>The staged to-be-signed content and returned signature bytes are
 * operationally sensitive and must not be logged.</li>
 * <li>The generated operation identifier is a stable lookup identifier for the
 * persisted signing state; it carries no live workflow context.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of this class are not thread-safe. Each instance owns one sequential
 * staged-content sink and is intended for one certificate or CRL signing flow.
 * </p>
 *
 * <h2>Complexity</h2>
 * <p>
 * Staging is streaming {@code O(n)} time with {@code O(1)} aggregate auxiliary
 * heap, excluding the returned signature. Foreground status work is exactly one
 * bounded observation, independent of TTL.
 * </p>
 */
// PMD cannot infer the one-shot field ownership or that retaining provider causes
// would violate the redaction contract.
@SuppressWarnings({ "PMD.PreserveStackTrace", "PMD.CloseResource", "PMD.UseTryWithResources" })
public final class PkiBusContentSigner implements ContentSigner, AutoCloseable {

    private final PkiSigningBus bus;
    private final KeyRef keyRef;
    private final AlgorithmIdentity algorithmIdentity;
    private final X509ExecutionPlan<SignatureWorkflow> executionPlan;
    private final Instant deadline;
    private final CancellationSignal cancellation;
    private final PkiSigningBus.NewSignAdmission newSignAdmission;
    private final Optional<DomainContinuationTemplate> domainContinuation;

    private final ContentSink contentSink;
    private final OutputStream contentOutput;
    private boolean signatureRequested;
    private boolean closed;

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
     * @param ttl         positive durable signing deadline bound; must not be
     *                    {@code null}, zero, or negative
     * @throws IllegalArgumentException if any argument violates the described
     *                                  contract
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, String algorithmId, Duration ttl) {
        this(bus, keyRef, algorithmId, ttl, CancellationSignal.NONE);
    }

    /**
     * Creates a signer carrying one originating caller cancellation signal.
     *
     * @param bus signing bus that owns submission and reconciliation
     * @param keyRef managed signing-key reference
     * @param algorithmId nonblank signature algorithm identifier
     * @param ttl positive durable signing lifetime
     * @param cancellation originating cooperative cancellation signal
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, String algorithmId, Duration ttl,
            CancellationSignal cancellation) {
        this(bus, keyRef, bus.authority().resolveIdentity(algorithmId), ttl, cancellation);
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
        this(bus, keyRef, algorithmIdentity, ttl, CancellationSignal.NONE);
    }

    /**
     * Creates an identity-bound signer carrying caller cancellation.
     *
     * @param bus signing bus that owns submission and reconciliation
     * @param keyRef managed signing-key reference
     * @param algorithmIdentity exact provider-independent signature identity
     * @param ttl positive durable signing lifetime
     * @param cancellation originating cooperative cancellation signal
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity, Duration ttl,
            CancellationSignal cancellation) {
        this(bus, keyRef, algorithmIdentity, Optional.empty(), ttl, cancellation, Optional.empty());
    }

    /**
     * Creates a signer whose delayed result is owned by a durable domain continuation.
     *
     * @param bus signing bus that owns submission and reconciliation
     * @param keyRef managed signing-key reference
     * @param algorithmIdentity exact provider-independent signature identity
     * @param ttl positive durable signing lifetime
     * @param cancellation originating cooperative cancellation signal
     * @param domainContinuation durable outer continuation that will own a delayed result
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity,
            Duration ttl, CancellationSignal cancellation, DomainContinuationTemplate domainContinuation) {
        this(bus, keyRef, algorithmIdentity, Optional.empty(), ttl, cancellation,
                Optional.of(Objects.requireNonNull(domainContinuation, "domainContinuation")));
    }

    /**
     * Creates a signer using one explicitly selected X.509 binding.
     *
     * @param bus signing bus
     * @param keyRef managed signing-key reference
     * @param algorithmIdentity exact cryptographic identity
     * @param bindingId stable active binding identity
     * @param ttl positive workflow time-to-live
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity,
            String bindingId, Duration ttl) {
        this(bus, keyRef, algorithmIdentity, bindingId, ttl, CancellationSignal.NONE);
    }

    /**
     * Creates an explicitly bound signer carrying caller cancellation.
     *
     * @param bus signing bus that owns submission and reconciliation
     * @param keyRef managed signing-key reference
     * @param algorithmIdentity exact provider-independent signature identity
     * @param bindingId stable active X.509 binding identifier
     * @param ttl positive durable signing lifetime
     * @param cancellation originating cooperative cancellation signal
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity,
            String bindingId, Duration ttl, CancellationSignal cancellation) {
        this(bus, keyRef, algorithmIdentity, Optional.of(bindingId), ttl, cancellation, Optional.empty());
    }

    /**
     * Creates an explicitly bound signer with a durable domain continuation.
     *
     * @param bus signing bus that owns submission and reconciliation
     * @param keyRef managed signing-key reference
     * @param algorithmIdentity exact provider-independent signature identity
     * @param bindingId stable active X.509 binding identifier
     * @param ttl positive durable signing lifetime
     * @param cancellation originating cooperative cancellation signal
     * @param domainContinuation durable outer continuation that will own a delayed result
     */
    public PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity,
            String bindingId, Duration ttl, CancellationSignal cancellation,
            DomainContinuationTemplate domainContinuation) {
        this(bus, keyRef, algorithmIdentity, Optional.of(bindingId), ttl, cancellation,
                Optional.of(Objects.requireNonNull(domainContinuation, "domainContinuation")));
    }

    // Constructor validation keeps all signing and continuation invariants atomic before publication.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.CyclomaticComplexity" })
    private PkiBusContentSigner(PkiSigningBus bus, KeyRef keyRef, AlgorithmIdentity algorithmIdentity,
            Optional<String> bindingId, Duration ttl, CancellationSignal cancellation,
            Optional<DomainContinuationTemplate> domainContinuation) {
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
        String implementation = bus.signingImplementationId(keyRef);
        X509ExecutionPlan<SignatureWorkflow> plan = bindingId.isPresent()
                ? bus.authority().planSigningWithBinding(algorithmIdentity.canonicalForm(), bindingId.orElseThrow(),
                        implementation, SignatureWorkflow.class)
                : bus.authority().planSigning(algorithmIdentity.canonicalForm(), implementation,
                        SignatureWorkflow.class);
        bus.authority().authorize(plan, plan.executor(),
                zeroecho.core.spi.AlgorithmExecutionCapability.Direction.SIGN);
        this.executionPlan = plan;
        this.algorithmIdentity = plan.selection().requested();
        this.deadline = Instant.now().plus(ttl);
        this.cancellation = Objects.requireNonNull(cancellation, "cancellation");
        this.domainContinuation = Objects.requireNonNull(domainContinuation, "domainContinuation");
        this.newSignAdmission = bus.reserveNewSignAdmission();
        ContentSink openedSink;
        try {
            openedSink = bus.beginSigningContent(Encoding.BINARY);
        } catch (RuntimeException | Error stagingFailure) {
            newSignAdmission.close();
            throw stagingFailure;
        }
        this.contentSink = openedSink;
        try {
            this.contentOutput = openedSink.outputStream();
        } catch (IOException ex) {
            try {
                openedSink.close();
            } catch (IOException cleanupFailure) {
                ex.addSuppressed(cleanupFailure);
            } finally {
                newSignAdmission.close();
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
    public AlgorithmIdentifier algorithm() {
        return BcX509AlgorithmAdapter.toLib(executionPlan.selection().binding());
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
     * @throws IllegalStateException if signing has already been requested or this
     *                               signer has been closed
     */
    @Override
    public OutputStream contentStream() {
        requireWritable();
        return contentOutput;
    }

    /**
     * Compatibility alias for {@link #contentStream()}.
     *
     * @return sequential staged-content output stream
     */
    public OutputStream getOutputStream() {
        return contentStream();
    }

    /*
     * Package-local postconditions receive the exact live plan minted for this
     * signer. A public semantic fingerprint is intentionally insufficient.
     */
    /* default */ X509ExecutionPlan<SignatureWorkflow> executionPlan() {
        return executionPlan;
    }

    /**
     * Submits the buffered to-be-signed payload and performs one bounded result
     * observation.
     *
     * <p>
     * The method creates a synthetic system-owned signing workflow using purpose
     * {@code X509_SIGN}, submits it to {@link PkiSigningBus}, and observes one of:
     * </p>
     * <ul>
     * <li>the workflow succeeds and produces a signature result,</li>
     * <li>the workflow fails,</li>
     * <li>a durable pending state owned by the linked outer continuation.</li>
     * </ul>
     *
     * <p>
     * On successful completion, the signature bytes contained in the workflow
     * result are returned. If the workflow reports success but no result is
     * available, the method fails explicitly. Invoking this method consumes the
     * signer; a second invocation fails. Immediate terminal or unsupported
     * delayed operations are retired before return. A supported delayed operation
     * remains owned solely by its persisted outer continuation. Cleanup failures
     * are discarded when a safe primary failure already exists and otherwise
     * become a stable, redacted cleanup failure.
     * </p>
     *
     * <p>
     * This method does not retry with a new operation identifier and does not
     * attempt recovery from workflow inconsistency beyond raising a
     * {@link PkiException}.
     * </p>
     *
     * @return raw signature bytes produced by the delegated sign workflow
     * @throws PkiException if the signing workflow fails or a successful workflow
     *                      produces no signature result
     * @throws IllegalStateException if signing has already been requested or this
     *                               signer has been closed
     */
    /**
     * Compatibility alias for {@link #signature()}.
     *
     * @return raw signature bytes produced by the delegated sign workflow
     */
    public byte[] getSignature() {
        return signature();
    }

    @Override
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public byte[] signature() {
        requireWritable();
        PkiSigningBus.ForegroundCall foregroundCall;
        try {
            foregroundCall = bus.registerForegroundCall(cancellation);
        } catch (RuntimeException | Error rejected) {
            close();
            throw rejected;
        }
        signatureRequested = true;
        SigningAttempt attempt = new SigningAttempt();
        Throwable primaryFailure = null;
        try {
            attempt.result = executeAttempt(foregroundCall, attempt);
            return attempt.result.clone();
        } catch (PendingSigningOperation | ImmediateSigningPending | SigningExecutionException
                | Error signingFailure) {
            primaryFailure = signingFailure;
            throw signingFailure;
        } catch (RuntimeException failure) {
            PkiException sanitized = new PkiException("Signing workflow failed: code=SIGNING_WORKFLOW_FAILED");
            primaryFailure = sanitized;
            throw sanitized;
        } finally {
            attempt.finish(this, primaryFailure, foregroundCall);
        }
    }

    private byte[] executeAttempt(PkiSigningBus.ForegroundCall foregroundCall, SigningAttempt attempt) {
        foregroundCall.requireActive();
        attempt.content = completeContent();
        foregroundCall.requireActive();
        Principal owner = new Principal("SYSTEM", "pki");
        attempt.operationId = bus.newSubmissionId(keyRef);
        foregroundCall.requireActive();
        String canonicalIdentity = algorithmIdentity.canonicalForm();
        AccessContext access = new AccessContext(owner, new Purpose("X509_SIGN"), Optional.empty(), Optional.empty());
        SignContinuation continuation = new SignContinuation(access, canonicalIdentity, attempt.content,
                keyRef, Encoding.BINARY, Optional.empty());
        EncodedObject encodedContinuation = continuation.encode();
        Duration ttl = submissionTtl(attempt.operationId);
        attempt.dispositionTransferred = true;
        submitAttempt(foregroundCall, attempt, owner, canonicalIdentity, encodedContinuation, ttl);
        return observeAttempt(foregroundCall, attempt);
    }

    private void submitAttempt(PkiSigningBus.ForegroundCall foregroundCall, SigningAttempt attempt,
            Principal owner, String canonicalIdentity, EncodedObject continuation, Duration ttl) {
        if (domainContinuation.isPresent()) {
            bus.submitInitialSign(newSignAdmission, new DomainSigningRequest(
                    attempt.operationId, owner, keyRef, canonicalIdentity, attempt.content,
                    ttl, Optional.of(continuation), domainContinuation.orElseThrow()), foregroundCall);
        } else {
            bus.submitInitialSign(newSignAdmission, attempt.operationId, owner, keyRef,
                    canonicalIdentity, attempt.content, ttl, Optional.of(continuation), foregroundCall);
        }
    }

    private byte[] observeAttempt(PkiSigningBus.ForegroundCall foregroundCall, SigningAttempt attempt) {
        PkiSigningBus.SigningObservation observation = bus.observeSigningResult(attempt.operationId,
                foregroundCall.cancellation());
        if (observation instanceof PkiSigningBus.SigningObservation.Pending durablePending) {
            if (domainContinuation.isPresent()) {
                attempt.pending = true;
                throw new PendingSigningOperation(durablePending.operationId());
            }
            throw new ImmediateSigningPending();
        }
        if (observation instanceof PkiSigningBus.SigningObservation.Failed terminalFailure) {
            throw new PkiException("Signing failed: " + terminalFailure.state());
        }
        return ((PkiSigningBus.SigningObservation.Completed) observation).signature().bytes();
    }

    /** Stack-confined mutable disposition of one synchronous adapter attempt. */
    private static final class SigningAttempt {
        private DurableContentReference content;
        private PkiId operationId;
        private byte[] result;
        private boolean dispositionTransferred;
        private boolean pending;

        private void finish(PkiBusContentSigner owner, Throwable primaryFailure,
                PkiSigningBus.ForegroundCall foregroundCall) {
            try {
                if (dispositionTransferred && !pending) {
                    owner.retirePreservingFailure(operationId, primaryFailure, foregroundCall);
                } else if (content != null) {
                    owner.releasePreservingFailure(content, primaryFailure);
                }
            } finally {
                close(owner, primaryFailure, foregroundCall);
            }
        }

        private void close(PkiBusContentSigner owner, Throwable primaryFailure,
                PkiSigningBus.ForegroundCall foregroundCall) {
            try {
                owner.closeSink(primaryFailure);
            } finally {
                owner.closed = true;
                owner.newSignAdmission.close();
                foregroundCall.close();
                if (result != null) {
                    java.util.Arrays.fill(result, (byte) 0);
                }
            }
        }
    }

    /**
     * Aborts incomplete staged content owned by this signer.
     *
     * <p>
     * Closing is idempotent. Closing before {@link #getSignature()} permanently
     * consumes the signer and removes its partial staged content. Calling this
     * method after a signing attempt is a no-op because that attempt has already
     * disposed of or transferred every resource it owned.
     * </p>
     *
     * @throws PkiException if incomplete staging cannot be removed
     */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            contentSink.close();
        } catch (IOException cleanupFailure) {
            throw new PkiException("Signing cleanup failed: code=SIGNING_CLEANUP_FAILED");
        } finally {
            newSignAdmission.close();
        }
    }

    private void requireWritable() {
        if (closed || signatureRequested) {
            throw new IllegalStateException("Content signer is already consumed");
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

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void releasePreservingFailure(DurableContentReference content, Throwable primaryFailure) {
        try {
            bus.releaseContent(content);
        } catch (RuntimeException cleanupFailure) {
            if (primaryFailure == null) {
                throw new PkiException("Signing cleanup failed: code=SIGNING_CLEANUP_FAILED");
            }
        }
    }

    private Duration submissionTtl(PkiId operationId) {
        Duration exactTtl = Duration.between(SigningSubmissionId.parse(operationId).createdAt(), deadline);
        if (exactTtl.isZero() || exactTtl.isNegative()) {
            throw new PkiException("Signing deadline expired: code=SIGNING_DEADLINE_EXPIRED");
        }
        return exactTtl;
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void retirePreservingFailure(PkiId opId, Throwable primaryFailure,
            PkiSigningBus.ForegroundCall foregroundCall) {
        try {
            bus.retireSignOperation(opId, primaryFailure == null ? "completed" : "failed-or-expired",
                    foregroundCall);
        } catch (RuntimeException cleanupFailure) {
            if (primaryFailure == null) {
                throw new PkiException("Signing cleanup failed: code=SIGNING_CLEANUP_FAILED");
            }
        }
    }

}
