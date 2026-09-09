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
package zeroecho.pki.impl.core.async;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.SignWorkflowStore;

/** Validation and blocking-result boundary shared by the execution facade. */
final class SigningExecutionSupport {
    private static final long NO_WAIT_NANOS = 0L;
    private static final long WAIT_POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(10L);

    private SigningExecutionSupport() { }

    /* default */ static String workflowImplementationId(SignatureWorkflow workflow) {
        return "workflow." + Objects.requireNonNull(workflow, "workflow").id();
    }

    /* default */ static PkiSessionConfiguration.SigningConfiguration executionBounds(int laneCount,
            int queueCapacity, Duration gracefulDrain, Duration forcedCancellation) {
        ProviderConfig placeholder = new ProviderConfig("runtime", Map.of());
        return new PkiSessionConfiguration.SigningConfiguration(placeholder, placeholder, "runtime-signature",
                Duration.ofSeconds(1), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                laneCount, queueCapacity, gracefulDrain, forcedCancellation);
    }

    /* default */ static Optional<String> retirementReason(PkiStore store,
            SignWorkflowStore.Record candidate, Instant current) {
        boolean deadlineExpired = !candidate.deadline().isAfter(current);
        boolean horizonExpired = !candidate.createdAt().plus(store.signingHorizon()).isAfter(current);
        if (!deadlineExpired && !horizonExpired
                || candidate.state() == SignWorkflowStore.State.RETIRED && !horizonExpired
                || candidate.state() == SignWorkflowStore.State.SUCCEEDED
                        && DomainContinuationValidation.isPublishing(store, candidate.submissionId())) {
            return Optional.empty();
        }
        return Optional.of(deadlineExpired ? "deadline-expired" : "retention-expired");
    }

    @SuppressWarnings({ "PMD.PreserveStackTrace",
            "PMD.DoNotUseThreads" }) // This boundary restores the interrupted caller before classification.
    /* default */ static <T> T await(SigningExecutionRuntime.StepSubmission<T> submission, Instant deadline,
            CancellationSignal cancellation) {
        if (submission.disposition() != SigningExecutionRuntime.StepDisposition.ACCEPTED) {
            throw schedulingFailure(submission.disposition());
        }
        Future<T> future = submission.future().orElseThrow();
        try {
            return pollFuture(future, deadline, cancellation);
        } catch (InterruptedException interrupted) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                    "Signing execution interrupted: code=SIGNING_INTERRUPTED");
        } catch (TimeoutException timeout) {
            throw new PkiException("Signing deadline expired: code=SIGNING_DEADLINE_EXPIRED");
        } catch (CancellationException cancelled) {
            throw failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                    "Signing execution cancelled: code=SIGNING_SHUTTING_DOWN");
        } catch (ExecutionException failed) {
            return rethrowExecutionFailure(failed);
        }
    }

    private static <T> T pollFuture(Future<T> future, Instant deadline, CancellationSignal cancellation)
            throws InterruptedException, ExecutionException, TimeoutException {
        while (true) {
            if (cancellation.isCancelled()) {
                future.cancel(true);
                throw new CancellationException();
            }
            long remaining = Duration.between(Instant.now(), deadline).toNanos();
            if (remaining <= NO_WAIT_NANOS) {
                future.cancel(true);
                throw new TimeoutException();
            }
            try {
                return future.get(Math.min(remaining, WAIT_POLL_NANOS), TimeUnit.NANOSECONDS);
            } catch (TimeoutException pollElapsed) {
                if (remaining <= WAIT_POLL_NANOS) {
                    future.cancel(true);
                    throw pollElapsed;
                }
            }
        }
    }

    /* default */ static SigningExecutionException schedulingFailure(
            SigningExecutionRuntime.StepDisposition disposition) {
        return switch (Objects.requireNonNull(disposition, "disposition")) {
            case BUSY -> failure(SigningExecutionException.Classification.OVERLOADED,
                    "Signing operation step is busy: code=SIGNING_OVERLOADED");
            case SATURATED -> failure(SigningExecutionException.Classification.OVERLOADED,
                    "Signing execution queue is full: code=SIGNING_OVERLOADED");
            case SHUTTING_DOWN -> failure(SigningExecutionException.Classification.SHUTTING_DOWN,
                    "Signing execution is unavailable: code=SIGNING_SHUTTING_DOWN");
            case ACCEPTED -> throw new IllegalArgumentException("Accepted scheduling has no failure");
        };
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    /* default */ static <T> T callNested(Callable<T> action) {
        try {
            return action.call();
        } catch (RuntimeException | Error failure) {
            throw failure;
        } catch (Exception failure) {
            throw new PkiException("Signing execution failed: code=SIGNING_EXECUTION_FAILED");
        }
    }

    // Re-throws a store-wide durability-uncertain failure verbatim so it is never
    // reclassified. The decision reads the typed reason carried structurally on the
    // failure or any of its causes, not the human-readable message text.
    /* default */ static void rethrowStoreWideFailure(RuntimeException failure) {
        for (Throwable current = failure; current != null; current = current.getCause()) {
            if (current instanceof PkiException pkiFailure
                    && pkiFailure.failureReason().orElse(null)
                            == PkiFailureReason.STORE_DURABILITY_UNCONFIRMED) {
                throw failure;
            }
        }
    }

    private static <T> T rethrowExecutionFailure(ExecutionException failed) {
        Throwable cause = failed.getCause();
        if (cause instanceof RuntimeException runtimeFailure) {
            throw runtimeFailure;
        }
        if (cause instanceof Error error) {
            throw error;
        }
        throw new PkiException("Signing execution failed: code=SIGNING_EXECUTION_FAILED");
    }

    private static SigningExecutionException failure(SigningExecutionException.Classification classification,
            String message) {
        return new SigningExecutionException(classification, message);
    }
}
