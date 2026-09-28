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

package zeroecho.pki.impl.crypto.remote;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.CallControl;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.crypto.SigningProvider.DetailCode;
import zeroecho.pki.spi.crypto.SigningProvider.ObservationState;
import zeroecho.pki.spi.crypto.SigningProvider.SignRequest;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;

final class RemoteSigningProviderTest {
    private static final String NAMESPACE = "store.zeroecho-remote";
    private static final PkiId OPERATION_ID = new PkiId("remote-operation");
    private static final Instant UPDATED_AT = Instant.parse("2026-09-10T08:00:00Z");

    @Test
    void rejectsMismatchedOperationIdFromDispatchReconcileAndCancel() {
        MismatchTransport transport = new MismatchTransport();
        try (RemoteSigningProvider provider = provider(transport)) {
            SignRequest request = request(provider, OPERATION_ID);
            assertThrows(IllegalStateException.class, () -> provider.dispatch(request, control()));
            assertThrows(IllegalStateException.class, () -> provider.reconcile(OPERATION_ID, control()));
            assertThrows(IllegalStateException.class, () -> provider.cancel(OPERATION_ID, 1L,
                    SigningProvider.CancellationReason.CALLER_REQUESTED, control()));
            assertEquals(1, transport.dispatchCalls.get());
            assertEquals(1, transport.statusCalls.get());
            assertEquals(1, transport.cancelCalls.get());
        }
    }

    @Test
    void deniedRemoteOutcomeMapsToFiniteProviderBoundary() {
        RemoteSigningTransport transport = new FixedTransport(new RemoteSigningTransport.RemoteSigningStatus(
                OPERATION_ID.value(), RemoteSigningTransport.RemoteSigningState.DENIED, UPDATED_AT,
                Optional.empty(), ""));
        try (RemoteSigningProvider provider = provider(transport)) {
            SigningProvider.OperationObservation observation = provider.reconcile(OPERATION_ID, control());
            assertEquals(ObservationState.FAILED, observation.state());
            assertEquals(DetailCode.DENIED, observation.detailCode());
            assertEquals("OperationObservation[operationId=remote-operation, state=FAILED, "
                    + "updatedAt=2026-09-10T08:00:00Z, detailCode=DENIED, signature=Optional.empty]",
                    observation.toString());
        }
    }

    @Test
    void retryableUnknownAndPendingRemainDistinctFromTerminalUnrecoverable() {
        try (RemoteSigningProvider unknown = provider(new FixedTransport(status(
                RemoteSigningTransport.RemoteSigningState.UNKNOWN)))) {
            assertEquals(ObservationState.RETRYABLE_UNKNOWN,
                    unknown.reconcile(OPERATION_ID, control()).state());
        }
        try (RemoteSigningProvider pending = provider(new FixedTransport(status(
                RemoteSigningTransport.RemoteSigningState.QUEUED)))) {
            assertEquals(ObservationState.PENDING, pending.reconcile(OPERATION_ID, control()).state());
        }
        try (RemoteSigningProvider lost = provider(new FixedTransport(status(
                RemoteSigningTransport.RemoteSigningState.UNRECOVERABLE)))) {
            assertEquals(ObservationState.UNRECOVERABLE,
                    lost.reconcile(OPERATION_ID, control()).state());
        }
    }

    @Test
    void transportUncertaintyMapsAllCallsToExactBoundedRetryableUnknown() {
        UncertainTransport transport = new UncertainTransport();
        try (RemoteSigningProvider provider = provider(transport)) {
            assertRetryableUnknown(provider.dispatch(request(provider, OPERATION_ID), control()));
            assertRetryableUnknown(provider.reconcile(OPERATION_ID, control()));
            assertRetryableUnknown(provider.cancel(OPERATION_ID, 1L,
                    SigningProvider.CancellationReason.CALLER_REQUESTED, control()));
            assertEquals(1, transport.dispatchCalls.get());
            assertEquals(1, transport.statusCalls.get());
            assertEquals(1, transport.cancelCalls.get());
        }
    }

    @Test
    void unexpectedFailuresAreNotReclassifiedAsTransportUncertainty() {
        ProgrammingFailureTransport transport = new ProgrammingFailureTransport();
        try (RemoteSigningProvider provider = provider(transport)) {
            assertThrows(IllegalStateException.class,
                    () -> provider.dispatch(request(provider, OPERATION_ID), control()));
            assertThrows(IllegalStateException.class, () -> provider.reconcile(OPERATION_ID, control()));
            assertThrows(IllegalStateException.class, () -> provider.cancel(OPERATION_ID, 1L,
                    SigningProvider.CancellationReason.CALLER_REQUESTED, control()));
        }
    }

    private static void assertRetryableUnknown(SigningProvider.OperationObservation observation) {
        assertEquals(OPERATION_ID, observation.operationId());
        assertEquals(ObservationState.RETRYABLE_UNKNOWN, observation.state());
        assertEquals(DetailCode.RETRYABLE_UNKNOWN, observation.detailCode());
        assertTrue(observation.signature().isEmpty());
        assertFalse(observation.toString().contains("private-provider-reason"));
    }

    private static RemoteSigningTransport.RemoteSigningStatus status(
            RemoteSigningTransport.RemoteSigningState state) {
        return new RemoteSigningTransport.RemoteSigningStatus(OPERATION_ID.value(), state, UPDATED_AT,
                Optional.empty(), "");
    }

    private static RemoteSigningProvider provider(RemoteSigningTransport transport) {
        RemoteSigningProvider provider = new RemoteSigningProvider("zeroecho-remote", transport,
                "zeroecho-remote:", Duration.ofDays(90));
        provider.validateSigningDomain(NAMESPACE, Duration.ofDays(90), Duration.ZERO);
        return provider;
    }

    private static SignRequest request(SigningProvider provider, PkiId operationId) {
        byte[] content = new byte[] { 1, 2, 3 };
        AccessContext access = new AccessContext(new Principal("TEST", "owner"), new Purpose("TEST"),
                Optional.empty(), Optional.empty());
        return SignRequest.create(operationId, NAMESPACE, provider.configurationCommitment(), 1L,
                access, new KeyRef("zeroecho-remote:key"), "SHA256withRSA",
                ContentCommitment.sha256(content), new ImmutableByteContent(content),
                Optional.of(Encoding.BINARY), Optional.empty());
    }

    private static CallControl control() {
        return new CallControl(Instant.MAX, CancellationSignal.NONE);
    }

    private static class FixedTransport implements RemoteSigningTransport {
        private final RemoteSigningStatus status;

        private FixedTransport(RemoteSigningStatus status) {
            this.status = status;
        }

        @Override public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
            return status;
        }
        @Override public RemoteSigningStatus status(String operationId, RemoteCallControl control) {
            return status;
        }
        @Override public RemoteSigningStatus cancel(String operationId, long fencingToken, String reason,
                RemoteCallControl control) {
            return status;
        }
        @Override public byte[] publicKeyInfo(String keyHandle, RemoteCallControl control) {
            return new byte[] { 1 };
        }
        @Override public RemoteCapabilities capabilities() {
            return new RemoteCapabilities(Set.of("SHA256withRSA"), new byte[32], 2,
                    new zeroecho.pki.spi.crypto.SigningInputCapabilities(16L * 1024 * 1024, java.util.Map.of()));
        }
        @Override public void close() {
            // No resources.
        }
    }

    private static final class MismatchTransport extends FixedTransport {
        private final AtomicInteger dispatchCalls = new AtomicInteger();
        private final AtomicInteger statusCalls = new AtomicInteger();
        private final AtomicInteger cancelCalls = new AtomicInteger();

        private MismatchTransport() {
            super(new RemoteSigningStatus("different-operation", RemoteSigningState.QUEUED,
                    UPDATED_AT, Optional.empty(), ""));
        }

        @Override public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
            dispatchCalls.incrementAndGet();
            return super.submit(request, control);
        }
        @Override public RemoteSigningStatus status(String operationId, RemoteCallControl control) {
            statusCalls.incrementAndGet();
            return super.status(operationId, control);
        }
        @Override public RemoteSigningStatus cancel(String operationId, long fencingToken, String reason,
                RemoteCallControl control) {
            cancelCalls.incrementAndGet();
            return super.cancel(operationId, fencingToken, reason, control);
        }
    }

    private static final class UncertainTransport extends FixedTransport {
        private final AtomicInteger dispatchCalls = new AtomicInteger();
        private final AtomicInteger statusCalls = new AtomicInteger();
        private final AtomicInteger cancelCalls = new AtomicInteger();

        private UncertainTransport() {
            super(RemoteSigningProviderTest.status(RemoteSigningState.UNKNOWN));
        }

        @Override public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
            dispatchCalls.incrementAndGet();
            throw new RemoteSigningException("private-provider-reason");
        }
        @Override public RemoteSigningStatus status(String operationId, RemoteCallControl control) {
            statusCalls.incrementAndGet();
            throw new RemoteSigningException("private-provider-reason");
        }
        @Override public RemoteSigningStatus cancel(String operationId, long fencingToken, String reason,
                RemoteCallControl control) {
            cancelCalls.incrementAndGet();
            throw new RemoteSigningException("private-provider-reason");
        }
    }

    private static final class ProgrammingFailureTransport extends FixedTransport {
        private ProgrammingFailureTransport() {
            super(RemoteSigningProviderTest.status(RemoteSigningState.UNKNOWN));
        }

        @Override public RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
            throw new IllegalStateException("programming failure");
        }
        @Override public RemoteSigningStatus status(String operationId, RemoteCallControl control) {
            throw new IllegalStateException("programming failure");
        }
        @Override public RemoteSigningStatus cancel(String operationId, long fencingToken, String reason,
                RemoteCallControl control) {
            throw new IllegalStateException("programming failure");
        }
    }
}
