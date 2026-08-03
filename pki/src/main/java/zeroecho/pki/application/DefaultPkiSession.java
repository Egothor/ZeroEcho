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
package zeroecho.pki.application;

import java.time.Clock;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.impl.core.DefaultProfileService;
import zeroecho.pki.impl.core.DefaultRevocationService;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.store.PkiStore;

/** Default synchronous session composition. */
final class DefaultPkiSession implements PkiSession {

    private final PkiStore store;
    private final AuditSink audit;
    private final ProfileService profiles;
    private final RevocationService revocations;
    private final PkiOperationExecutor operations;
    private final AtomicBoolean closed = new AtomicBoolean();

    private DefaultPkiSession(PkiSessionConfiguration configuration, PkiStore store, AuditSink audit, Clock clock) {
        this.store = store;
        this.audit = audit;
        this.profiles = new DefaultProfileService(store, clock, audit);
        this.revocations = new DefaultRevocationService(store, clock, audit);
        this.operations = new DefaultPkiOperationExecutor(configuration, store, revocations,
                this::requireOpen);
    }

    /* default */ static PkiSession open(PkiSessionConfiguration configuration) {
        return open(configuration, Clock.systemUTC(), ProductionBootstrap.INSTANCE);
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ static PkiSession open(PkiSessionConfiguration configuration, Clock clock, Bootstrap bootstrap) {
        PkiSessionConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(bootstrap, "bootstrap");
        bootstrap.validateStore(exact.store());
        bootstrap.validateAudit(exact.audit());

        PkiStore store = null;
        AuditSink audit = null;
        try {
            store = Objects.requireNonNull(bootstrap.openStore(exact.store()), "opened store");
            audit = Objects.requireNonNull(bootstrap.openAudit(exact.audit()), "opened audit sink");
            return new DefaultPkiSession(exact, store, audit, clock);
        } catch (RuntimeException | Error primary) {
            closeAfterConstructionFailure(audit, store, primary);
            throw primary;
        }
    }

    @Override
    public ProfileService profiles() {
        requireOpen();
        return profiles;
    }

    @Override
    public RevocationService revocations() {
        requireOpen();
        return revocations;
    }

    @Override
    public PkiOperationExecutor operations() {
        requireOpen();
        return operations;
    }

    @Override
    public void close() throws Exception {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        Throwable primary = null;
        try {
            audit.close();
        } catch (Throwable failure) { // NOPMD - preserve Error and checked close failures.
            primary = failure;
        }
        try {
            store.close();
        } catch (Throwable failure) { // NOPMD - preserve Error and checked close failures.
            if (primary == null) {
                primary = failure;
            } else {
                primary.addSuppressed(failure);
            }
        }
        rethrow(primary);
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("PKI session is closed");
        }
    }

    private static void closeAfterConstructionFailure(AuditSink audit, PkiStore store, Throwable primary) {
        if (audit != null) {
            try {
                audit.close();
            } catch (Throwable failure) { // NOPMD - construction failure remains primary.
                primary.addSuppressed(failure);
            }
        }
        if (store != null) {
            try {
                store.close();
            } catch (Throwable failure) { // NOPMD - construction failure remains primary.
                primary.addSuppressed(failure);
            }
        }
    }

    @SuppressWarnings("PMD.SignatureDeclareThrowsException")
    private static void rethrow(Throwable failure) throws Exception {
        if (failure == null) {
            return;
        }
        if (failure instanceof Exception exception) {
            throw exception;
        }
        if (failure instanceof Error error) {
            throw error;
        }
        throw new IllegalStateException("PKI session close failed", failure);
    }

    /** Resource bootstrap seam used for deterministic lifecycle verification. */
    /* default */ interface Bootstrap {
        /** Validates store configuration without allocating a store. */
        void validateStore(ProviderConfig configuration);

        /** Validates audit configuration without allocating a sink. */
        void validateAudit(ProviderConfig configuration);

        /** Opens the configured store. */
        PkiStore openStore(ProviderConfig configuration);

        /** Opens the configured audit sink. */
        AuditSink openAudit(ProviderConfig configuration);
    }

    /** Production provider bootstrap implementation. */
    private enum ProductionBootstrap implements Bootstrap {
        INSTANCE;

        @Override
        public void validateStore(ProviderConfig configuration) {
            PkiBootstrap.validateStoreConfiguration(configuration);
        }

        @Override
        public void validateAudit(ProviderConfig configuration) {
            PkiBootstrap.validateAuditConfiguration(configuration);
        }

        @Override
        public PkiStore openStore(ProviderConfig configuration) {
            return PkiBootstrap.openStore(configuration);
        }

        @Override
        public AuditSink openAudit(ProviderConfig configuration) {
            return PkiBootstrap.openAudit(configuration);
        }
    }
}
