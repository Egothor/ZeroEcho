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
package zeroecho.pki.server;

import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicReference;

import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.PosixTransactionalMetadataStore;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;

/**
 * Lifecycle owner for one server realm, one long-lived PKI session, and one
 * dedicated durable server-control authority.
 *
 * <p>The context is transport-neutral and synchronous. It creates no execution
 * lane, queue, thread, scheduler, retry loop, HTTP type, or ACME object. A future
 * transport can retain one instance for its process lifetime and submit existing
 * typed operations through {@link #gateway()}.</p>
 */
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.CloseResource", "PMD.UseProperClassLoader",
        "PMD.AvoidCatchingGenericException", "PMD.LinguisticNaming", "PMD.ControlStatementBraces",
        "PMD.PreserveStackTrace", "PMD.SignatureDeclareThrowsException", "PMD.CommentRequired",
        "PMD.AvoidSynchronizedAtMethodLevel", "PMD.AvoidInstantiatingObjectsInLoops" })
public final class ServerRealmContext implements AutoCloseable {
    /** Closed lifecycle states. */
    public enum State { OPEN, CLOSING, CLOSED }

    private final ServerRealmConfiguration configuration;
    private final ServerControlStore control;
    private final PkiSession session;
    private final RoleTemplateCatalog roles;
    private final AuthorizationEngine authorization;
    private final ApprovalService approvals;
    private final BreakGlassService breakGlass;
    private final DisclosureService disclosure;
    private final AuditorViews auditorViews;
    private final ServerOperationGateway gateway;
    private final SafeAudit audit;
    private final AtomicReference<State> state = new AtomicReference<>(State.OPEN);

    private ServerRealmContext(ServerRealmConfiguration configuration, ServerControlStore control,
            PkiSession session, RoleTemplateCatalog roles, AuthorizationEngine authorization,
            ApprovalService approvals, BreakGlassService breakGlass, DisclosureService disclosure,
            AuditorViews auditorViews, AuditSink auditSink, Clock clock) {
        this.configuration = configuration;
        this.control = control;
        this.session = session;
        this.roles = roles;
        this.authorization = authorization;
        this.approvals = approvals;
        this.breakGlass = breakGlass;
        this.disclosure = disclosure;
        this.auditorViews = auditorViews;
        this.audit = new SafeAudit(clock, auditSink);
        this.gateway = new ServerOperationGateway(configuration.realmId(), configuration.authorityExposure(),
                control, roles, authorization, approvals, breakGlass, new OperationSecurityDescriptors(),
                session.operations(), session.resourceScopes(), configuration.approvalPolicies(), clock, auditSink,
                this::requireOpen);
    }

    /**
     * Opens one production realm using explicit process-local capabilities.
     *
     * @param configuration validated immutable realm configuration
     * @param dependencies key-access capabilities, never secret values
     * @return fully recovered realm context
     */
    public static ServerRealmContext open(ServerRealmConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies) {
        return open(configuration, dependencies, Clock.systemUTC(), new SecureRandom());
    }

    static ServerRealmContext open(ServerRealmConfiguration configuration,
            PkiSessionRuntimeDependencies dependencies, Clock clock, SecureRandom random) {
        ServerRealmConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        PkiSessionRuntimeDependencies runtime = Objects.requireNonNull(dependencies, "dependencies");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        if (Files.isSymbolicLink(exact.controlLogPath())) {
            throw new IllegalArgumentException("Server-control log must not be a symbolic link");
        }
        ServerControlStore control = null;
        SharedAuditSink audit = null;
        PkiSession session = null;
        try {
            control = new ServerControlStore(openControl(exact));
            ServerControlStore.RealmRecord realm = new ServerControlStore.RealmRecord(exact.realmId(),
                    exact.displayName(), exact.authorityExposure(), exact.authorizationCommitment(),
                    exact.approvalCommitment(), exact.disclosureCommitment(), exact.controlStoreId());
            control.ensureRealm(realm);
            RoleTemplateCatalog roles = RoleTemplateCatalog.load(ServerRealmContext.class.getClassLoader());
            control.validateAll();
            control.validateReferences(roles);
            audit = new SharedAuditSink(PkiBootstrap.openAudit(exact.pkiSessionConfiguration().audit()));
            session = PkiSession.open(exact.pkiSessionConfiguration(), runtime.withAuditSink(audit));
            validateExposure(exact.authorityExposure(), session);
            AuthorizationEngine authorization = new AuthorizationEngine(clock);
            ApprovalService approvals = new ApprovalService(control, clock, audit);
            BreakGlassService breakGlass = new BreakGlassService(control, clock, audit);
            DisclosureService disclosure = new DisclosureService(exact.realmId(), control,
                    exact.disclosureDefaults(), clock, random, audit);
            AuditorViews views = new AuditorViews(clock, audit);
            ServerRealmContext result = new ServerRealmContext(exact, control, session, roles, authorization,
                    approvals, breakGlass, disclosure, views, audit, clock);
            result.audit.record("REALM_OPEN", "system", Optional.empty(), Map.of("realm", exact.realmId().value()));
            return result;
        } catch (RuntimeException | Error primary) {
            closeAfterFailure(session, audit, control, primary);
            throw primary;
        }
    }

    /** @return exact realm configuration without rendering provider values */
    public ServerRealmConfiguration configuration() { requireOpen(); return configuration; }
    /** @return the one long-lived PKI session */
    public PkiSession session() { requireOpen(); return session; }
    /** @return immutable built-in role template catalog */
    public RoleTemplateCatalog roleTemplates() { requireOpen(); return roles; }
    /** @return deterministic authorization engine */
    public AuthorizationEngine authorization() { requireOpen(); return authorization; }
    /** @return durable approval service */
    public ApprovalService approvals() { requireOpen(); return approvals; }
    /** @return durable break-glass service */
    public BreakGlassService breakGlass() { requireOpen(); return breakGlass; }
    /** @return durable disclosure decision service */
    public DisclosureService disclosure() { requireOpen(); return disclosure; }
    /** @return explicit auditor projection service */
    public AuditorViews auditorViews() { requireOpen(); return auditorViews; }
    /** @return authorized typed-operation gateway */
    public ServerOperationGateway gateway() { requireOpen(); return gateway; }
    /** @return current lifecycle state */
    public State state() { return state.get(); }

    /** Creates a principal and records only safe administrative audit metadata. */
    public void createPrincipal(SecurityPrincipal principal, String actorPrincipalId) {
        requireOpen();
        control.createPrincipal(principal);
        audit.record("PRINCIPAL_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("principal", principal.principalId(), "enabled", Boolean.toString(principal.enabled())));
    }

    /** Changes only the enabled state of an existing principal. */
    public SecurityPrincipal setPrincipalEnabled(String principalId, boolean enabled, String actorPrincipalId) {
        requireOpen();
        SecurityPrincipal current = control.requirePrincipal(principalId);
        SecurityPrincipal updated = new SecurityPrincipal(current.principalId(), current.type(),
                current.displayName(), current.organization(), current.attributes(), enabled);
        control.replacePrincipal(current, updated);
        audit.record("PRINCIPAL_STATE", actorPrincipalId, Optional.empty(),
                Map.of("principal", principalId, "enabled", Boolean.toString(enabled)));
        return updated;
    }

    /** Creates one scoped role assignment; templates remain non-authoritative alone. */
    public void assignRole(RoleTemplateCatalog.Assignment assignment, String actorPrincipalId) {
        requireOpen();
        roles.instantiate(assignment);
        control.requirePrincipal(assignment.principalId());
        control.createAssignment(assignment);
        audit.record("ROLE_ASSIGNMENT_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("assignment", assignment.assignmentId(), "template", assignment.templateId()));
    }

    /** Creates one explicit scoped direct grant. */
    public void grant(Permission.Grant grant, String actorPrincipalId) {
        requireOpen();
        control.requirePrincipal(grant.principalId());
        control.createGrant(grant);
        audit.record("PERMISSION_GRANT_CREATE", actorPrincipalId, Optional.empty(),
                Map.of("grant", grant.grantId(), "effect", grant.effect().name()));
    }

    /**
     * Rejects new work and closes session then server-control authority. Repeated
     * calls are harmless and failure suppression preserves causal order.
     */
    @Override
    public void close() throws Exception {
        if (!state.compareAndSet(State.OPEN, State.CLOSING)) return;
        Throwable primary = null;
        try {
            audit.record("REALM_CLOSE", "system", Optional.empty(), Map.of("realm", configuration.realmId().value()));
        } catch (Throwable failure) {
            primary = failure;
        }
        primary = closeOne(session, primary);
        primary = closeOne(control, primary);
        state.set(State.CLOSED);
        rethrow(primary);
    }

    private void requireOpen() {
        if (state.get() != State.OPEN) throw new IllegalStateException("Server realm is not open");
    }

    private static PosixTransactionalMetadataStore openControl(ServerRealmConfiguration configuration) {
        try {
            if (Files.exists(configuration.controlLogPath())) {
                PosixTransactionalMetadataStore opened = PosixTransactionalMetadataStore.open(
                        configuration.controlLogPath(), OptionalLong.of(1_048_576));
                if (!opened.id().equals(configuration.controlStoreId())) {
                    opened.close();
                    throw new IllegalStateException("Server-control store identity differs");
                }
                return opened;
            }
            return PosixTransactionalMetadataStore.create(configuration.controlLogPath(),
                    configuration.controlStoreId(), OptionalLong.of(1_048_576));
        } catch (IOException failure) {
            throw new IllegalStateException("Server-control metadata authority cannot be opened");
        }
    }

    private static void validateExposure(AuthorityExposurePolicy exposure, PkiSession session) {
        if (exposure.mode() == AuthorityExposurePolicy.Mode.EXPLICIT_AUTHORITIES) {
            for (zeroecho.pki.api.PkiId authorityId : exposure.authorityIds()) {
                PkiOperationOutcome outcome = session.operations().execute(
                        new PkiOperation.InspectAuthority(authorityId), zeroecho.core.io.CancellationSignal.NONE);
                if (!(outcome instanceof PkiOperationOutcome.Success)) {
                    throw new IllegalStateException("Configured authority exposure contains an unavailable authority");
                }
            }
        }
    }

    private static void closeAfterFailure(PkiSession session, AuditSink audit, ServerControlStore control,
            Throwable primary) {
        Throwable result = closeOne(session, primary);
        if (session == null) result = closeOne(audit, result);
        closeOne(control, result);
    }

    private static Throwable closeOne(AutoCloseable resource, Throwable primary) {
        if (resource == null) return primary;
        try {
            resource.close();
        } catch (Throwable failure) {
            if (primary == null) return failure;
            primary.addSuppressed(failure);
        }
        return primary;
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure == null) return;
        if (failure instanceof Exception exception) throw exception;
        if (failure instanceof Error error) throw error;
        throw new IllegalStateException("Unexpected realm close failure");
    }

    private static final class SharedAuditSink implements AuditSink {
        private final AuditSink delegate;
        private boolean closed;

        private SharedAuditSink(AuditSink delegate) { this.delegate = Objects.requireNonNull(delegate, "delegate"); }
        @Override public synchronized void record(zeroecho.pki.api.audit.AuditEvent event) {
            if (closed) throw new IllegalStateException("Audit sink is closed");
            delegate.record(event);
        }
        @Override public synchronized void close() {
            if (!closed) { closed = true; delegate.close(); }
        }
    }
}
