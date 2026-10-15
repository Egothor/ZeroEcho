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

package zeroecho.pki.server.enrollment;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.SecretKey;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.BackupTransferConfiguration;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerControlStore;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.cmp.CmpEndpoint;
import zeroecho.pki.server.cmp.CmpProtectionPolicy;
import zeroecho.pki.server.est.EstEndpoint;
import zeroecho.pki.server.scep.ScepEndpoint;

/**
 * Thread-safe realm owner of dedicated enrollment keyrings and immutable
 * authority-scoped credentials. Acquisition is bounded and atomic with shutdown.
 * No caller callback runs under a runtime or control-store monitor.
 *
 * <p>Closing fences new leases immediately. If borrowers remain, close fails
 * without releasing keys or exclusive file ownership; callers must drain them
 * and retry. This permits the server's bounded shutdown protocol without
 * destroying credentials underneath a live operation.</p>
 */
public final class EnrollmentRuntime implements AutoCloseable { // NOPMD CyclomaticComplexity - One runtime owns the credential graph, keyrings and lease shutdown; individual methods remain checked.
    private final EnrollmentRuntimeConfiguration configuration;
    private final Clock clock;
    private final ServerControlStore control;
    private final Map<String, KeyringStore> keyrings;
    private final Map<String, EnrollmentCredentialValidation.Loaded> credentials;
    private final Map<String, String> active;
    private final EnrollmentKeygenSpool keygenSpool;
    private boolean closing;
    private boolean closed;
    private int leases;

    private EnrollmentRuntime(EnrollmentRuntimeConfiguration configuration, Clock clock, ServerControlStore control,
            Map<String, KeyringStore> keyrings, Map<String, EnrollmentCredentialValidation.Loaded> credentials, EnrollmentKeygenSpool keygenSpool) {
        this.configuration = configuration;
        this.clock = clock;
        this.control = control;
        this.keygenSpool = keygenSpool;
        this.keyrings = Map.copyOf(keyrings);
        this.credentials = Map.copyOf(credentials);
        Map<String, String> selected = new HashMap<>();
        for (EnrollmentRuntimeConfiguration.ActiveCredential item : configuration.activeCredentials()) {
            selected.put(selection(item.protocol(), item.authorityId()), item.credentialId());
        }
        active = Map.copyOf(selected);
    }

    /**
     * Validates companion presence and lexical storage separation without opening
     * stores. Actual paths, keys, certificates and authority records are checked
     * by {@link #open}.
     * @param server main schema-8 configuration
     * @param enrollment explicit optional companion
     * @param backup optional independently configured backup spool
     */
    public static void validateConfiguration(PkiServerConfiguration server,
            Optional<EnrollmentRuntimeConfiguration> enrollment, Optional<BackupTransferConfiguration> backup) {
        Objects.requireNonNull(server, "server");
        Objects.requireNonNull(enrollment, "enrollment");
        Objects.requireNonNull(backup, "backup");
        if ((server.estListener().isPresent() || server.scepListener().isPresent()
                || server.cmpListener().isPresent() || server.acmeListener().isPresent()) && enrollment.isEmpty()) {
            throw new IllegalArgumentException("Enabled enrollment listener requires enrollment configuration");
        }
        enrollment.ifPresent(value -> validateTopology(value, server.realm(), backup, false));
    }

    /**
     * Opens preprovisioned encrypted keyrings, validates the complete credential
     * graph and atomically pins immutable public commitments in server control.
     * Failed construction closes every acquired keyring owner. Parsing and key
     * provider calls happen before any control-store transaction.
     * @param configuration strict explicit companion
     * @param realm exact realm settings
     * @param repository authoritative issuer and certificate repository
     * @param control durable realm control
     * @param endpoints registry owned by the same durable realm control
     * @param dependencies existing process-local unlock capability
     * @param clock validity clock
     * @param backup optional backup spool to exclude from custody paths
     * @return fully validated lifecycle owner
     * @throws IllegalStateException if custody, integrity or credential validation fails
     */
    public static EnrollmentRuntime open(EnrollmentRuntimeConfiguration configuration, ServerRealmConfiguration realm,
            PkiRepository repository, ServerControlStore control, EnrollmentEndpointRegistry endpoints,
            PkiSessionRuntimeDependencies dependencies,
            Clock clock, Optional<BackupTransferConfiguration> backup) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(endpoints, "endpoints");
        validateTopology(configuration, realm, backup, true);
        Map<String, KeyringStore> rings = new HashMap<>();
        EnrollmentKeygenSpool spool = null; // NOPMD CloseResource - Returned runtime owns the spool; this method closes it on every pre-transfer failure.
        try {
            if (configuration.keygenArtifacts().isPresent()) {
                spool = new EnrollmentKeygenSpool(
                    configuration.keygenArtifacts().orElseThrow(), configuration.budgets().maximumConcurrentDispatches());
            }
            if (!configuration.keyrings().isEmpty()) {
                KeyringUnlockProvider unlock = dependencies.keyringUnlockProvider().orElseThrow(
                        () -> new IllegalStateException("Enrollment unlock capability is unavailable"));
                for (EnrollmentRuntimeConfiguration.Keyring ring : configuration.keyrings()) {
                    rings.put(ring.id(), openRing(ring.path(), unlock));
                }
            }
            Map<String, EnrollmentCredentialValidation.Loaded> loaded = new HashMap<>();
            for (EnrollmentRuntimeConfiguration.CredentialSet set : configuration.credentialSets()) {
                loaded.put(set.credentialId(), EnrollmentCredentialValidation.load(
                        set, realm.realmId().value(), repository, rings));
            }
            EnrollmentRuntime result = new EnrollmentRuntime(configuration, clock, control, rings, loaded, spool);
            for (EnrollmentRuntimeConfiguration.ActiveCredential selected : configuration.activeCredentials()) {
                EnrollmentCredentialValidation.Loaded value = loaded.get(selected.credentialId());
                EnrollmentCredentialValidation.requireCurrent(value, repository);
                result.requireValid(value, clock.instant().plus(configuration.budgets().retryAfter()));
            }
            endpoints.installRuntime(result);
            return result;
        } catch (IOException | RuntimeException | Error failure) { // NOPMD AvoidCatchingGenericException - Release every already-opened custody resource before preserving the original unchecked failure.
            if (spool != null) {
                try { spool.close(); } catch (IOException cleanup) { failure.addSuppressed(cleanup); }
            }
            for (KeyringStore ring : rings.values()) { // NOPMD CloseResource - Failure cleanup explicitly closes every opened ring before rethrowing.
                try { ring.close(); } catch (RuntimeException cleanup) { failure.addSuppressed(cleanup); } // NOPMD AvoidCatchingGenericException - Continue releasing the remaining keyrings while retaining the original failure and cleanup evidence.
            }
            if (failure instanceof Error error) {
                throw error; // NOPMD PreserveStackTrace - Pattern matching rethrows the identical original Error after cleanup.
            }
            if (failure instanceof RuntimeException runtimeFailure) {
                throw runtimeFailure; // NOPMD PreserveStackTrace - Pattern matching rethrows the identical original RuntimeException after cleanup.
            }
            throw new IllegalStateException("Enrollment ciphertext custody is unavailable"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    // Called only after endpoint validation while holding that registry's control monitor.
    /* default */ void pinCredentials(ServerControlStore authority) {
        if (authority != control) { // NOPMD CompareObjectsWithEquals - Registry binding requires the identical control-store monitor, not value equality.
            throw new IllegalArgumentException("Enrollment registry belongs to another control owner");
        }
        EnrollmentCredentialValidation.pin(control, credentials);
    }

    /**
     * Returns explicit immutable settings; no credential material is exposed.
     * @return runtime configuration
     */
    public EnrollmentRuntimeConfiguration configuration() { return configuration; }

    /**
     * Validates that an exact immutable credential set remains provisioned for a
     * retained transaction. Expiry forbids wire use but does not erase recovery
     * provenance. This metadata-only check acquires no key lease.
     * @param credentialId retained immutable credential identity
     */
    // Reads the retained credential graph atomically with runtime close and rotation checks.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized void requireRetainedCredential(String credentialId) {
        requireOpen(); requireCredential(credentialId);
    }

    /**
     * Validates the exact immutable scope of retained credential metadata without
     * requiring current certificate validity or acquiring a private-key lease.
     * Expired credentials may establish recovery provenance but cannot sign.
     * @param credentialId retained credential-set identity
     * @param authorityId frozen logical authority
     * @param issuerId frozen issuer generation
     * @param pathId frozen chain path
     */
    // Reads the retained credential graph atomically with runtime close and rotation checks.
    // Preserves the public source/binary contract for named persisted identity coordinates.
    @SuppressWarnings({"PMD.AvoidSynchronizedAtMethodLevel", "PMD.UseObjectForClearerAPI"})
    public synchronized void requireRetainedCredential(String credentialId, String authorityId, String issuerId, String pathId) {
        requireOpen();
        EnrollmentRuntimeConfiguration.CredentialSet set = requireCredential(credentialId).configuration();
        if (!set.authorityId().equals(authorityId) || !set.issuerId().equals(issuerId) || !set.chainPathId().equals(pathId)) {
            throw unavailable();
        }
    }

    /**
     * Checks retained credential scope and its exact protocol capability without
     * acquiring a lease or requiring unexpired signing material.
     * @param protocol frozen protocol role; never inferred from another credential
     * @param credentialId retained immutable credential identity
     * @param authorityId frozen authority
     * @param issuerId frozen issuer generation
     * @param pathId frozen chain path
     */
    // Reads the retained credential graph atomically with runtime close and rotation checks.
    // Preserves the public source/binary contract for named persisted identity coordinates.
    @SuppressWarnings({"PMD.AvoidSynchronizedAtMethodLevel", "PMD.UseObjectForClearerAPI"})
    public synchronized void requireRetainedCredential(EnrollmentRuntimeConfiguration.Protocol protocol,
            String credentialId, String authorityId, String issuerId, String pathId) {
        Objects.requireNonNull(protocol, "protocol");
        requireRetainedCredential(credentialId, authorityId, issuerId, pathId);
        if (requireCredential(credentialId).configuration().protocol() != protocol) {
            throw unavailable();
        }
    }

    /**
     * Checks a retained credential's current validity and exact frozen authority
     * binding before an unclaimed request is admitted. Does not load private keys
     * or replace the active selection for new requests.
     * @param credentialId frozen credential identity
     * @param authorityId expected logical authority
     * @param issuerId expected issuer generation
     * @param pathId expected issuer chain path
     */
    // Reads admission eligibility and the active credential graph atomically with close.
    // Preserves the public source/binary contract for named persisted identity coordinates.
    @SuppressWarnings({"PMD.AvoidSynchronizedAtMethodLevel", "PMD.UseObjectForClearerAPI"})
    public synchronized void requireAdmissionCredential(String credentialId, String authorityId, String issuerId, String pathId) {
        requireOpen();
        EnrollmentCredentialValidation.Loaded loaded = requireCredential(credentialId);
        requireValid(loaded, clock.instant());
        EnrollmentRuntimeConfiguration.CredentialSet set = loaded.configuration();
        if (!set.authorityId().equals(authorityId) || !set.issuerId().equals(issuerId) || !set.chainPathId().equals(pathId)) {
            throw unavailable();
        }
    }

    /**
     * Resolves the immutable selection for a new transaction.
     * @param protocol exact protocol
     * @param authorityId exact authority
     * @return configured credential-set identity
     * @throws IllegalStateException if absent, expired, or quiescing
     */
    // Reads the active credential selection under the runtime lifecycle monitor.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized String activeCredentialId(EnrollmentRuntimeConfiguration.Protocol protocol, String authorityId) {
        requireOpen();
        String id = active.get(selection(protocol, authorityId));
        if (id == null) {
            throw unavailable();
        }
        requireValid(credentials.get(id), clock.instant());
        return id;
    }

    /**
     * Returns a deadline bounded by both pending lifetime and the exact
     * authority/response/trust certificate validity window.
     * @param credentialId retained immutable credential-set identity
     * @return latest permitted pending deadline
     */
    // Reads credential validity and admission eligibility under the runtime lifecycle monitor.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized Instant admissionDeadline(String credentialId) {
        requireOpen();
        EnrollmentCredentialValidation.Loaded loaded = requireCredential(credentialId);
        requireValid(loaded, clock.instant().plus(configuration.budgets().retryAfter()));
        Instant requested = clock.instant().plus(configuration.budgets().pendingLifetime());
        return requested.isBefore(loaded.notAfter()) ? requested : loaded.notAfter();
    }

    /**
     * Returns the immutable end of the credential and validated chain validity window.
     * Unlike the admission deadline this does not shorten delivery to the pending
     * lifetime. Expired retained material remains identifiable for recovery.
     * @param credentialId exact retained credential-set identity
     * @return exclusive upper bound for credential use and encrypted-key delivery
     */
    // Reads the retained credential validity under the runtime lifecycle monitor.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized Instant credentialNotAfter(String credentialId) {
        requireOpen();
        return requireCredential(credentialId).notAfter();
    }

    /**
     * Validates an endpoint's provisioned capability without loading keys or
     * invoking providers. Suitable for the registry's serialized policy guard.
     * @param endpoint exact registration or admission binding
     */
    // Checks endpoint bindings against one runtime credential graph while excluding close.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized void validateEndpoint(EnrollmentEndpoint endpoint) {
        requireOpen();
        if (endpoint instanceof EstEndpoint est && est.keygen().enabled()) {
                if (configuration.keygenArtifacts().isEmpty()) {
                    throw unavailable();
                }
                activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.EST, endpoint.authorityId());
        } else if (endpoint instanceof ScepEndpoint) {
            activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, endpoint.authorityId());
        } else if (endpoint instanceof CmpEndpoint cmp) {
            String id = activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.CMP, endpoint.authorityId());
            EnrollmentRuntimeConfiguration.CredentialSet set = requireCredential(id).configuration();
            if (cmp.protectionPolicy() == CmpProtectionPolicy.SIGNATURE_BASED && set.signer().isEmpty()
                    || cmp.protectionPolicy() == CmpProtectionPolicy.SHARED_SECRET_MAC && set.pbm().isEmpty()) {
                throw unavailable();
            }
        }
    }

    /**
     * Acquires bounded access to an exact current or retained credential set.
     * The caller must close the lease and must not retain private/secret keys
     * beyond it. Expired credentials remain pinned but cannot protect responses.
     * @param credentialId immutable transaction-selected credential identity
     * @return closeable credential lease
     * @throws IllegalStateException if unavailable, expired, or capacity is exhausted
     */
    // Increments the live credential-lease count atomically with the closing-state check.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    public synchronized CredentialLease acquire(String credentialId) {
        requireOpen();
        EnrollmentCredentialValidation.Loaded loaded = requireCredential(credentialId);
        requireValid(loaded, clock.instant());
        if (leases >= configuration.budgets().maximumConcurrentDispatches()) {
            throw unavailable();
        }
        leases++;
        return new CredentialLease(loaded);
    }

    /**
     * Fences new leases and releases exclusive custody only after all borrowers
     * have released their leases. Idempotent after a successful close.
     * @throws IllegalStateException if borrowers still hold leases; retry after draining
     */
    // Serializes closing/closed flags with lease draining before keyring and spool release.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    @Override public synchronized void close() {
        closing = true;
        if (closed) {
            return;
        }
        if (leases != 0) {
            throw new IllegalStateException("Enrollment credentials are still leased");
        }
        if (keygenSpool != null) {
            try { keygenSpool.close(); } catch (IOException failure) { throw new IllegalStateException("Enrollment ciphertext custody is still in use"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
        for (KeyringStore ring : keyrings.values()) { // NOPMD CloseResource - Runtime shutdown explicitly closes every owned ring.
            ring.close();
        }
        closed = true;
    }

    // Guards lazy keygen-spool access against concurrent runtime close.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    /* default */ synchronized EnrollmentKeygenSpool keygenSpool() {
        requireOpen();
        if (keygenSpool == null) {
            throw unavailable();
        }
        return keygenSpool;
    }

    /**
     * Bounded credential borrower. Key imports occur outside the runtime monitor.
     * Do not share a lease across threads or close it concurrently with a use.
     * Certificate lists are immutable and contain public material only.
     */
    public final class CredentialLease implements AutoCloseable {
        private final EnrollmentCredentialValidation.Loaded loaded;
        private final AtomicBoolean released = new AtomicBoolean();

        private CredentialLease(EnrollmentCredentialValidation.Loaded loaded) { this.loaded = loaded; }

        /**
         * Returns the exact frozen public configuration.
         * @return immutable credential configuration
         */
        public EnrollmentRuntimeConfiguration.CredentialSet configuration() { requireLive(); return loaded.configuration(); }

        /**
         * Returns response leaf followed by its exact authority chain.
         * @return immutable public certificate chain, empty for PBM-only sets
         */
        public List<X509Certificate> responseChain() { requireLive(); return loaded.signerChain(); }

        /**
         * Returns this authority's configured request trust anchors.
         * @return immutable public anchors
         */
        public List<X509Certificate> requestTrustAnchors() { requireLive(); return loaded.trustAnchors(); }

        /**
         * Imports the provisioned response private key. The caller may use it
         * only during this lease and must not serialize, log or retain it.
         * @return private key for the exact response certificate
         * @throws IllegalStateException if absent or import fails
         */
        public PrivateKey privateKey() {
            requireLive();
            EnrollmentRuntimeConfiguration.KeyReference reference = loaded.configuration().signer()
                    .orElseThrow(EnrollmentRuntime::unavailable).key();
            try { return keyrings.get(reference.keyringId()).getPrivate(reference.alias()); }
            catch (IOException | GeneralSecurityException failure) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }

        /**
         * Imports a configured PBM secret for the exact senderKID. The caller
         * owns any extracted byte copy and must zero it after use.
         * @param senderKid exact canonical configured senderKID
         * @return borrowed secret key, usable only within this lease
         * @throws IllegalStateException if not configured or import fails
         */
        public SecretKey pbmSecret(String senderKid) {
            requireLive();
            EnrollmentRuntimeConfiguration.PbmIdentity identity = loaded.configuration().pbm()
                    .orElseThrow(EnrollmentRuntime::unavailable).identities().stream()
                    .filter(value -> value.senderKid().equals(senderKid)).findFirst().orElseThrow(EnrollmentRuntime::unavailable);
            try { return keyrings.get(identity.secret().keyringId()).getSecret(identity.secret().alias()); }
            catch (IOException | GeneralSecurityException failure) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }

        /** Releases this borrower exactly once; it does not close shared custody. */
        @Override public void close() {
            if (released.compareAndSet(false, true)) {
                synchronized (EnrollmentRuntime.this) { leases--; } // NOPMD AvoidSynchronizedStatement - Serializes this lifecycle owner’s state and lease transitions.
            }
        }
        private void requireLive() {
            if (released.get()) {
                throw unavailable();
            }
            requireValid(loaded, clock.instant());
        }
        @Override public String toString() { return "EnrollmentCredentialLease[redacted]"; }
    }

    private EnrollmentCredentialValidation.Loaded requireCredential(String id) {
        EnrollmentCredentialValidation.Loaded result = credentials.get(id);
        if (result == null) {
            throw unavailable();
        }
        return result;
    }
    private void requireValid(EnrollmentCredentialValidation.Loaded value, Instant through) {
        Instant now = clock.instant();
        if (now.isBefore(value.notBefore()) || !through.isBefore(value.notAfter())) {
            throw unavailable();
        }
    }
    private void requireOpen() { if (closing || closed) {
        throw unavailable();
    } }
    private static String selection(EnrollmentRuntimeConfiguration.Protocol protocol, String authority) {
        Objects.requireNonNull(protocol, "protocol"); EnrollmentRuntimeConfiguration.id(authority);
        return protocol.name() + ":" + authority;
    }
    private static KeyringStore openRing(Path path, KeyringUnlockProvider provider) {
        // Capability exceptions are deliberately stripped at the secret boundary.
        try (KeyringPassword password = provider.acquire()) {
            if (password == null) {
                throw unavailable();
            }
            return KeyringStore.open(path, password);
        } catch (IOException | GeneralSecurityException | RuntimeException failure) { throw unavailable(); } // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    private static IllegalStateException unavailable() { return new IllegalStateException("Enrollment credentials are unavailable"); }

    private static void validateTopology(EnrollmentRuntimeConfiguration config, ServerRealmConfiguration realm,
            Optional<BackupTransferConfiguration> backup, boolean resolve) {
        List<Path> excluded = new ArrayList<>();
        realm.pkiSessionConfiguration().store().get("root").ifPresent(value -> excluded.add(Path.of(value)));
        excluded.add(realm.controlLogPath());
        realm.pkiSessionConfiguration().audit().get("root").ifPresent(value -> excluded.add(Path.of(value)));
        realm.pkiSessionConfiguration().signing().ifPresent(value -> value.provider().get("keyringPath").ifPresent(path -> excluded.add(Path.of(path))));
        backup.ifPresent(value -> excluded.add(value.directory()));
        List<Path> owned = new ArrayList<>();
        config.keygenArtifacts().ifPresent(value -> owned.add(value.directory()));
        config.keyrings().forEach(value -> owned.add(value.path()));
        try {
            List<Path> authorities = new ArrayList<>();
            for (Path path : excluded) {
                authorities.add(resolve ? path.toRealPath() : path.toAbsolutePath().normalize());
            }
            List<Path> resolved = new ArrayList<>();
            for (Path path : owned) {
                Path exact = resolve ? path.toRealPath() : path.toAbsolutePath().normalize();
                if (resolve && config.keygenArtifacts().map(value -> value.directory().equals(path)).orElse(false)
                        && !Files.isDirectory(exact)) {
                    throw new IOException("Enrollment artifact directory is unavailable");
                }
                requireDisjoint(exact, authorities, resolve);
                requireDisjoint(exact, resolved, resolve);
                resolved.add(exact);
            }
        } catch (IOException failure) { throw new IllegalArgumentException("Enrollment storage topology is unavailable"); } // NOPMD ExceptionAsFlowControl, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }
    private static void requireDisjoint(Path exact, List<Path> others, boolean resolve) throws IOException {
        for (Path other : others) {
            rejectOverlap(exact, other);
        }
        if (resolve) {
            for (Path other : others) {
                if (Files.isSameFile(exact, other)) {
                    throw new IllegalArgumentException("Enrollment storage paths alias");
                }
            }
        }
    }

    private static void rejectOverlap(Path first, Path second) {
        if (first.startsWith(second) || second.startsWith(first)
                || first.equals(second.resolveSibling(second.getFileName() + ".lock"))
                || first.equals(second.resolveSibling(second.getFileName() + ".nonce"))
                || second.equals(first.resolveSibling(first.getFileName() + ".lock"))
                || second.equals(first.resolveSibling(first.getFileName() + ".nonce"))) {
            throw new IllegalArgumentException("Enrollment storage paths overlap");
        }
    }
}
