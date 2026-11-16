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
package zeroecho.pki.server;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.MetadataStoreId;

/**
 * Shared deterministic fixtures for the server security tests.
 */
final class ServerTestSupport {
    /**
     * Canonical realm identity shared by deterministic server-security fixtures.
     */
    static final RealmId REALM = new RealmId("production");
    /**
     * Authority identity used by the default scoped permission fixtures.
     */
    static final PkiId AUTHORITY = new PkiId("ca-a");
    /**
     * Fixed UTC clock used for deterministic approval, grant and audit observations.
     */
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-04T12:00:00Z"), ZoneOffset.UTC);
    /**
     * Canonical SHA-256-shaped fixture commitment used where no content hashing is under test.
     */
    static final String DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /**
     * Stable durable metadata-store identity for isolated fixture control logs.
     */
    static final MetadataStoreId STORE_ID = new MetadataStoreId("0123456789abcdef0123456789abcdef");
    /**
     * Default fixture proof policy: fixed audience, five-minute TTL and an 8,192-bit RSA maximum.
     */
    static final CredentialConfirmationProofPolicy CONFIRMATION_PROOF_POLICY =
            new CredentialConfirmationProofPolicy(new CredentialConfirmationProofAudience(
                    "urn:uuid:123e4567-e89b-42d3-a456-426614174000"),
                    Duration.ofMinutes(5L), 8_192);

    private ServerTestSupport() { }

    /**
     * Creates a fresh durable control log and initializes the deterministic fixture realm.
     *
     * @param directory isolated filesystem root in which the control log is created
     * @return caller-owned store bundle with an initially empty recording audit sink
     * @throws IOException if the durable control authority cannot be created or initialized
     */
    static OpenedStore open(Path directory) throws IOException {
        Path log = directory.resolve("server-control.log");
        DurableTransactionalMetadataStore metadata = DurableTransactionalMetadataStore.create(log, STORE_ID,
                OptionalLong.of(1_048_576));
        ServerControlStore store = new ServerControlStore(metadata);
        store.ensureRealm(new ServerControlStore.RealmRecord(REALM, "Production",
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                DIGEST, DIGEST, DIGEST, DIGEST, STORE_ID));
        return new OpenedStore(log, store, new RecordingAudit());
    }

    /**
     * Returns the default authority scope inside the deterministic fixture realm.
     *
     * @return scope selecting only the fixture authority
     */
    static Permission.Scope scope() {
        return new Permission.Scope(REALM, Optional.of(AUTHORITY), Optional.empty(), Optional.empty());
    }

    /**
     * Returns the default authority resource used by authorization fixtures.
     *
     * @return self-scoped authority object in the fixture realm
     */
    static Permission.Resource authorityResource() {
        return new Permission.Resource(Permission.ResourceType.AUTHORITY, scope(), Optional.of(AUTHORITY),
                Optional.empty());
    }

    /**
     * Creates an enabled user principal without ownership or extra attributes.
     *
     * @param id canonical fixture principal identity, also used as its display name
     * @return enabled immutable principal
     * @throws IllegalArgumentException if identity or display-name syntax is invalid
     */
    static SecurityPrincipal principal(String id) {
        return new SecurityPrincipal(id, SecurityPrincipal.Type.USER, id, Optional.empty(), Map.of(), true);
    }

    /**
     * Creates an enabled unconditional grant without implicit ownership constraints.
     *
     * @param id canonical grant identity
     * @param principal grantee principal identity
     * @param effect explicit allow or deny effect
     * @param action exact permission action
     * @param type target resource type
     * @param scope realm/authority/issuer/profile scope
     * @param relationship required subject/object relationship
     * @param view permitted data view
     * @return enabled grant with no conditions or explicit owner
     * @throws IllegalArgumentException if grant coordinates are inconsistent
     */
    static Permission.Grant grant(String id, String principal, Permission.Effect effect,
            Permission.Action action, Permission.ResourceType type, Permission.Scope scope,
            Permission.Relationship relationship, Permission.DataView view) {
        return new Permission.Grant(id, principal, effect, action, type, scope, relationship, view,
                Set.of(), Optional.empty(), true);
    }

    /**
     * Owned durable control fixture and its in-memory audit observations.
     *
     * @param log durable control-log path
     * @param store initialized control authority owned by this bundle
     * @param audit recording sink used to inspect emitted events
     */
    record OpenedStore(Path log, ServerControlStore store, RecordingAudit audit) implements AutoCloseable {
        /**
         * {@inheritDoc}
         */
        @Override public void close() throws IOException { store.close(); }
    }

    /**
     * Thread-confined test sink retaining event objects in delivery order.
     */
    static final class RecordingAudit implements AuditSink {
        private final List<AuditEvent> events = new ArrayList<>();
        /**
         * {@inheritDoc}
         */
        @Override public void record(AuditEvent event) { events.add(event); }
        /**
         * Snapshots the events delivered to this fixture sink.
         *
         * @return immutable ordered event list
         */
        List<AuditEvent> events() { return List.copyOf(events); }
    }
}
