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
import java.nio.file.Path;
import java.time.Clock;
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
import zeroecho.pki.impl.fs.PosixTransactionalMetadataStore;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Shared deterministic fixtures for the server security tests. */
final class ServerTestSupport {
    static final RealmId REALM = new RealmId("production");
    static final PkiId AUTHORITY = new PkiId("ca-a");
    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-04T12:00:00Z"), ZoneOffset.UTC);
    static final String DIGEST = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static final MetadataStoreId STORE_ID = new MetadataStoreId("0123456789abcdef0123456789abcdef");

    private ServerTestSupport() { }

    static OpenedStore open(Path directory) throws IOException {
        Path log = directory.resolve("server-control.log");
        PosixTransactionalMetadataStore metadata = PosixTransactionalMetadataStore.create(log, STORE_ID,
                OptionalLong.of(1_048_576));
        ServerControlStore store = new ServerControlStore(metadata);
        store.ensureRealm(new ServerControlStore.RealmRecord(REALM, "Production",
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                DIGEST, DIGEST, DIGEST, STORE_ID));
        return new OpenedStore(log, store, new RecordingAudit());
    }

    static Permission.Scope scope() {
        return new Permission.Scope(REALM, Optional.of(AUTHORITY), Optional.empty(), Optional.empty());
    }

    static Permission.Resource authorityResource() {
        return new Permission.Resource(Permission.ResourceType.AUTHORITY, scope(), Optional.of(AUTHORITY),
                Optional.empty());
    }

    static SecurityPrincipal principal(String id) {
        return new SecurityPrincipal(id, SecurityPrincipal.Type.USER, id, Optional.empty(), Map.of(), true);
    }

    static Permission.Grant grant(String id, String principal, Permission.Effect effect,
            Permission.Action action, Permission.ResourceType type, Permission.Scope scope,
            Permission.Relationship relationship, Permission.DataView view) {
        return new Permission.Grant(id, principal, effect, action, type, scope, relationship, view,
                Set.of(), Optional.empty(), true);
    }

    record OpenedStore(Path log, ServerControlStore store, RecordingAudit audit) implements AutoCloseable {
        @Override public void close() throws IOException { store.close(); }
    }

    static final class RecordingAudit implements AuditSink {
        private final List<AuditEvent> events = new ArrayList<>();
        @Override public void record(AuditEvent event) { events.add(event); }
        List<AuditEvent> events() { return List.copyOf(events); }
    }
}
