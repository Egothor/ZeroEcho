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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Exact authorization projections decoded from durable domain commands. */
final class DefaultPkiSessionSigningAuthorizationTest {
    private static final String DIGEST = "1".repeat(64);

    @Test
    void mapsEveryClosedDomainOperationWithoutRequesterIdentity() {
        assertProjection(record(DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                        "CREATE_ROOT", "x509", "subject:root", "root", "key:root", "root", "1", DIGEST,
                        "2026-08-20T10:00:00Z", "2027-08-20T10:00:00Z", "1", "CN=Root", "policy", "binding")),
                SigningOperationAuthorization.Action.AUTHORITY_CREATE,
                SigningOperationAuthorization.ResourceType.AUTHORITY, Optional.empty(), Optional.empty());
        assertProjection(record(DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                        "CREATE_INTERMEDIATE", intermediateFields())),
                SigningOperationAuthorization.Action.AUTHORITY_CREATE,
                SigningOperationAuthorization.ResourceType.AUTHORITY,
                Optional.of(new PkiId("ca:parent")), Optional.of(new PkiId("ca:subject")));
        assertProjection(record(DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                        "ISSUE_INTERMEDIATE", intermediateFields())),
                SigningOperationAuthorization.Action.ISSUER_CREATE,
                SigningOperationAuthorization.ResourceType.ISSUER,
                Optional.of(new PkiId("ca:subject")), Optional.empty());
        assertProjection(record(DomainCommandEncoding.template(DomainContinuationStore.Kind.ISSUANCE,
                        "ISSUE_END_ENTITY", issuanceFields())),
                SigningOperationAuthorization.Action.CERTIFICATE_ISSUE,
                SigningOperationAuthorization.ResourceType.CERTIFICATE,
                Optional.of(new PkiId("ca:issuer")), Optional.empty());
        assertProjection(record(DomainCommandEncoding.template(DomainContinuationStore.Kind.STATUS,
                        "GENERATE_STATUS", "ca:issuer", "CRL", "x509-crl", "2026-08-20T10:00:00Z",
                        "2026-08-20T11:00:00Z", "key:issuer", "entries", DIGEST, "AAAAAA")),
                SigningOperationAuthorization.Action.STATUS_GENERATE,
                SigningOperationAuthorization.ResourceType.STATUS_OBJECT,
                Optional.of(new PkiId("ca:issuer")), Optional.empty());
    }

    private static void assertProjection(DomainContinuationStore.Record record,
            SigningOperationAuthorization.Action action,
            SigningOperationAuthorization.ResourceType resourceType,
            Optional<PkiId> authorityId, Optional<PkiId> objectId) {
        SigningOperationAuthorization projection = DefaultPkiSession.authorizationProjection(record);
        assertEquals(action, projection.action());
        assertEquals(resourceType, projection.resourceType());
        assertEquals(authorityId, projection.authorityId());
        assertEquals(objectId, projection.objectId());
    }

    private static DomainContinuationStore.Record record(DomainContinuationTemplate template) {
        return new DomainContinuationStore.Record(new PkiId("signing:test"), 2, template.kind(),
                template.correlationId(), DomainContinuationStore.State.SIGNING, 0L,
                Instant.parse("2026-08-20T09:00:00Z"), Instant.parse("2026-08-20T12:00:00Z"),
                template.command(), template.commandCommitment(), Optional.of(reference()),
                Optional.empty(), Optional.empty());
    }

    private static DurableContentReference reference() {
        return new DurableContentReference() {
            @Override public String storeId() { return "test-store"; }
            @Override public String contentId() { return "test-content"; }
            @Override public zeroecho.pki.api.Encoding encoding() { return zeroecho.pki.api.Encoding.BINARY; }
            @Override public long length() { return 1L; }
            @Override public String sha256() { return DIGEST; }
            @Override public Lifecycle lifecycle() { return Lifecycle.OPERATION; }
        };
    }

    private static String[] intermediateFields() {
        return new String[] { "x509", "ca:parent", "ca:subject", "issuer:parent", "path:parent", DIGEST,
                "key:subject", "intermediate", "1", DIGEST, "subject:intermediate",
                "2026-08-20T10:00:00Z", "2027-08-20T10:00:00Z", "2", "CN=Intermediate",
                "content", "request", DIGEST, DIGEST, "policy", "binding" };
    }

    private static String[] issuanceFields() {
        return new String[] { "ca:issuer", "issuer:generation", "path:issuer", DIGEST, "leaf", "1", DIGEST,
                "subject:leaf", "2026-08-20T10:00:00Z", "2026-08-20T11:00:00Z", "3", "key:leaf",
                "content", DIGEST, DIGEST, "", "", "CN=Leaf", "[]", "[]", "[]", "binding",
                zeroecho.pki.impl.core.async.DomainAttributeEncoding.encode(
                        zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build()) };
    }
}
