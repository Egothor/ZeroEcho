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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.store.DomainContinuationStore;

final class DomainContinuationValidationTest {
    private static final PkiId OPERATION_ID = new PkiId("signing:validation-test");
    private static final String DIGEST = "1".repeat(64);

    @Test
    void recoveredRecordRequiresKeyAndCanonicalCommitment() {
        DomainContinuationStore.Record valid = record(command("2026-08-20T10:00:00Z"), null);

        assertEquals(valid, DomainContinuationValidation.validate(OPERATION_ID, valid, 4096));
        assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(
                new PkiId("signing:different"), valid, 4096));
        DomainContinuationStore.Record hostileCommitment = record(valid.command(), "domain:v1:" + "2".repeat(64));
        assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(
                OPERATION_ID, hostileCommitment, 4096));
    }

    @Test
    void recoveredRecordRejectsNoncanonicalCommandAndLifecycle() {
        DomainContinuationStore.Record noncanonicalInstant = record(command("2026-08-20T10:00:00.000Z"), null);

        assertThrows(IllegalStateException.class, () -> DomainContinuationValidation.validate(
                OPERATION_ID, noncanonicalInstant, 4096));
        assertThrows(IllegalArgumentException.class, () -> new DomainContinuationStore.Record(OPERATION_ID, 2,
                DomainContinuationStore.Kind.ISSUANCE, Optional.of("order:test"),
                DomainContinuationStore.State.COMPLETED, 2L, Instant.parse("2026-08-20T09:00:00Z"),
                Instant.parse("2026-08-20T11:00:00Z"), command("2026-08-20T10:00:00Z"),
                DomainContinuationTemplate.commitment(command("2026-08-20T10:00:00Z")), Optional.of(reference()),
                Optional.empty(), Optional.of("COMPLETED")));
    }

    private static DomainContinuationStore.Record record(EncodedObject command, String commitment) {
        return new DomainContinuationStore.Record(OPERATION_ID, 2, DomainContinuationStore.Kind.ISSUANCE,
                Optional.of("order:test"), DomainContinuationStore.State.SIGNING, 0L,
                Instant.parse("2026-08-20T09:00:00Z"), Instant.parse("2026-08-20T11:00:00Z"), command,
                commitment == null ? DomainContinuationTemplate.commitment(command) : commitment,
                Optional.of(reference()), Optional.empty(), Optional.empty());
    }

    private static EncodedObject command(String notBefore) {
        return DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.ISSUANCE, "order:test",
                "ISSUE_END_ENTITY", "ca:test", "issuer:test", "path:test", DIGEST,
                "leaf", "1", DIGEST, "subject:test", notBefore, "2026-08-20T11:00:00Z", "1",
                "key:test", "content:test", DIGEST, DIGEST, "order:test", DIGEST,
                "CN=test", "[]", "[]", "[]", "binding:test",
                DomainAttributeEncoding.encode(
                        zeroecho.pki.impl.core.attr.SimpleAttributeSet.builder().build())).command();
    }

    private static DurableContentReference reference() {
        return new TestReference("store:test", "content:test", Encoding.BINARY, 1L, DIGEST,
                DurableContentReference.Lifecycle.OPERATION);
    }

    private record TestReference(String storeId, String contentId, Encoding encoding, long length,
            String sha256, DurableContentReference.Lifecycle lifecycle) implements DurableContentReference { }
}
