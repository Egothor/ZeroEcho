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

package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class AuthorityMetadataCodecTest {
    @Test void normalizedBaseHeadAndBothMembershipDirectionsHaveClosedBindings() {
        CaRecord ca = ca("authority");
        AuthorityMetadataCodec.Base base = AuthorityMetadataCodec.Base.of(ca);
        byte[] baseBytes = FsCodec.encode(FsCodec.CA_BASE, base);
        assertEquals(base, AuthorityMetadataCodec.base(AuthorityMetadataCodec.baseKey(ca.caId()), baseBytes));
        AuthorityMetadataCodec.Membership member = new AuthorityMetadataCodec.Membership(ca.caId(), ca.currentIssuanceIssuerId(), 17);
        byte[] bytes = FsCodec.encode(FsCodec.CA_MEMBERSHIP, member);
        assertEquals(member, AuthorityMetadataCodec.membership(AuthorityMetadataCodec.orderKey(ca.caId(), 17), bytes));
        assertEquals(member, AuthorityMetadataCodec.membership(AuthorityMetadataCodec.memberKey(ca.caId(), member.generationId()), bytes));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.membership(AuthorityMetadataCodec.orderKey(ca.caId(), 18), bytes));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.membership(AuthorityMetadataCodec.caKey(ca.caId()), bytes));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.head(AuthorityMetadataCodec.caKey(ca.caId()), FsCodec.encode(FsCodec.CA_RECORD, ca)));
        assertThrows(IllegalStateException.class, () -> new AuthorityMetadataCodec.Head(ca.caId(), ca.state(), ca.currentIssuanceIssuerId(), ca.issuanceChainPathId(), 0));
    }

    @Test void opaqueIdentityAndNamespaceAreBoundWithoutChangingPayloads() {
        CaRecord ca = ca("authority:/opaque/žluťoučký");
        byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, AuthorityMetadataCodec.Head.of(ca));
        MetadataKey key = AuthorityMetadataCodec.caKey(ca.caId());
        assertEquals(64, key.key().length());
        assertEquals(AuthorityMetadataCodec.Head.of(ca), AuthorityMetadataCodec.head(key, payload));
        assertNotEquals(key, AuthorityMetadataCodec.generationKey(ca.caId()));
        assertNotEquals(key, AuthorityMetadataCodec.pathKey(ca.caId()));
        assertNotEquals(key, AuthorityMetadataCodec.credentialKey(ca.caId()));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.head(
                AuthorityMetadataCodec.caKey(new PkiId("another")), payload));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.head(
                AuthorityMetadataCodec.credentialKey(ca.caId()), payload));
        String content = "00000000-0000-0000-0000-000000000001";
        assertEquals(content, AuthorityMetadataCodec.ownerSetKey(content).key());
        assertThrows(RuntimeException.class, () -> AuthorityMetadataCodec.ownerSetKey("not-a-content-id"));
    }

    @Test void collisionOrderingUsesCommittedRevisionAndCanonicalTimestamp() {
        CaRecord ca = ca("authority");
        byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, AuthorityMetadataCodec.Head.of(ca));
        Instant timestamp = Instant.parse("2026-09-21T12:00:00Z");
        MetadataKey lexicallyLast = AuthorityMetadataCodec.historyKey(ca.caId(), timestamp,
                transaction("f"));
        MetadataKey lexicallyFirst = AuthorityMetadataCodec.historyKey(ca.caId(), timestamp,
                transaction("0"));
        AuthorityMetadataCodec.HistoryEntry earlierCommit = AuthorityMetadataCodec.history(lexicallyLast, payload, 1);
        AuthorityMetadataCodec.HistoryEntry laterCommit = AuthorityMetadataCodec.history(lexicallyFirst, payload, 2);
        AuthorityMetadataCodec.HistoryEntry laterTimestamp = AuthorityMetadataCodec.history(
                AuthorityMetadataCodec.historyKey(ca.caId(), timestamp.plusNanos(1000), transaction("1")), payload, 0);
        List<AuthorityMetadataCodec.HistoryEntry> entries = new ArrayList<>(List.of(laterTimestamp, laterCommit, earlierCommit));
        entries.sort(AuthorityMetadataCodec.HISTORY_ORDER);
        assertEquals(List.of(earlierCommit, laterCommit, laterTimestamp), entries);
        assertEquals(laterCommit, entries.stream().filter(value -> !value.timestamp().isAfter(timestamp))
                .max(AuthorityMetadataCodec.HISTORY_ORDER).orElseThrow());
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.history(
                new MetadataKey(AuthorityMetadataCodec.CA_HISTORY,
                        lexicallyLast.key().replace(AuthorityMetadataCodec.historyPrefix(ca.caId()),
                                AuthorityMetadataCodec.historyPrefix(ca.caId()) + "+")), payload, 1));
        assertThrows(IllegalStateException.class, () -> AuthorityMetadataCodec.history(lexicallyLast,
                FsCodec.encode(FsCodec.CA_HEAD, AuthorityMetadataCodec.Head.of(ca("different"))), 1));
    }

    @Test void historyMicrosTruncateAndRoundTripBothSignedBoundaries() {
        CaRecord ca = ca("authority");
        byte[] payload = FsCodec.encode(FsCodec.CA_HEAD, AuthorityMetadataCodec.Head.of(ca));
        for (long micros : new long[] {Long.MIN_VALUE, -1, 0, Long.MAX_VALUE}) {
            Instant instant = Instant.ofEpochSecond(Math.floorDiv(micros, 1_000_000L), Math.floorMod(micros, 1_000_000L) * 1000);
            MetadataKey key = AuthorityMetadataCodec.historyKey(ca.caId(), instant, transaction("1"));
            assertEquals(instant, AuthorityMetadataCodec.history(key, payload, 1).timestamp());
        }
        Instant instant = Instant.ofEpochSecond(0, 1999);
        assertEquals(Instant.ofEpochSecond(0, 1000), AuthorityMetadataCodec.history(
                AuthorityMetadataCodec.historyKey(ca.caId(), instant, transaction("1")), payload, 1).timestamp());
        assertThrows(ArithmeticException.class, () -> AuthorityMetadataCodec.historyKey(ca.caId(), Instant.MAX, transaction("1")));
    }

    private static MetadataTransactionId transaction(String digit) {
        return new MetadataTransactionId(new MetadataStoreId("0".repeat(32)), digit.repeat(32));
    }

    private static CaRecord ca(String identity) {
        PkiId generation = new PkiId("generation");
        return new CaRecord(new PkiId(identity), CaKind.ROOT, CaState.ACTIVE, new KeyRef("key"), new SubjectRef("CN=Root"),
                List.of(generation), generation, new PkiId("path"));
    }
}
