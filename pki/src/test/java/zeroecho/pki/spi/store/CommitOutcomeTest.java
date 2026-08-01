/*
 * Copyright (c) 2025 ZeroEcho
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;

final class CommitOutcomeTest {

    @Test
    void outcomesEnforceRevisionAndFailureShape() {
        System.out.print("outcomesEnforceRevisionAndFailureShape ");
        MetadataTransactionId transactionId = new MetadataTransactionId(
                new MetadataStoreId("0123456789abcdef0123456789abcdef"),
                "11111111111111111111111111111111");
        MetadataCommitResult committed = new MetadataCommitResult(
                transactionId,
                MetadataCommitResult.Outcome.COMMITTED,
                OptionalLong.of(3L),
                Optional.empty());
        assertEquals(3L, committed.committedRevision().orElseThrow());
        MetadataCommitResult unknown = new MetadataCommitResult(
                transactionId,
                MetadataCommitResult.Outcome.UNKNOWN,
                OptionalLong.empty(),
                Optional.empty());
        assertEquals(MetadataCommitResult.Outcome.UNKNOWN, unknown.outcome());
        assertThrows(
                IllegalArgumentException.class,
                () -> new MetadataCommitResult(
                        transactionId,
                        MetadataCommitResult.Outcome.COMMITTED,
                        OptionalLong.empty(),
                        Optional.empty()));
        System.out.println("...ok");
    }
}
