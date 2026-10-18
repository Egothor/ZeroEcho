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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.AuditQuery;
import zeroecho.pki.impl.audit.InMemoryAuditSink;

/**
 * Reconstructs a threshold-approved operation from its recorded audit evidence,
 * proving the chain is complete, attributable, join-able by the operation
 * commitment, bounded on retrieval, and free of decision payload.
 */
class AuditEvidenceReconstructionTest {
    @TempDir Path temporaryDirectory;

    @Test
    void thresholdApprovedOperationReconstructsCompleteAttributableChainWithoutPayload() throws Exception {
        System.out.println("thresholdApprovedOperationReconstructsCompleteAttributableChainWithoutPayload");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("requester"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver-a"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver-b"));

            InMemoryAuditSink sink = new InMemoryAuditSink();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, sink);
            ApprovalService.Policy policy = new ApprovalService.Policy("issuance-threshold", 2,
                    Set.of("approver-a", "approver-b"), Set.of(), true, Duration.ofHours(1), true);
            Permission.Scope scope = ServerTestSupport.scope();
            String commitment = ServerTestSupport.DIGEST;

            // One threshold-approved operation, authenticated request through terminal outcome.
            approvals.request("approval-1", "credential.issue", commitment, scope, "requester", policy);
            approvals.decide("approval-1", "approver-a", ApprovalService.Choice.APPROVE, "reviewed-alpha");
            approvals.decide("approval-1", "approver-b", ApprovalService.Choice.APPROVE, "reviewed-bravo");
            approvals.claim("approval-1", "credential.issue", commitment, scope);
            approvals.complete("approval-1", "SUCCEEDED");

            // Reconstruct the operation's evidence chain by its shared operation commitment.
            AuditQuery byOperation = new AuditQuery(Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Map.of("opCommitment", commitment), 100);
            List<AuditEvent> chain = sink.search(byOperation);

            // Complete chain: request, two decisions, terminal execution.
            Map<String, Long> byAction = chain.stream()
                    .collect(Collectors.groupingBy(AuditEvent::action, Collectors.counting()));
            assertEquals(Map.of("APPROVAL_REQUEST", 1L, "APPROVAL_DECISION", 2L, "APPROVAL_EXECUTION", 1L), byAction);

            // Every event binds the exact immutable operation commitment.
            assertTrue(chain.stream().allMatch(e -> commitment.equals(e.details().get("opCommitment"))));

            // The request is attributable to the requester.
            AuditEvent request = single(chain, "APPROVAL_REQUEST");
            assertEquals("requester", request.principal().name());
            assertEquals(policy.commitment(), request.details().get("policyCommitment"));

            // Both approvers are individually attributable and both approved.
            List<AuditEvent> decisions = chain.stream().filter(e -> e.action().equals("APPROVAL_DECISION")).toList();
            Set<String> approvers = decisions.stream().map(e -> e.principal().name()).collect(Collectors.toSet());
            assertEquals(Set.of("approver-a", "approver-b"), approvers);
            assertTrue(decisions.stream().allMatch(e -> "APPROVE".equals(e.details().get("choice"))));

            // Terminal cryptographic outcome is recorded.
            assertEquals("SUCCEEDED", single(chain, "APPROVAL_EXECUTION").details().get("result"));

            // No payload disclosure: the approver justification plaintext is never surfaced.
            assertTrue(chain.stream().noneMatch(e -> e.details().values().stream()
                    .anyMatch(value -> value.contains("reviewed-alpha") || value.contains("reviewed-bravo"))));

            // Retrieval is bounded regardless of chain length.
            AuditQuery bounded = new AuditQuery(Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Map.of("opCommitment", commitment), 2);
            assertTrue(sink.search(bounded).size() <= 2);
            System.out.println("...reconstructed-events=" + chain.size());
        }
        System.out.println("...ok");
    }

    private static AuditEvent single(List<AuditEvent> chain, String action) {
        return chain.stream().filter(e -> e.action().equals(action)).findFirst().orElseThrow();
    }
}
