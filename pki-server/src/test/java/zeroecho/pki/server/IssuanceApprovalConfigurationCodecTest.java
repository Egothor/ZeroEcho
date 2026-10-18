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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;

/** Verifies configuration-file wiring of issuance-approval policies with tamper-evident B' commitment. */
class IssuanceApprovalConfigurationCodecTest {
    private static final Path PRODUCTION_EXAMPLE = Path.of("..", "docs", "pki-server-production-example.json");

    private static final ApprovalService.Policy ISSUANCE_SINGLE = new ApprovalService.Policy("issuance-single",
            1, Set.of("issuance-approver"), Set.of(), true, Duration.ofMillis(3_600_000L), true);
    private static final ApprovalService.Policy ISSUANCE_THRESHOLD = new ApprovalService.Policy(
            "issuance-threshold", 2, Set.of("issuance-approver", "second-approver"), Set.of(), true,
            Duration.ofMillis(3_600_000L), true);

    @Test
    void unmodifiedExampleHasEmptyExtendedApprovalCommitment() throws Exception {
        PkiServerConfiguration decoded = PkiServerConfigurationCodec.decode(
                Files.readString(PRODUCTION_EXAMPLE).getBytes(StandardCharsets.UTF_8));
        assertEquals(Set.of(ApprovalCategory.HIGH_RISK), decoded.realm().approvalPolicies().keySet());
        assertEquals(ServerRealmConfiguration.extendedApprovalCommitment(Map.of()),
                decoded.realm().extendedApprovalCommitment());
    }

    @Test
    void parsesIssuanceApprovalPoliciesWhenCommitmentMatches() throws Exception {
        String expected = ServerRealmConfiguration.extendedApprovalCommitment(Map.of(
                ApprovalCategory.ISSUANCE_SINGLE, ISSUANCE_SINGLE,
                ApprovalCategory.ISSUANCE_THRESHOLD, ISSUANCE_THRESHOLD));
        PkiServerConfiguration decoded = PkiServerConfigurationCodec.decode(
                withIssuancePolicies(expected).getBytes(StandardCharsets.UTF_8));
        Map<ApprovalCategory, ApprovalService.Policy> policies = decoded.realm().approvalPolicies();
        assertEquals(Set.of(ApprovalCategory.HIGH_RISK, ApprovalCategory.ISSUANCE_SINGLE,
                ApprovalCategory.ISSUANCE_THRESHOLD), policies.keySet());
        assertEquals(1, policies.get(ApprovalCategory.ISSUANCE_SINGLE).threshold());
        assertEquals(2, policies.get(ApprovalCategory.ISSUANCE_THRESHOLD).threshold());
        assertEquals(expected, decoded.realm().extendedApprovalCommitment());
    }

    @Test
    void rejectsOmittedCommitmentWhenIssuancePoliciesConfigured() {
        // Symmetric with the required HIGH_RISK approvalCommitment: once issuance policies are configured,
        // the operator must assert the extended commitment at parse time.
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                withIssuancePolicies(null).getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsMismatchedExtendedApprovalCommitment() {
        String wrong = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                withIssuancePolicies(wrong).getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsSingleIssuancePolicyWithNonUnitThreshold() throws Exception {
        String production = Files.readString(PRODUCTION_EXAMPLE);
        String insertion = "\"issuanceSingleApprovalPolicy\": {\"policyId\":\"issuance-single\",\"threshold\":2,"
                + "\"eligibleApprovers\":[\"issuance-approver\",\"second-approver\"],\"requiredRoleTemplateIds\":[],"
                + "\"requesterSeparation\":true,\"lifetimeMillis\":3600000,\"justificationRequired\":true},\n    ";
        String spliced = production.replace("\"pkiSession\": {", insertion + "\"pkiSession\": {");
        assertThrows(IllegalArgumentException.class, () -> PkiServerConfigurationCodec.decode(
                spliced.getBytes(StandardCharsets.UTF_8)));
    }

    private static String withIssuancePolicies(String extendedCommitment) throws Exception {
        String production = Files.readString(PRODUCTION_EXAMPLE);
        StringBuilder insertion = new StringBuilder()
                .append("\"issuanceSingleApprovalPolicy\": {\"policyId\":\"issuance-single\",\"threshold\":1,")
                .append("\"eligibleApprovers\":[\"issuance-approver\"],\"requiredRoleTemplateIds\":[],")
                .append("\"requesterSeparation\":true,\"lifetimeMillis\":3600000,\"justificationRequired\":true},\n    ")
                .append("\"issuanceThresholdApprovalPolicy\": {\"policyId\":\"issuance-threshold\",\"threshold\":2,")
                .append("\"eligibleApprovers\":[\"issuance-approver\",\"second-approver\"],")
                .append("\"requiredRoleTemplateIds\":[],\"requesterSeparation\":true,\"lifetimeMillis\":3600000,")
                .append("\"justificationRequired\":true},\n    ");
        if (extendedCommitment != null) {
            insertion.append("\"extendedApprovalCommitment\":\"").append(extendedCommitment).append("\",\n    ");
        }
        return production.replace("\"pkiSession\": {", insertion + "\"pkiSession\": {");
    }
}
