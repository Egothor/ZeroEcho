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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

/** Round-trip, classification, and strict-decode coverage for issuance execution evidence. */
class IssuanceExecutionEvidenceTest {
    private static final String COMMITMENT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    void administrativeEvidenceRoundTrips() {
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.administrative("operator-a", "production",
                "correlation-1", IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, COMMITMENT, "ca-a", "leaf");
        IssuanceExecutionEvidence decoded = IssuanceExecutionEvidence.decode(evidence.attributes()).orElseThrow();
        assertEquals(evidence, decoded);
        assertEquals(IssuanceExecutionEvidence.ActorType.ADMIN_PRINCIPAL, decoded.actorType());
        assertEquals(Optional.of(COMMITMENT), decoded.operationCommitment());
        assertEquals("ca-a", decoded.issuerCaId());
        assertEquals("leaf", decoded.profileId());
    }

    @Test
    void acmeEvidenceRoundTrips() {
        IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.acme("acct-1", "production", "correlation-2",
                "ca-a", "leaf");
        IssuanceExecutionEvidence decoded = IssuanceExecutionEvidence.decode(evidence.attributes()).orElseThrow();
        assertEquals(evidence, decoded);
        assertEquals(IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT, decoded.actorType());
        assertTrue(decoded.operationCommitment().isEmpty());
        assertTrue(decoded.authorizationPath().isEmpty());
    }

    @Test
    void protocolEvidenceRetainsRealRequesterAndExactApprovalPath() {
        java.util.Map<IssuanceExecutionEvidence.ActorType, IssuanceExecutionEvidence.Authentication> mechanisms = java.util.Map.of(
                IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT, IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS,
                IssuanceExecutionEvidence.ActorType.EST_CLIENT, IssuanceExecutionEvidence.Authentication.EST_MTLS,
                IssuanceExecutionEvidence.ActorType.SCEP_SIGNER, IssuanceExecutionEvidence.Authentication.SCEP_CMS,
                IssuanceExecutionEvidence.ActorType.CMP_SIGNER, IssuanceExecutionEvidence.Authentication.CMP_SIGNATURE,
                IssuanceExecutionEvidence.ActorType.CMP_PBM, IssuanceExecutionEvidence.Authentication.CMP_PBM);
        mechanisms.forEach((actor, authentication) -> {
            for (boolean approved : java.util.List.of(false, true)) {
                IssuanceExecutionEvidence evidence = IssuanceExecutionEvidence.enrollment(actor, "protocol-requester", "realm",
                        "enrollment-id", authentication, approved, COMMITMENT, "ca", "profile");
                assertEquals(evidence, IssuanceExecutionEvidence.decode(evidence.attributes()).orElseThrow());
                assertEquals(IssuanceExecutionEvidence.Authorization.ENROLLMENT_POLICY, evidence.authorization());
                assertEquals(Optional.of(approved ? IssuanceExecutionEvidence.AuthorizationPath.APPROVAL
                        : IssuanceExecutionEvidence.AuthorizationPath.ENROLLMENT_POLICY), evidence.authorizationPath());
            }
            assertThrows(IllegalArgumentException.class, () -> IssuanceExecutionEvidence.administrative("admin", "realm", "request",
                    authentication, IssuanceExecutionEvidence.AuthorizationPath.APPROVAL, COMMITMENT, "ca", "profile"));
        });
        assertThrows(IllegalArgumentException.class, () -> IssuanceExecutionEvidence.enrollment(
                IssuanceExecutionEvidence.ActorType.ADMIN_PRINCIPAL, "admin", "realm", "request",
                IssuanceExecutionEvidence.Authentication.DIRECT_MTLS, true, COMMITMENT, "ca", "profile"));
        assertThrows(IllegalArgumentException.class, () -> IssuanceExecutionEvidence.enrollment(
                IssuanceExecutionEvidence.ActorType.CMP_PBM, "requester", "realm", "request",
                IssuanceExecutionEvidence.Authentication.CMP_SIGNATURE, true, COMMITMENT, "ca", "profile"));
    }

    @Test
    void decodeReturnsEmptyWhenNoEvidencePresent() {
        assertTrue(IssuanceExecutionEvidence.decode(SimpleAttributeSet.builder().build()).isEmpty());
    }

    @Test
    void rejectsInconsistentAdminClassification() {
        // ADMIN actor with ACME authorization is not a valid combination.
        assertThrows(IllegalArgumentException.class, () -> new IssuanceExecutionEvidence(
                IssuanceExecutionEvidence.ActorType.ADMIN_PRINCIPAL, "operator-a", "production", "c",
                IssuanceExecutionEvidence.Authentication.DIRECT_MTLS,
                IssuanceExecutionEvidence.Authorization.ACME_OWNERSHIP, Optional.empty(), Optional.empty(),
                "ca-a", "leaf", IssuanceExecutionEvidence.Outcome.ISSUED));
    }

    @Test
    void rejectsPartialEvidenceVocabulary() {
        // A single evidence-namespaced attribute without the rest of the closed set is rejected.
        AttributeSet partial = SimpleAttributeSet.builder()
                .put(IssuanceExecutionEvidence.ACTOR_ID, new AttributeValue.StringValue("operator-a")).build();
        assertThrows(IllegalArgumentException.class, () -> IssuanceExecutionEvidence.decode(partial));
    }
}
