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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.api.PkiId;

/** Stable typed overload mappings at each signing-capable HTTP boundary. */
final class SigningOverloadMappingTest {

    @Test
    void administrativeFailureMapsToHttp429WithoutMessageParsing() {
        PkiOperationOutcome outcome = new PkiOperationOutcome.Failed("issue-credential",
                PkiOperationFailure.OVERLOADED, "SIGNING_OVERLOADED");

        HttpResponses.Response response = HttpResponses.gateway("request-1", "issue-credential",
                new ServerOperationGateway.Outcome.Executed(outcome));

        assertEquals(429, response.statusCode());
        assertTrue(new String(response.body(), StandardCharsets.UTF_8)
                .contains("\"classification\":\"OVERLOADED\""));
    }

    @Test
    void administrativePendingMapsTo202WithPrivateStatusLocation() {
        PkiId operationId = new PkiId("signing:private-operation");

        HttpResponses.Response response = HttpResponses.gateway("request-2", "issue-credential",
                new ServerOperationGateway.Outcome.Executed(
                        new PkiOperationOutcome.Pending("issue-credential", operationId)));

        assertEquals(202, response.statusCode());
        assertEquals(java.util.Optional.of("/admin/v1/signing-operations/" + operationId.value()),
                response.statusLocation());
        assertTrue(new String(response.body(), StandardCharsets.UTF_8).contains("\"status\":\"PENDING\""));
    }

    @ParameterizedTest
    @CsvSource({
            "RECOVERY_REQUIRED, 503, true, false",
            "EXTERNAL_OUTCOME_UNKNOWN, 409, false, true"
    })
    void administrativeUncertaintyMapsToMutuallyExclusiveRecoverySemantics(
            PkiOperationFailure classification, int expectedStatus,
            boolean recoveryRequired, boolean reconciliationRequired) {
        PkiOperationOutcome outcome = new PkiOperationOutcome.Failed(
                "issue-credential", classification, classification.name());

        HttpResponses.Response response = HttpResponses.gateway(
                "request-uncertainty", "issue-credential",
                new ServerOperationGateway.Outcome.Executed(outcome));
        String body = new String(response.body(), StandardCharsets.UTF_8);

        assertEquals(expectedStatus, response.statusCode());
        assertTrue(body.contains("\"classification\":\"" + classification.name() + "\""));
        assertTrue(body.contains("\"recoveryRequired\":" + recoveryRequired));
        assertTrue(body.contains("\"reconciliationRequired\":" + reconciliationRequired));
    }

    @Test
    void acmeFailureMapsToRateLimitedFromTypedClassification() {
        SigningExecutionException overload = failure(SigningExecutionException.Classification.OVERLOADED,
                "message text intentionally unrelated");

        AcmeHttpHandler.Response response = AcmeHttpHandler.protocolFailure(overload);

        assertEquals(429, response.status());
        assertTrue(new String(response.body(), StandardCharsets.UTF_8)
                .contains("urn:ietf:params:acme:error:rateLimited"));
    }

    @Test
    void ocspFailureMapsOnlyTypedOverloadToHttp429() {
        assertEquals(429, OcspHttpHandler.signingFailureStatus(failure(
                SigningExecutionException.Classification.OVERLOADED, "not inspected")));
        assertEquals(503, OcspHttpHandler.signingFailureStatus(failure(
                SigningExecutionException.Classification.SHUTTING_DOWN, "SIGNING_OVERLOADED")));
    }

    @Test
    void ocspPendingUsesCanonicalDerTryLaterBody() throws Exception {
        byte[] encoded = OcspHttpHandler.protocolFailureBody(
                org.bouncycastle.cert.ocsp.OCSPRespBuilder.TRY_LATER);

        org.bouncycastle.cert.ocsp.OCSPResp decoded =
                new org.bouncycastle.cert.ocsp.OCSPResp(encoded);
        assertEquals(org.bouncycastle.cert.ocsp.OCSPRespBuilder.TRY_LATER, decoded.getStatus());
        assertTrue(java.util.Arrays.equals(encoded, decoded.getEncoded()));
    }

    private static SigningExecutionException failure(SigningExecutionException.Classification classification,
            String message) {
        return new SigningExecutionException(classification, message);
    }
}
