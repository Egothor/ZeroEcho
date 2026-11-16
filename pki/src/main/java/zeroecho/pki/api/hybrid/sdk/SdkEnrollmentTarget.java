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
package zeroecho.pki.api.hybrid.sdk;

import java.util.Map;
import java.util.Objects;
import zeroecho.pki.api.request.X509EnrollmentPayload;

/**
 * Captures the public native-enrollment coordinates bound into an SDK issuance target.
 *
 * <p>These immutable values identify the retained endpoint, policy, request and
 * authentication-context commitments. They do not authenticate a caller or authorize
 * enrollment. CMP requests use CRMF; the other supported carriers use PKCS#10.
 *
 * @param version contract version, which must be 1
 * @param protocol native carrier: {@code ACME}, {@code EST}, {@code SCEP} or {@code CMP}
 * @param endpointId configured endpoint identifier, between 1 and 8,192 characters
 * @param sourceRevision frozen, nonnegative endpoint-source revision
 * @param endpointCommitment native endpoint-source commitment, between 1 and 8,192 characters
 * @param enrollmentPolicyId retained policy identifier, between 1 and 8,192 characters
 * @param enrollmentPolicyVersion positive retained policy version
 * @param enrollmentPolicyCommitment native policy commitment, between 1 and 8,192 characters
 * @param operation requested lifecycle action: {@code ISSUE}, {@code RENEW} or {@code REPLACE}
 * @param requestKind original request syntax; must not be {@code null}
 * @param transactionIdSha256 native transaction commitment as 64 lowercase hexadecimal characters
 * @param authenticationContextSha512 F6 commitment as {@code sha512:} followed by
 *        128 lowercase hexadecimal characters
 */
public record SdkEnrollmentTarget(int version, String protocol, String endpointId, long sourceRevision,
        String endpointCommitment, String enrollmentPolicyId, long enrollmentPolicyVersion,
        String enrollmentPolicyCommitment, String operation, X509EnrollmentPayload.Kind requestKind,
        String transactionIdSha256, String authenticationContextSha512) {
    /**
     * Validates the closed carrier, request-kind and commitment representation.
     *
     * <p>Validation is local and performs no endpoint lookup or enrollment admission.
     * The four endpoint and policy text coordinates are required and bounded; their
     * interpretation remains the responsibility of the native enrollment workflow.
     *
     * @throws NullPointerException if the protocol, operation or request kind is null
     * @throws IllegalArgumentException if a version, revision, carrier, action, text
     *         bound, commitment or carrier/request-kind combination is invalid
     * @param version contract version, which must be 1
     * @param protocol native carrier: {@code ACME}, {@code EST}, {@code SCEP} or {@code CMP}
     * @param endpointId configured endpoint identifier, between 1 and 8,192 characters
     * @param sourceRevision frozen, nonnegative endpoint-source revision
     * @param endpointCommitment native endpoint-source commitment, between 1 and 8,192 characters
     * @param enrollmentPolicyId retained policy identifier, between 1 and 8,192 characters
     * @param enrollmentPolicyVersion positive retained policy version
     * @param enrollmentPolicyCommitment native policy commitment, between 1 and 8,192 characters
     * @param operation requested lifecycle action: {@code ISSUE}, {@code RENEW} or {@code REPLACE}
     * @param requestKind original request syntax; must not be {@code null}
     * @param transactionIdSha256 native transaction commitment as 64 lowercase hexadecimal characters
     * @param authenticationContextSha512 F6 commitment as {@code sha512:} followed by 128 lowercase hexadecimal characters
     */
    public SdkEnrollmentTarget {
        if (version != 1 || sourceRevision < 0 || enrollmentPolicyVersion <= 0) {
            throw invalid();
        }
        if (!java.util.Set.of("ACME", "EST", "SCEP", "CMP").contains(protocol)
                || !java.util.Set.of("ISSUE", "RENEW", "REPLACE").contains(operation)) {
            throw invalid();
        }
        for (String value : new String[] {endpointId, endpointCommitment, enrollmentPolicyId, enrollmentPolicyCommitment}) {
            if (value == null || value.isEmpty() || value.length() > 8192) {
                throw invalid();
            }
        }
        Objects.requireNonNull(requestKind, "requestKind");
        if (transactionIdSha256 == null || !transactionIdSha256.matches("[0-9a-f]{64}")
                || authenticationContextSha512 == null || !authenticationContextSha512.matches("sha512:[0-9a-f]{128}")) {
            throw invalid();
        }
        if ((protocol.equals("CMP")) != (requestKind == X509EnrollmentPayload.Kind.CRMF)) {
            throw invalid();
        }
    }
    /**
     * Builds the canonical enrollment member used in F7 field 17.
     *
     * <p>The returned value contains the frozen public coordinates and introduces no
     * authentication authority. The surrounding SDK target supplies the wrapper version.
     *
     * @return a new canonical SDK object containing this enrollment target
     */
    public HybridSdkValue value() {
        return HybridSdkValue.object(Map.ofEntries(
                Map.entry("protocol", HybridSdkValue.text(protocol)),
                Map.entry("endpointId", HybridSdkValue.text(endpointId)),
                Map.entry("sourceRevision", HybridSdkValue.integer(sourceRevision)),
                Map.entry("endpointCommitment", HybridSdkValue.text(endpointCommitment)),
                Map.entry("enrollmentPolicyId", HybridSdkValue.text(enrollmentPolicyId)),
                Map.entry("enrollmentPolicyVersion", HybridSdkValue.integer(enrollmentPolicyVersion)),
                Map.entry("enrollmentPolicyCommitment", HybridSdkValue.text(enrollmentPolicyCommitment)),
                Map.entry("operation", HybridSdkValue.text(operation)),
                Map.entry("requestKind", HybridSdkValue.text(requestKind.name())),
                Map.entry("transactionIdSha256", HybridSdkValue.text(transactionIdSha256)),
                Map.entry("authenticationContextSha512", HybridSdkValue.text(authenticationContextSha512))));
    }
    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_ENROLLMENT_TARGET_INVALID");
    }
}
