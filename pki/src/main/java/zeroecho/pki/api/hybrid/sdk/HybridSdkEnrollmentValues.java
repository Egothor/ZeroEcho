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

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Map;

/**
 * Checks the closed native enrollment authentication field registry.
 */
final class HybridSdkEnrollmentValues {
    private static final String LIMIT_EST_V1 = "est-v1";
    private static final String LIMIT_IDENTIFIERS = "identifiers";
    private static final String LIMIT_CHALLENGEAUTHENTICATED = "challengeAuthenticated";
    private static final String REVISION_FIELD = "authenticationCredentialRevision";

    private final HybridSdkFrame frame;

    /* default */ HybridSdkEnrollmentValues(HybridSdkFrame frame) {
        this.frame = frame;
    }

    private byte[] field(int tag) {
        return frame.field(tag);
    }

    private String text(int tag) {
        return HybridSdkValue.text(field(tag));
    }



    private void requireEnrollmentAuthenticationValues() {
        String[] keys;
        String carrier;
        switch (text(2)) {
            case "acme-account-jws-v1" -> {
                carrier = "acme-v1";
                keys =
                        new String[] {
                            "endpointId",
                            "endpointCommitment",
                            "accountId",
                            "accountKeySha256",
                            "orderId",
                            "orderCommitment",
                            "authorizationCommitment",
                            LIMIT_IDENTIFIERS,
                            "requestKind"
                        };
            }
            case "est-mtls-v1" -> {
                carrier = LIMIT_EST_V1;
                keys =
                        new String[] {
                            "endpointId",
                            "endpointCommitment",
                            "certificateSha256",
                            "canonicalKeySha256",
                            "issuerSerialSha256",
                            "operation",
                            "predecessorId",
                            "requestKind"
                        };
            }
            case "scep-cms-v1" -> {
                carrier = "scep-v1";
                keys =
                        new String[] {
                            "endpointId",
                            "endpointCommitment",
                            "signerCertificateSha256",
                            "transactionIdSha256",
                            "senderNonceSha256",
                            "nativeMessageSha512",
                            "challengePolicyCommitment",
                            LIMIT_CHALLENGEAUTHENTICATED,
                            "messageType",
                            "requestKind"
                        };
            }
            case "cmp-signature-v1", "cmp-pbm-v1" -> {
                carrier = "cmp-v1";
                keys =
                        new String[] {
                            "endpointId",
                            "endpointCommitment",
                            "authenticationPolicyCommitment",
                            "manifestCommitment",
                            "transactionIdSha256",
                            "certReqId",
                            "bodyType",
                            "originalWireSha512",
                            "senderNonceSha256",
                            "recipientNonceSha256",
                            "authenticationCredentialId",
                            REVISION_FIELD,
                            "requestKind"
                        };
            }
            default -> throw invalid();
        }
        if (!text(4).equals(carrier)) {
            throw invalid();
        }
        Map<String, HybridSdkValue> values = HybridSdkValue.decode(field(5)).objectFields();
        if (!values.keySet().equals(java.util.Set.of(keys))) {
            throw invalid();
        }
        for (String key : keys) {
            requireEnrollmentValue(key, values.get(key), carrier);
        }
        if (LIMIT_EST_V1.equals(carrier)) {
            boolean enroll = "simpleenroll".equals(values.get("operation").textValue());
            if (enroll != values.get("predecessorId").textValue().isEmpty()) {
                throw invalid();
            }
        }
    }

    private static void requireEnrollmentValue(String key, HybridSdkValue value, String carrier) {
        if (LIMIT_IDENTIFIERS.equals(key)) {
            HybridSdkAcmeIdentifiers.validate(value);
            return;
        }
        if (LIMIT_CHALLENGEAUTHENTICATED.equals(key)) {
            if (!Arrays.equals(value.encode(), HybridSdkValue.bool(true).encode())) {
                throw invalid();
            }
            return;
        }
        if (REVISION_FIELD.equals(key)) {
            if (value.integerValue() < 0) {
                throw invalid();
            }
            return;
        }
        requireEnrollmentText(key, value.textValue(), carrier);
    }

    private static void requireEnrollmentText(String key, String text, String carrier) {
        boolean empty = "recipientNonceSha256".equals(key) || "predecessorId".equals(key);
        if ((!empty && text.isEmpty()) || text.length() > 8_192) {
            throw invalid();
        }
        requireEnrollmentDigest(key, text, empty);
        requireRequestCoordinates(key, text, carrier);
        if ("operation".equals(key)
                && !java.util.Set.of("simpleenroll", "simplereenroll").contains(text)) {
            throw invalid();
        }
        if ("authenticationCredentialId".equals(key) && (!text.matches("[\\x21-\\x7e]{1,128}"))) {
            throw invalid();
        }
    }

    private static void requireRequestCoordinates(String key, String text, String carrier) {
        if ("certReqId".equals(key)
                && (!text.matches("0|[1-9][0-9]{0,19}") || new BigInteger(text).bitLength() > 64)) {
            throw invalid();
        }
        if ("requestKind".equals(key)
                && !text.equals("cmp-v1".equals(carrier) ? "CRMF" : "PKCS10")) {
            throw invalid();
        }
    }

    private static void requireEnrollmentDigest(String key, String text, boolean empty) {
        if (key.endsWith("Sha256") && !(empty && text.isEmpty()) && !text.matches("[0-9a-f]{64}")) {
            throw invalid();
        }
        if (key.endsWith("Sha512") && !text.matches("sha512:[0-9a-f]{128}")) {
            throw invalid();
        }
    }

    /* default */ void validate() {
        requireEnrollmentAuthenticationValues();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
