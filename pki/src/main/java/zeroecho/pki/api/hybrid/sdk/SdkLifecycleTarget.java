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
import java.util.Set;
import zeroecho.pki.api.PkiId;

/**
 * Strict lifecycle extension of existing F7 field 17. The values are public
 * commitments, not possession evidence; both operation-bound proofs remain required.
 *
 * <p>Construction checks syntax and the closed operation names, without loading the
 * predecessor or proving either key. A permitted name in this carrier does not
 * establish that a particular server or native enrollment path supports it.</p>
 *
 * @param version payload version, exactly one
 * @param operation exact existing credential.renew/credential.reissue/credential.replace name
 * @param predecessorId retained predecessor credential identity
 * @param predecessorSha256 prefixed exact predecessor DER SHA-256
 * @param subjectPrimarySpkiSha512 prefixed requested primary SPKI SHA-512
 * @param subjectAlternativeSpkiSha512 prefixed requested alternative SPKI SHA-512
 */
public record SdkLifecycleTarget(int version, String operation, PkiId predecessorId,
        String predecessorSha256, String subjectPrimarySpkiSha512, String subjectAlternativeSpkiSha512) {
    private static final Set<String> FIELDS = Set.of("version", "operation", "predecessorId", "predecessorSha256",
            "subjectPrimarySpkiSha512", "subjectAlternativeSpkiSha512");

    /**
     * Checks the closed lifecycle schema and prefixed digest spellings.
     *
     * @param version payload version, exactly one
     * @param operation exact existing credential.renew/credential.reissue/credential.replace name
     * @param predecessorId retained predecessor credential identity
     * @param predecessorSha256 prefixed exact predecessor DER SHA-256
     * @param subjectPrimarySpkiSha512 prefixed requested primary SPKI SHA-512
     * @param subjectAlternativeSpkiSha512 prefixed requested alternative SPKI SHA-512
     * @throws NullPointerException if the predecessor identifier is null, or the operation is null when tested
     * @throws IllegalArgumentException if the version, operation name or digest syntax is invalid
     */
    public SdkLifecycleTarget {
        Objects.requireNonNull(predecessorId, "predecessorId");
        if (version != 1 || !Set.of("credential.renew", "credential.reissue", "credential.replace").contains(operation)
                || predecessorSha256 == null || !predecessorSha256.matches("sha256:[0-9a-f]{64}")
                || subjectPrimarySpkiSha512 == null || !subjectPrimarySpkiSha512.matches("sha512:[0-9a-f]{128}")
                || subjectAlternativeSpkiSha512 == null || !subjectAlternativeSpkiSha512.matches("sha512:[0-9a-f]{128}")) {
            throw new IllegalArgumentException("Invalid SDK lifecycle target");
        }
    }

    /**
     * Encodes these coordinates as the closed version-one lifecycle object.
     *
     * @return immutable canonical typed value for direct F7 lifecycle use or its enrollment wrapper
     * @throws IllegalArgumentException if the predecessor identifier exceeds typed-text encoding bounds
     */
    public HybridSdkValue value() {
        return HybridSdkValue.object(Map.of("version", HybridSdkValue.integer(1),
                "operation", HybridSdkValue.text(operation), "predecessorId", HybridSdkValue.text(predecessorId.value()),
                "predecessorSha256", HybridSdkValue.text(predecessorSha256),
                "subjectPrimarySpkiSha512", HybridSdkValue.text(subjectPrimarySpkiSha512),
                "subjectAlternativeSpkiSha512", HybridSdkValue.text(subjectAlternativeSpkiSha512)));
    }

    /**
     * Decodes the exact lifecycle object without accepting unknown or missing fields.
     *
     * @param value canonical typed F7 extension object
     * @return checked lifecycle coordinates
     * @throws NullPointerException if the value is null
     * @throws IllegalArgumentException if fields, types, version, identifier or commitments are invalid
     */
    public static SdkLifecycleTarget decode(HybridSdkValue value) {
        var fields = Objects.requireNonNull(value, "value").objectFields();
        if (!fields.keySet().equals(FIELDS) || fields.get("version").integerValue() != 1) {
            throw new IllegalArgumentException("Invalid SDK lifecycle extension schema");
        }
        return new SdkLifecycleTarget(1, fields.get("operation").textValue(),
                new PkiId(fields.get("predecessorId").textValue()), fields.get("predecessorSha256").textValue(),
                fields.get("subjectPrimarySpkiSha512").textValue(), fields.get("subjectAlternativeSpkiSha512").textValue());
    }
}
