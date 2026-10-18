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
package zeroecho.pki.impl.framework.x509.bc;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.X509EnrollmentPayload;

/** Closed extraction boundary for original X.509 enrollment transport attributes. */
public final class BcX509RequestPayloads {
    private static final int ORIGINAL_REQUEST_ATTRIBUTE = 1;
    private BcX509RequestPayloads() { }

    /**
     * Validates one original payload, its exclusive attribute and digest identity.
     * @param parsed diagnostic or persisted parsed request
     * @return independently owned typed payload
     * @throws IllegalArgumentException if any original binding is malformed or inconsistent
     */
    public static X509EnrollmentPayload extract(ParsedCertificationRequest parsed) {
        if (parsed == null || !BcX509CredentialFramework.FORMAT_ID.equals(parsed.formatId())) {
            throw new IllegalArgumentException("Retained certification request format is invalid");
        }
        if (parsed.attributes().ids().size() != ORIGINAL_REQUEST_ATTRIBUTE) {
            throw invalid();
        }
        AttributeId id = parsed.attributes().ids().iterator().next();
        X509EnrollmentPayload.Kind kind;
        String prefix;
        if (id.equals(BcX509Attributes.CSR_DER)) {
            kind = X509EnrollmentPayload.Kind.PKCS10;
            prefix = "csr:";
        } else if (id.equals(BcX509Attributes.CRMF_DER)) {
            kind = X509EnrollmentPayload.Kind.CRMF;
            prefix = "crmf:";
        } else {
            throw invalid();
        }
        List<AttributeValue> values = parsed.attributes().getAll(id);
        if (values.size() != 1 || !(values.getFirst() instanceof AttributeValue.BytesValue bytes)) {
            throw invalid();
        }
        byte[] original = bytes.value();
        if (original.length == 0 || original.length > X509EnrollmentPayload.MAXIMUM_DER_BYTES) {
            throw invalid();
        }
        X509EnrollmentPayload payload = new X509EnrollmentPayload(kind, original);
        requireIdentity(parsed, prefix, payload);
        return payload;
    }

    private static void requireIdentity(ParsedCertificationRequest parsed, String prefix, X509EnrollmentPayload payload) {
        try {
            String identity = prefix + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(payload.der()));
            if (!identity.equals(parsed.requestId().value())) {
                throw new IllegalArgumentException("Retained certification request identity differs");
            }
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Retained certification request payload is invalid");
    }
}
