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

import zeroecho.pkix.ocsp.StrictOcspProjection;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * Checks ordered closed OCSP status entries and unique certificate identities.
 */
final class HybridSdkOcspStatusValues {
    private static final String LIMIT_REVOKED = "REVOKED";

    private HybridSdkOcspStatusValues() {}

    /* default */ static void requireStatuses(HybridSdkValue value) {
        List<HybridSdkValue> statuses = value.listValues();
        if (statuses.isEmpty() || statuses.size() > 819) {
            throw invalid();
        }
        java.util.Set<String> ids = new HashSet<>();
        for (HybridSdkValue status : statuses) {
            requireStatus(status, ids);
        }
    }

    private static void requireStatus(HybridSdkValue status, java.util.Set<String> ids) {
            Map<String, HybridSdkValue> entry = status.objectFields();
            if (!entry.keySet()
                    .equals(java.util.Set.of("certIdDer", "status", "revocationTime", "reason"))) {
                throw invalid();
            }
            byte[] cert = entry.get("certIdDer").encode();
            if (cert[0] != 4
                    || cert.length <= 5
                    || !ids.add(ocspCertIdIdentity(Arrays.copyOfRange(cert, 5, cert.length)))) {
                throw invalid();
            }
            String state = entry.get("status").textValue();
            String revoked = entry.get("revocationTime").textValue();
            long reason = entry.get("reason").integerValue();
            if (!java.util.Set.of("GOOD", LIMIT_REVOKED, "UNKNOWN").contains(state)) {
                throw invalid();
            }
            requireRevocationState(state, revoked, reason);
    }

    private static void requireRevocationState(String state, String revoked, long reason) {
            if (LIMIT_REVOKED.equals(state)) {
                Instant instant = Instant.parse(revoked);
                if (!instant.toString().equals(revoked)
                        || instant.getNano() != 0
                        || reason < -1
                        || reason > 10
                        || reason == 7) {
                    throw invalid();
                }
            } else if (!revoked.isEmpty() || reason != -1) {
                throw invalid();
            }
    }

    // Preserve the finite safe frame parser failure without exposing untrusted causes.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static String ocspCertIdIdentity(byte[] bytes) {
        try {
            return StrictOcspProjection.certIdIdentity(bytes);
        } catch (IllegalArgumentException malformed) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
