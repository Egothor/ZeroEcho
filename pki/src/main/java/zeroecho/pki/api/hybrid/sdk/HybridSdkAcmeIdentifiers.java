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

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Checks canonical ordered DNS identifiers retained by ACME authentication.
 */
final class HybridSdkAcmeIdentifiers {
    private HybridSdkAcmeIdentifiers() {}

    /* default */ static void validate(HybridSdkValue value) {
        List<HybridSdkValue> identifiers = value.listValues();
        if (identifiers.isEmpty()) {
            throw invalid();
        }
        String previous = null;
        for (HybridSdkValue identifier : identifiers) {
            Map<String, HybridSdkValue> item = identifier.objectFields();
            if (!item.keySet().equals(java.util.Set.of("type", "value", "wildcard"))
                    || !"dns".equals(item.get("type").textValue())) {
                throw invalid();
            }
            String dns = item.get("value").textValue();
            requireDnsName(dns);
            byte[] wildcard = item.get("wildcard").encode();
            if (!Arrays.equals(wildcard, HybridSdkValue.bool(false).encode())
                    && !Arrays.equals(wildcard, HybridSdkValue.bool(true).encode())) {
                throw invalid();
            }
            String coordinate = dns + "\u0000" + (wildcard[1] == 0 ? "0" : "1");
            if (previous != null && previous.compareTo(coordinate) >= 0) {
                throw invalid();
            }
            previous = coordinate;
        }
    }

    private static void requireDnsName(String dns) {
        if (dns.length() > 253 || !dns.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
            throw invalid();
        }
        for (String label : dns.split("\\.", -1)) {
            if (label.isEmpty()
                    || label.length() > 63
                    || label.startsWith("-")
                    || label.endsWith("-")) {
                throw invalid();
            }
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
