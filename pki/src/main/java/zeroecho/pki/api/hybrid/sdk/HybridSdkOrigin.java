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



/**
 * Checks canonical SDK HTTPS origin spelling without performing DNS authorization.
 */
final class HybridSdkOrigin {
    private static final int LIMIT_1 = 1;
    private static final int LIMIT_4 = 4;

    private HybridSdkOrigin() { }

    /* default */ static void requireOrigin(String value) {
        if (value == null
                || value.length() > 256
                || !value.startsWith("https://")
                || !value.chars().allMatch(c -> c < 128)) {
            throw invalid();
        }
        String authority = value.substring(8);
        int colon = authority.lastIndexOf(':');
        if (colon < LIMIT_1) {
            throw invalid();
        }
        String host = authority.substring(0, colon);
        String port = authority.substring(colon + LIMIT_1);
        if (!port.matches("[1-9][0-9]{0,4}") || Integer.parseInt(port) > 65_535) {
            throw invalid();
        }
        requireOriginHost(host);
    }

    private static void requireOriginHost(String host) {
        if (host.startsWith("[")) {
            if (!host.endsWith("]")
                    || !host.substring(LIMIT_1, host.length() - LIMIT_1).matches("[0-9a-f:.]+")) {
                throw invalid();
            }
            if (!canonicalIpv6(host.substring(LIMIT_1, host.length() - LIMIT_1))
                    .equals(host.substring(LIMIT_1, host.length() - LIMIT_1))) {
                throw invalid();
            }
        } else if (host.matches("[0-9.]+")) {
            requireIpv4(host);
        } else {
            if (host.length() > 253 || !host.equals(host.toLowerCase(java.util.Locale.ROOT))) {
                throw invalid();
            }
            for (String label : host.split("\\.", -LIMIT_1)) {
                if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                    throw invalid();
                }
            }
        }
    }

    private static void requireIpv4(String host) {
            String[] parts = host.split("\\.", -LIMIT_1);
            if (parts.length != LIMIT_4) {
                throw invalid();
            }
            for (String part : parts) {
                if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) {
                    throw invalid();
                }
            }
    }

    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static String canonicalIpv6(String literal) {
        try {
            if (literal.indexOf(':') < 0) {
                throw invalid();
            }
            byte[] address = java.net.InetAddress.getByName(literal).getAddress();
            if (address.length == LIMIT_4) {
                return "::ffff:"
                        + (address[0] & 255)
                        + "."
                        + (address[LIMIT_1] & 255)
                        + "."
                        + (address[2] & 255)
                        + "."
                        + (address[3] & 255);
            }
            int[] groups = new int[8];
            int best = -LIMIT_1;
            int bestLength = LIMIT_1;
            for (int i = 0; i < 8; i++) {
                groups[i] = (address[2 * i] & 255) * 256 + (address[2 * i + LIMIT_1] & 255);
            }
            int i = 0;
            while (i < 8) {
                if (groups[i] != 0) {
                    i++;
                    continue;
                }
                int end = i;
                while (end < 8 && groups[end] == 0) {
                    end++;
                }
                if (end - i > bestLength) {
                    best = i;
                    bestLength = end - i;
                }
                i = end;
            }
            StringBuilder result = new StringBuilder();
            i = 0;
            while (i < 8) {
                if (i == best) {
                    result.append("::");
                    i += bestLength;
                } else {
                    if (!result.isEmpty() && result.charAt(result.length() - LIMIT_1) != ':') {
                        result.append(':');
                    }
                    result.append(Integer.toHexString(groups[i++]));
                }
            }
            return result.toString();
        } catch (java.net.UnknownHostException malformed) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }


}
