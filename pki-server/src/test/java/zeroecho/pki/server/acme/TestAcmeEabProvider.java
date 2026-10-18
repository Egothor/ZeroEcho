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
package zeroecho.pki.server.acme;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Deterministic secret-free test proof of explicit EAB provider composition. */
public final class TestAcmeEabProvider implements AcmeExternalAccountBindingProvider {
    /** Stable test provider identity. */
    public static final String ID = "test.eab.v1";
    private static final byte[] SECRET = "zeroecho-test-eab-secret-32-bytes"
            .getBytes(StandardCharsets.US_ASCII);
    private static final Pattern FLATTENED = Pattern.compile("\\{\\\"protected\\\":\\\"([A-Za-z0-9_-]+)\\\","
            + "\\\"payload\\\":\\\"([A-Za-z0-9_-]+)\\\",\\\"signature\\\":\\\"([A-Za-z0-9_-]+)\\\"}");
    private static final Pattern JWK = Pattern.compile("\\{\\\"kty\\\":\\\"EC\\\",\\\"crv\\\":\\\"P-256\\\","
            + "\\\"x\\\":\\\"([A-Za-z0-9_-]{43})\\\",\\\"y\\\":\\\"([A-Za-z0-9_-]{43})\\\"}");

    @Override public String id() { return ID; }

    @Override public Binding verify(Request request, ProviderConfig configuration) {
        if (!ID.equals(configuration.backendId()) || !configuration.properties().isEmpty()) {
            throw new SecurityException("Test EAB rejected");
        }
        try {
            Matcher match = FLATTENED.matcher(new String(request.nestedJws(), StandardCharsets.US_ASCII));
            if (!match.matches()) throw new SecurityException("Test EAB rejected");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String protectedValue = new String(decoder.decode(match.group(1)), StandardCharsets.UTF_8);
            String payload = new String(decoder.decode(match.group(2)), StandardCharsets.UTF_8);
            Matcher jwk = JWK.matcher(payload);
            if (!jwk.matches()) throw new SecurityException("Test EAB rejected");
            String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"" + jwk.group(1)
                    + "\",\"y\":\"" + jwk.group(2) + "\"}";
            if (!protectedValue.contains("\"alg\":\"HS256\"")
                    || !protectedValue.contains("\"kid\":\"test-key\"")
                    || !protectedValue.contains("/acme/eab/new-account\"")
                    || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                            .digest(canonical.getBytes(StandardCharsets.US_ASCII)))
                            .equals(request.accountKeyThumbprint())) {
                throw new SecurityException("Test EAB rejected");
            }
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(SECRET, "HmacSHA256"));
            byte[] expected = mac.doFinal((match.group(1) + "." + match.group(2))
                    .getBytes(StandardCharsets.US_ASCII));
            byte[] actual = decoder.decode(match.group(3));
            if (!MessageDigest.isEqual(expected, actual)) throw new SecurityException("Test EAB rejected");
            return new Binding("test-key", "b".repeat(64), Set.of("localhost"),
                    request.now().plus(Duration.ofMinutes(5)), true);
        } catch (SecurityException failure) {
            throw failure;
        } catch (Exception failure) {
            throw new SecurityException("Test EAB rejected");
        }
    }
}
