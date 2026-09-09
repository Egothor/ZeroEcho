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
package zeroecho.pki.server.acme;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Production HTTP-01 validator using policy-checked, IP-pinned port-80 sockets. */
@SuppressWarnings("PMD")
public final class Http01ChallengeProvider implements AcmeChallengeProvider {
    private static final int HTTP_PORT = 80;
    /** Stable built-in provider identity. */
    public static final String ID = "zeroecho.http-01.v1";

    /** Creates the stateless built-in HTTP-01 challenge provider. */
    public Http01ChallengeProvider() {
    }

    @Override public String id() { return ID; }
    @Override public Set<AcmeState.ChallengeType> challengeTypes() { return Set.of(AcmeState.ChallengeType.HTTP_01); }

    @Override
    public Result validate(Context context, ProviderConfig configuration, CancellationSignal cancellation) {
        if (context.challengeType() != AcmeState.ChallengeType.HTTP_01 || context.identifier().wildcard()) {
            return invalid(context, "IDENTIFIER_UNSUPPORTED");
        }
        Settings settings = settings(configuration);
        try {
            InetAddress[] resolved = InetAddress.getAllByName(context.identifier().value());
            if (resolved.length == 0 || resolved.length > settings.maximumAddresses()
                    || Arrays.stream(resolved).anyMatch(address -> !settings.allowPrivate() && !globallyRoutable(address))) {
                return invalid(context, "TARGET_NETWORK_REJECTED");
            }
            Arrays.sort(resolved, Comparator.comparing(InetAddress::getHostAddress));
            boolean probeCompleted = false;
            for (InetAddress address : resolved) {
                cancellation.throwIfCancelled();
                try {
                    Result result = probe(address, context, settings, cancellation);
                    probeCompleted = true;
                    if (result.valid()) return result;
                } catch (java.io.IOException unavailable) {
                    // Continue across the complete bounded, policy-validated DNS answer set.
                }
            }
            return invalid(context, probeCompleted ? "KEY_AUTHORIZATION_MISMATCH" : "HTTP_VALIDATION_FAILED");
        } catch (Exception failure) {
            return invalid(context, "HTTP_VALIDATION_FAILED");
        }
    }

    private static Result probe(InetAddress address, Context context, Settings settings,
            CancellationSignal cancellation) throws Exception {
        long remaining = Math.max(1L, Duration.between(context.validationTime(), context.deadline()).toMillis());
        int timeout = Math.toIntExact(Math.min(settings.timeoutMillis(), remaining));
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, settings.targetPort()), timeout); socket.setSoTimeout(timeout);
            String request = "GET /.well-known/acme-challenge/" + context.token()
                    + " HTTP/1.1\r\nHost: " + context.identifier().value()
                    + "\r\nConnection: close\r\nAccept: text/plain\r\n\r\n";
            OutputStream output = socket.getOutputStream(); output.write(request.getBytes(StandardCharsets.US_ASCII));
            output.flush(); cancellation.throwIfCancelled();
            byte[] response = bounded(socket.getInputStream(), settings.maximumBodyBytes() + 16_384, cancellation);
            int boundary = indexOf(response, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            if (boundary < 0 || boundary > 16_384) return invalid(context, "HTTP_RESPONSE_MALFORMED");
            String headers = new String(response, 0, boundary, StandardCharsets.US_ASCII);
            if (!headers.startsWith("HTTP/1.1 200 ") && !headers.startsWith("HTTP/1.0 200 ")) {
                return invalid(context, "HTTP_STATUS_REJECTED");
            }
            byte[] body = Arrays.copyOfRange(response, boundary + 4, response.length);
            String observed = new String(body, StandardCharsets.US_ASCII).stripTrailing();
            boolean valid = MessageDigestSupport.equalAscii(observed, context.expectedKeyAuthorization());
            Instant now = context.validationTime();
            return new Result(valid, valid ? "VALID" : "KEY_AUTHORIZATION_MISMATCH", now, now.plus(Duration.ofHours(1)));
        }
    }

    private static byte[] bounded(InputStream input, int maximum, CancellationSignal cancellation) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(Math.min(maximum, 8_192)); byte[] buffer = new byte[4_096];
        int read; while ((read = input.read(buffer)) >= 0) { cancellation.throwIfCancelled();
            if (bytes.size() + read > maximum) throw new IllegalArgumentException("HTTP response bound exceeded");
            bytes.write(buffer, 0, read); }
        return bytes.toByteArray();
    }

    private static boolean globallyRoutable(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) return false;
        byte[] raw = address.getAddress();
        if (address instanceof Inet4Address) {
            int first = Byte.toUnsignedInt(raw[0]), second = Byte.toUnsignedInt(raw[1]);
            return first != 0 && first != 127 && !(first == 100 && second >= 64 && second <= 127)
                    && !(first == 169 && second == 254) && first < 224;
        }
        if (address instanceof Inet6Address) {
            return !(raw[0] == 0x20 && raw[1] == 0x01 && raw[2] == 0x0d && raw[3] == (byte) 0xb8)
                    && (raw[0] & 0xfe) != 0xfc;
        }
        return false;
    }

    private static Settings settings(ProviderConfig config) {
        Set<String> required = Set.of("allowPrivate", "timeoutMillis", "maximumBodyBytes", "maximumAddresses");
        Set<String> allowed = Set.of("allowPrivate", "timeoutMillis", "maximumBodyBytes", "maximumAddresses",
                "targetPort");
        if (!ID.equals(config.backendId()) || !config.properties().keySet().containsAll(required)
                || !allowed.containsAll(config.properties().keySet())) {
            throw new IllegalArgumentException("HTTP-01 provider configuration is invalid");
        }
        boolean allowPrivate = switch (config.require("allowPrivate")) { case "true" -> true; case "false" -> false;
            default -> throw new IllegalArgumentException("HTTP-01 network policy is invalid"); };
        int targetPort = config.get("targetPort").map(value -> integer(value, 1, 65_535)).orElse(HTTP_PORT);
        if (targetPort != HTTP_PORT && !allowPrivate) {
            throw new IllegalArgumentException("Nonstandard HTTP-01 port requires private-target policy");
        }
        return new Settings(allowPrivate, integer(config, "timeoutMillis", 100, 60_000),
                integer(config, "maximumBodyBytes", 64, 65_536), integer(config, "maximumAddresses", 1, 32),
                targetPort);
    }
    private static int integer(ProviderConfig config, String key, int minimum, int maximum) {
        return integer(config.require(key), minimum, maximum);
    }
    private static int integer(String source, int minimum, int maximum) {
        try { int value = Integer.parseInt(source); if (value < minimum || value > maximum) throw new NumberFormatException(); return value; }
        catch (NumberFormatException failure) { throw new IllegalArgumentException("HTTP-01 provider bound is invalid"); }
    }
    private static int indexOf(byte[] value, byte[] needle) { outer: for (int i = 0; i <= value.length - needle.length; i++) { for (int j = 0; j < needle.length; j++) if (value[i + j] != needle[j]) continue outer; return i; } return -1; }
    private static Result invalid(Context context, String code) { Instant now = context.validationTime(); return new Result(false, code, now, now.plus(Duration.ofMinutes(5))); }
    private record Settings(boolean allowPrivate, int timeoutMillis, int maximumBodyBytes, int maximumAddresses,
            int targetPort) { }
}
