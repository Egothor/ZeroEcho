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
package zeroecho.pki.server.http;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.pki.application.PkiOperationValue;

/**
 * Wire-level ACME fixture exercising real HTTPS and ES256 JWS authentication.
 *
 * <p>The caller owns the supplied HTTP client. This stateful fixture retains the
 * account key, account KID and latest replay nonce; callers serialize requests.
 * Closing clears local KID/nonce state without closing the borrowed HTTP client.</p>
 */
public final class AcmeTestClient implements AutoCloseable {
    private static final String JOSE = "application/jose+json";
    private static final int MAXIMUM_RESPONSE = 2_097_152;
    private final HttpClient client;
    private final URI directoryUri;
    private KeyPair accountKey;
    private String accountKid;
    private String nonce;

    /**
     * Creates a client for one exact ACME directory URL and ES256 account key.
     *
     * @param client caller-owned HTTPS client with test trust configuration
     * @param directoryUri exact public directory URL
     * @param accountKey P-256 account signing key pair
     * @throws NullPointerException if any argument is null
     */
    public AcmeTestClient(HttpClient client, URI directoryUri, KeyPair accountKey) {
        this.client = Objects.requireNonNull(client, "client");
        this.directoryUri = Objects.requireNonNull(directoryUri, "directoryUri");
        this.accountKey = Objects.requireNonNull(accountKey, "accountKey");
    }

    /**
     * Fetches the public directory and captures its response replay nonce.
     *
     * @return bounded actual HTTPS directory response
     * @throws Exception if request construction, HTTPS exchange or bounded response reading fails
     */
    public Response directory() throws Exception { return send(HttpRequest.newBuilder(directoryUri).GET().build()); }

    /**
     * Requests a fresh replay nonce using the advertised endpoint's HEAD operation.
     *
     * @param endpoint exact advertised new-nonce URL
     * @return actual HTTPS response whose nonce is retained by this fixture
     * @throws Exception if request construction or HTTPS exchange fails
     */
    public Response nonce(URI endpoint) throws Exception {
        return send(HttpRequest.newBuilder(endpoint).method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
    }

    /**
     * Submits JWK-authenticated account registration and retains the returned exact Location KID.
     *
     * @param endpoint exact advertised new-account URL
     * @param payload original account-registration JSON
     * @return actual registration response
     * @throws Exception if signing/HTTPS fails or the response lacks a Location field
     */
    public Response createAccount(URI endpoint, String payload) throws Exception {
        Response response = jwk(endpoint, payload);
        accountKid = response.header("Location").orElseThrow();
        return response;
    }

    /**
     * Signs one JWK-authenticated request with the current account key and replay nonce.
     *
     * @param endpoint exact external URL bound into the protected JWS header
     * @param payload original JSON payload
     * @return actual HTTPS protocol response
     * @throws Exception if signing, request construction or HTTPS exchange fails
     */
    public Response jwk(URI endpoint, String payload) throws Exception {
        return post(endpoint, flattened(endpoint, payload.getBytes(StandardCharsets.UTF_8), accountKey,
                Optional.of(jwk(accountKey)), Optional.empty(), true));
    }

    /**
     * Signs one account-KID-authenticated request with the current key and replay nonce.
     *
     * @param endpoint exact external URL bound into the protected JWS header
     * @param payload original JSON payload, or empty for POST-as-GET
     * @return actual HTTPS protocol response
     * @throws IllegalStateException if no account KID has been adopted
     * @throws Exception if signing, request construction or HTTPS exchange fails
     */
    public Response kid(URI endpoint, String payload) throws Exception {
        if (accountKid == null) throw new IllegalStateException("ACME account has not been created");
        return post(endpoint, flattened(endpoint, payload.getBytes(StandardCharsets.UTF_8), accountKey,
                Optional.empty(), Optional.of(accountKid), true));
    }

    /**
     * Sends a real KID JWS using an explicit nonce for replay-negative tests.
     *
     * <p>The previously retained nonce is restored before transport; the response may
     * subsequently replace it with a fresh server nonce.</p>
     *
     * @param endpoint exact external URL bound into the JWS
     * @param payload original JSON payload
     * @param selectedNonce explicit nonce to use for this signature
     * @return actual HTTPS protocol response
     * @throws IllegalStateException if no account KID has been adopted
     * @throws NullPointerException if the selected nonce is null
     * @throws Exception if signing, request construction or HTTPS exchange fails
     */
    public Response kidWithNonce(URI endpoint, String payload, String selectedNonce) throws Exception {
        if (accountKid == null) throw new IllegalStateException("ACME account has not been created");
        String current = nonce; byte[] body;
        try {
            nonce = Objects.requireNonNull(selectedNonce, "selectedNonce");
            body = flattened(endpoint, payload.getBytes(StandardCharsets.UTF_8), accountKey, Optional.empty(), Optional.of(accountKid), true);
        } finally { nonce = current; }
        return post(endpoint, body);
    }

    /**
     * Performs nested-JWS account-key rollover and adopts the replacement only after a 2xx response.
     *
     * @param endpoint exact advertised key-change URL
     * @param replacement P-256 replacement account key pair
     * @return actual HTTPS key-change response
     * @throws Exception if nested signing, request construction or HTTPS exchange fails
     */
    public Response rollover(URI endpoint, KeyPair replacement) throws Exception {
        String innerClaims = "{\"account\":\"" + accountKid + "\",\"oldKey\":" + jwk(accountKey) + "}";
        byte[] inner = flattened(endpoint, innerClaims.getBytes(StandardCharsets.UTF_8), replacement,
                Optional.of(jwk(replacement)), Optional.empty(), false);
        Response response = post(endpoint, flattened(endpoint, inner, accountKey, Optional.empty(),
                Optional.of(accountKid), true));
        if (response.status() >= 200 && response.status() < 300) accountKey = replacement;
        return response;
    }

    /**
     * Sends authenticated POST-as-GET using a zero-length JWS payload.
     *
     * @param endpoint exact account-owned resource URL
     * @return actual HTTPS resource response
     * @throws IllegalStateException if no account KID has been adopted
     * @throws Exception if signing, request construction or HTTPS exchange fails
     */
    public Response postAsGet(URI endpoint) throws Exception { return kid(endpoint, ""); }

    /**
     * Returns the exact adopted account KID without synthesizing a URL.
     *
     * @return current account KID, or null before account creation/adoption
     */
    public String accountKid() { return accountKid; }

    /**
     * Adopts an existing HTTPS account KID for restart and superseded-key fixtures.
     *
     * @param kid existing account URL; must begin with the HTTPS scheme
     * @throws IllegalArgumentException if the KID is null or is not an HTTPS URL
     */
    public void useAccount(String kid) {
        if (kid == null || !kid.startsWith("https://")) {
            throw new IllegalArgumentException("ACME account KID is invalid");
        }
        accountKid = kid;
    }

    /**
     * Returns the latest nonce captured from an actual server response.
     *
     * @return retained nonce, or empty before any nonce-bearing response
     */
    public Optional<String> replayNonce() { return Optional.ofNullable(nonce); }

    /**
     * Builds RFC 8555 key authorization using the canonical P-256 account JWK thumbprint.
     *
     * @param token server-issued challenge token
     * @return token followed by the unpadded base64url JWK SHA-256 thumbprint
     * @throws Exception if account JWK construction or SHA-256 initialization fails
     */
    public String keyAuthorization(String token) throws Exception {
        String value = jwk(accountKey);
        PkiOperationValue.ObjectValue parsed = (PkiOperationValue.ObjectValue) StrictJson.parse(
                value.getBytes(StandardCharsets.UTF_8), 4_096);
        String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
                + ((PkiOperationValue.Text) parsed.fields().get("x")).value() + "\",\"y\":\""
                + ((PkiOperationValue.Text) parsed.fields().get("y")).value() + "\"}";
        return token + "." + encode(MessageDigest.getInstance("SHA-256")
                .digest(canonical.getBytes(StandardCharsets.US_ASCII)));
    }

    /**
     * Builds a nested HS256 external-account JWS for the deterministic test provider.
     *
     * @param newAccount exact new-account URL bound into the protected header
     * @param keyId configured external-account key identity
     * @param secret caller-owned MAC key bytes; copied for MAC initialization
     * @return flattened nested JWS JSON string
     * @throws Exception if MAC initialization, JWK construction or signing fails
     */
    public String externalAccountBinding(URI newAccount, String keyId, byte[] secret) throws Exception {
        String protectedValue = encode(("{\"alg\":\"HS256\",\"kid\":\"" + keyId
                + "\",\"url\":\"" + newAccount.toASCIIString() + "\"}").getBytes(StandardCharsets.UTF_8));
        String payload = encode(jwk(accountKey).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.clone(), "HmacSHA256"));
        String signature = encode(mac.doFinal((protectedValue + "." + payload)
                .getBytes(StandardCharsets.US_ASCII)));
        return "{\"protected\":\"" + protectedValue + "\",\"payload\":\"" + payload
                + "\",\"signature\":\"" + signature + "\"}";
    }

    /**
     * Requires a textual property in a bounded strict JSON response object.
     *
     * @param response actual captured protocol response
     * @param field required JSON property name
     * @return exact response text value
     * @throws IllegalArgumentException if the response object or required text field is invalid
     */
    public static String text(Response response, String field) {
        PkiOperationValue value = response.json().fields().get(field);
        if (value instanceof PkiOperationValue.Text text) return text.value();
        throw new IllegalArgumentException("Missing ACME response field: " + field);
    }

    /**
     * Requires a list consisting only of text values in a strict response object.
     *
     * @param response actual captured protocol response
     * @param field required JSON property name
     * @return immutable ordered response text values
     * @throws IllegalArgumentException if the object, list field or any element has another shape
     */
    public static List<String> textList(Response response, String field) {
        PkiOperationValue value = response.json().fields().get(field);
        if (!(value instanceof PkiOperationValue.ListValue list)) {
            throw new IllegalArgumentException("Missing ACME response list: " + field);
        }
        return list.values().stream().map(item -> {
            if (item instanceof PkiOperationValue.Text text) return text.value();
            throw new IllegalArgumentException("Invalid ACME response list: " + field);
        }).toList();
    }

    /**
     * Requires the fixture's single-challenge authorization-response projection.
     *
     * @param response actual captured authorization response
     * @return sole challenge URL selected from the text-valued challenges array
     * @throws IllegalArgumentException if there is no exact single text URL or its URI is invalid
     */
    public static Challenge challenge(Response response) {
        PkiOperationValue value = response.json().fields().get("challenges");
        if (!(value instanceof PkiOperationValue.ListValue list) || list.values().size() != 1
                || !(list.values().get(0) instanceof PkiOperationValue.Text url)) {
            throw new IllegalArgumentException("ACME challenge response is invalid");
        }
        return new Challenge(URI.create(url.value()));
    }

    private Response post(URI endpoint, byte[] body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(endpoint).timeout(Duration.ofSeconds(20))
                .header("Content-Type", JOSE).POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        return send(request);
    }

    private Response send(HttpRequest request) throws Exception {
        HttpResponse<byte[]> response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.body().length > MAXIMUM_RESPONSE) throw new IllegalStateException("ACME response is oversized");
        response.headers().firstValue("Replay-Nonce").ifPresent(value -> nonce = value);
        return new Response(response.statusCode(), response.headers().map(), response.body());
    }

    private byte[] flattened(URI endpoint, byte[] payload, KeyPair key, Optional<String> protectedJwk,
            Optional<String> kid, boolean includeNonce) throws Exception {
        if (protectedJwk.isPresent() == kid.isPresent()) throw new IllegalArgumentException("JWK/KID mode is invalid");
        StringBuilder header = new StringBuilder("{\"alg\":\"ES256\"");
        if (includeNonce) {
            if (nonce == null) throw new IllegalStateException("ACME nonce is unavailable");
            header.append(",\"nonce\":\"").append(nonce).append('"');
        }
        header.append(",\"url\":\"").append(endpoint.toASCIIString()).append('"');
        protectedJwk.ifPresent(value -> header.append(",\"jwk\":").append(value));
        kid.ifPresent(value -> header.append(",\"kid\":\"").append(value).append('"'));
        header.append('}');
        String encodedHeader = encode(header.toString().getBytes(StandardCharsets.UTF_8));
        String encodedPayload = encode(payload);
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(key.getPrivate());
        signer.update((encodedHeader + "." + encodedPayload).getBytes(StandardCharsets.US_ASCII));
        String document = "{\"protected\":\"" + encodedHeader + "\",\"payload\":\""
                + encodedPayload + "\",\"signature\":\"" + encode(signer.sign()) + "\"}";
        return document.getBytes(StandardCharsets.UTF_8);
    }

    private static String jwk(KeyPair keyPair) {
        ECPublicKey key = (ECPublicKey) keyPair.getPublic();
        return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
                + coordinate(key.getW().getAffineX()) + "\",\"y\":\""
                + coordinate(key.getW().getAffineY()) + "\"}";
    }

    private static String coordinate(BigInteger value) {
        byte[] source = value.toByteArray(); byte[] exact = new byte[32];
        int length = Math.min(source.length, exact.length);
        System.arraycopy(source, source.length - length, exact, exact.length - length, length);
        return encode(exact);
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    /**
     * {@inheritDoc}
     */
    @Override public void close() { nonce = null; accountKid = null; }

    /**
     * Captured bounded response with a copied entity and a shallow immutable header-map snapshot.
     *
     * @param status actual HTTP response status
     * @param headers actual response fields; map copied, value lists retained
     * @param body actual entity bytes; copied on construction and access
     */
    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
        /**
         * Copies response entity bytes and snapshots the header map.
         *
         * @param status actual HTTP response status
         * @param headers response header map; value lists retained
         * @param body response entity bytes; copied
         * @throws NullPointerException if the map, a map entry or body is null
         */
        public Response { headers = Map.copyOf(headers); body = body.clone(); }
        /**
         * Copies the captured protocol entity for independent caller ownership.
         *
         * @return newly allocated response body bytes
         */
        @Override public byte[] body() { return body.clone(); }
        /**
         * Finds the first header value using case-insensitive field-name matching.
         *
         * @param name requested HTTP field name
         * @return first matching field value, or empty when absent
         */
        public Optional<String> header(String name) {
            return headers.entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase(name))
                    .flatMap(entry -> entry.getValue().stream()).findFirst();
        }
        /**
         * Decodes the captured entity as one strict bounded JSON object.
         *
         * @return closed operation-value object model
         * @throws IllegalArgumentException if the entity is malformed, oversized or has another root type
         */
        public PkiOperationValue.ObjectValue json() {
            PkiOperationValue value = StrictJson.parse(body, MAXIMUM_RESPONSE);
            if (value instanceof PkiOperationValue.ObjectValue object) return object;
            throw new IllegalArgumentException("ACME response is not an object");
        }
        /**
         * Decodes the captured entity as UTF-8 for test assertions.
         *
         * @return response text using the standard replacement behavior for malformed UTF-8
         */
        public String bodyText() { return new String(body, StandardCharsets.UTF_8); }
    }

    /**
     * Single challenge location selected from the fixture authorization response.
     *
     * @param url exact challenge URI; retained without additional validation
     */
    public record Challenge(URI url) { }
}
