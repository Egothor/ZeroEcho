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
 *******************************************************************************/
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

/** Narrow wire-level ACME test client exercising the real HTTPS/JWS boundary. */
public final class AcmeTestClient implements AutoCloseable {
    private static final String JOSE = "application/jose+json";
    private static final int MAXIMUM_RESPONSE = 2_097_152;
    private final HttpClient client;
    private final URI directoryUri;
    private KeyPair accountKey;
    private String accountKid;
    private String nonce;

    /** Creates a client for one exact ACME directory URL and ES256 account key. */
    public AcmeTestClient(HttpClient client, URI directoryUri, KeyPair accountKey) {
        this.client = Objects.requireNonNull(client, "client");
        this.directoryUri = Objects.requireNonNull(directoryUri, "directoryUri");
        this.accountKey = Objects.requireNonNull(accountKey, "accountKey");
    }

    /** Fetches the directory object and captures its response nonce. */
    public Response directory() throws Exception { return send(HttpRequest.newBuilder(directoryUri).GET().build()); }

    /** Obtains a fresh replay nonce using the advertised endpoint. */
    public Response nonce(URI endpoint) throws Exception {
        return send(HttpRequest.newBuilder(endpoint).method("HEAD", HttpRequest.BodyPublishers.noBody()).build());
    }

    /** Creates an account using JWK authentication and retains its exact KID. */
    public Response createAccount(URI endpoint, String payload) throws Exception {
        Response response = jwk(endpoint, payload);
        accountKid = response.header("Location").orElseThrow();
        return response;
    }

    /** Sends one JWK-authenticated ACME request. */
    public Response jwk(URI endpoint, String payload) throws Exception {
        return post(endpoint, flattened(endpoint, payload.getBytes(StandardCharsets.UTF_8), accountKey,
                Optional.of(jwk(accountKey)), Optional.empty(), true));
    }

    /** Sends one KID-authenticated ACME request. */
    public Response kid(URI endpoint, String payload) throws Exception {
        if (accountKid == null) throw new IllegalStateException("ACME account has not been created");
        return post(endpoint, flattened(endpoint, payload.getBytes(StandardCharsets.UTF_8), accountKey,
                Optional.empty(), Optional.of(accountKid), true));
    }

    /** Performs strict nested-JWS account-key rollover and adopts the replacement key. */
    public Response rollover(URI endpoint, KeyPair replacement) throws Exception {
        String innerClaims = "{\"account\":\"" + accountKid + "\",\"oldKey\":" + jwk(accountKey) + "}";
        byte[] inner = flattened(endpoint, innerClaims.getBytes(StandardCharsets.UTF_8), replacement,
                Optional.of(jwk(replacement)), Optional.empty(), false);
        Response response = post(endpoint, flattened(endpoint, inner, accountKey, Optional.empty(),
                Optional.of(accountKid), true));
        if (response.status() >= 200 && response.status() < 300) accountKey = replacement;
        return response;
    }

    /** Sends an authenticated POST-as-GET request. */
    public Response postAsGet(URI endpoint) throws Exception { return kid(endpoint, ""); }

    /** Returns the current exact account KID. */
    public String accountKid() { return accountKid; }

    /** Adopts an existing account URL for restart and superseded-key checks. */
    public void useAccount(String kid) {
        if (kid == null || !kid.startsWith("https://")) {
            throw new IllegalArgumentException("ACME account KID is invalid");
        }
        accountKid = kid;
    }

    /** Returns the current replay nonce, if one has been received. */
    public Optional<String> replayNonce() { return Optional.ofNullable(nonce); }

    /** Returns the RFC 8555 key authorization for one challenge token. */
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

    /** Constructs the strict nested HS256 EAB JWS used by the deterministic test provider. */
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

    /** Extracts a required text property from a strict JSON response. */
    public static String text(Response response, String field) {
        PkiOperationValue value = response.json().fields().get(field);
        if (value instanceof PkiOperationValue.Text text) return text.value();
        throw new IllegalArgumentException("Missing ACME response field: " + field);
    }

    /** Extracts a required list of text values from a strict JSON response. */
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

    /** Extracts one challenge object from an authorization response. */
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

    @Override public void close() { nonce = null; accountKid = null; }

    /** Immutable bounded HTTP response captured by the test client. */
    public record Response(int status, Map<String, List<String>> headers, byte[] body) {
        /** Defensively snapshots response data. */
        public Response { headers = Map.copyOf(headers); body = body.clone(); }
        @Override public byte[] body() { return body.clone(); }
        /** Returns one header without relying on implementation-specific casing. */
        public Optional<String> header(String name) {
            return headers.entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase(name))
                    .flatMap(entry -> entry.getValue().stream()).findFirst();
        }
        /** Decodes a strict JSON object response. */
        public PkiOperationValue.ObjectValue json() {
            PkiOperationValue value = StrictJson.parse(body, MAXIMUM_RESPONSE);
            if (value instanceof PkiOperationValue.ObjectValue object) return object;
            throw new IllegalArgumentException("ACME response is not an object");
        }
        /** Returns the UTF-8 response body for safe assertions. */
        public String bodyText() { return new String(body, StandardCharsets.UTF_8); }
    }

    /** One challenge URL selected from an authorization resource. */
    public record Challenge(URI url) { }
}
