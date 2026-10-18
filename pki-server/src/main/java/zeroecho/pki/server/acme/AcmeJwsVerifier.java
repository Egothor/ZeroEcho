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

import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/** Strict narrow ACME flattened-JWS verifier supporting only ES256. */
@SuppressWarnings("PMD")
public final class AcmeJwsVerifier {
    /** Creates a stateless strict ACME JWS verifier. */
    public AcmeJwsVerifier() {
        // Stateless.
    }

    /** Required protected-header account-key mode. */
    public enum KeyMode {
        /** Protected header carries a new-account JSON Web Key. */ JWK,
        /** Protected header carries an existing-account key identifier. */ KID
    }

    /**
     * Resolved durable account public key with exact revision commitment.
     *
     * @param accountId stable account identifier
     * @param kid exact account key identifier
     * @param keyThumbprint SHA-256 account-key thumbprint
     * @param publicKey verified account public key
     * @param recordCommitment expected durable account-record commitment
     */
    public record AccountKey(String accountId, String kid, String keyThumbprint,
            PublicKey publicKey, String recordCommitment) {
        /** Validates finite account authority metadata. */
        public AccountKey {
            requireId(accountId); Objects.requireNonNull(kid, "kid"); digest(keyThumbprint);
            Objects.requireNonNull(publicKey, "publicKey"); digest(recordCommitment);
        }
    }

    /** Account lookup used only after strict KID framing. */
    @FunctionalInterface
    public interface AccountKeyResolver {
        /**
         * Resolves one exact KID or fails without revealing another account.
         *
         * @param kid exact account key identifier
         * @return resolved account key and record commitment
         */
        AccountKey resolve(String kid);
    }

    /**
     * Verified JWS data safe to pass to one closed endpoint decoder.
     *
     * @param payload verified endpoint payload
     * @param keyThumbprint authenticated signing-key thumbprint
     * @param account resolved account for KID mode
     * @param publicKey authenticated signing public key
     */
    public record Verified(byte[] payload, String keyThumbprint, Optional<AccountKey> account,
            PublicKey publicKey) {
        /** Defensively snapshots verified payload. */
        public Verified {
            payload = Objects.requireNonNull(payload, "payload").clone(); digest(keyThumbprint);
            account = Objects.requireNonNull(account, "account"); Objects.requireNonNull(publicKey, "publicKey");
        }
        /**
         * Returns the verified endpoint payload.
         *
         * @return defensive copy of payload bytes
         */
        @Override public byte[] payload() { return payload.clone(); }
    }

    private static final Base64.Decoder URL_DECODER = Base64.getUrlDecoder();

    /**
     * Extracts a strictly framed KID only as a routing hint before full JWS verification.
     * The returned value grants no authority and must be resolved and authenticated by
     * {@link #verify(byte[], int, URI, String, KeyMode, AcmeNonceService, AccountKeyResolver)}.
     *
     * @param document flattened JWS document
     * @param maximumDocumentBytes positive encoded-document bound in bytes
     * @param expectedUrl exact externally visible endpoint URL
     * @return untrusted KID routing hint
     */
    public String kidRoutingHint(byte[] document, int maximumDocumentBytes, URI expectedUrl) {
        Objects.requireNonNull(expectedUrl, "expectedUrl");
        Flattened flattened = parseFlattened(document, maximumDocumentBytes);
        byte[] protectedBytes = decodeCanonical(flattened.protectedValue(), 16_384);
        try {
            PkiOperationValue.ObjectValue header = object(StrictJson.parse(protectedBytes, 16_384));
            Map<String, PkiOperationValue> fields = header.fields();
            if (!fields.keySet().equals(SetHolder.KID_PROTECTED)
                    || !"ES256".equals(text(fields, "alg"))
                    || !expectedUrl.toASCIIString().equals(text(fields, "url"))) {
                throw malformed("ACME protected header is invalid");
            }
            return text(fields, "kid");
        } finally {
            java.util.Arrays.fill(protectedBytes, (byte) 0);
        }
    }

    /**
     * Verifies one complete flattened JWS against the exact configured external URL.
     * The admitted replay nonce is consumed before signature verification.
     *
     * @param document flattened JWS document
     * @param maximumDocumentBytes positive encoded-document bound in bytes
     * @param expectedUrl exact externally visible endpoint URL
     * @param nonceScope canonical directory nonce scope
     * @param keyMode required protected-header key mode
     * @param nonces one-use replay-nonce service
     * @param accounts exact account-key resolver
     * @return verified payload and signing authority
     */
    public Verified verify(byte[] document, int maximumDocumentBytes, URI expectedUrl,
            String nonceScope, KeyMode keyMode, AcmeNonceService nonces,
            AccountKeyResolver accounts) {
        Objects.requireNonNull(expectedUrl, "expectedUrl"); requireId(nonceScope);
        Objects.requireNonNull(keyMode, "keyMode"); Objects.requireNonNull(nonces, "nonces");
        Objects.requireNonNull(accounts, "accounts");
        Flattened flattened = parseFlattened(document, maximumDocumentBytes);
        byte[] protectedBytes = decodeCanonical(flattened.protectedValue(), 16_384);
        PkiOperationValue.ObjectValue header = object(StrictJson.parse(protectedBytes, 16_384));
        Map<String, PkiOperationValue> fields = header.fields();
        if (!fields.keySet().stream().allMatch(SetHolder.PROTECTED::contains)
                || !"ES256".equals(text(fields, "alg"))
                || !expectedUrl.toASCIIString().equals(text(fields, "url"))) {
            throw malformed("ACME protected header is invalid");
        }
        String nonce = text(fields, "nonce");
        if (!nonces.consume(nonce, nonceScope)) throw new AcmeProblem("badNonce");

        Optional<AccountKey> account = Optional.empty();
        PublicKey key;
        String thumbprint;
        if (keyMode == KeyMode.JWK) {
            if (!fields.keySet().equals(SetHolder.JWK_PROTECTED)) throw malformed("ACME JWK header is invalid");
            Jwk jwk = jwk(object(fields.get("jwk")));
            key = jwk.key(); thumbprint = jwk.thumbprint();
        } else {
            if (!fields.keySet().equals(SetHolder.KID_PROTECTED)) throw malformed("ACME KID header is invalid");
            AccountKey resolved = accounts.resolve(text(fields, "kid"));
            account = Optional.of(resolved); key = resolved.publicKey(); thumbprint = resolved.keyThumbprint();
        }
        byte[] payload = decodeCanonical(flattened.payload(), maximumDocumentBytes);
        verifySignature(flattened, key);
        return new Verified(payload, thumbprint, account, key);
    }

    /**
     * Verifies the RFC key-change inner JWS signed by the replacement key.
     *
     * @param document flattened inner JWS document
     * @param maximumDocumentBytes positive encoded-document bound in bytes
     * @param expectedUrl exact externally visible key-change URL
     * @param expectedAccountKid exact existing-account KID
     * @param oldKeyThumbprint authenticated old account-key thumbprint
     * @return verified payload and replacement-key authority
     */
    public Verified verifyKeyChange(byte[] document, int maximumDocumentBytes, URI expectedUrl,
            String expectedAccountKid, String oldKeyThumbprint) {
        Objects.requireNonNull(expectedUrl, "expectedUrl");
        Objects.requireNonNull(expectedAccountKid, "expectedAccountKid"); digest(oldKeyThumbprint);
        Flattened flattened = parseFlattened(document, maximumDocumentBytes);
        PkiOperationValue.ObjectValue header = object(StrictJson.parse(
                decodeCanonical(flattened.protectedValue(), 16_384), 16_384));
        if (!header.fields().keySet().equals(SetHolder.INNER_PROTECTED)
                || !"ES256".equals(text(header.fields(), "alg"))
                || !expectedUrl.toASCIIString().equals(text(header.fields(), "url"))) {
            throw malformed("ACME key-change header is invalid");
        }
        Jwk replacement = jwk(object(header.fields().get("jwk")));
        byte[] payload = decodeCanonical(flattened.payload(), maximumDocumentBytes);
        PkiOperationValue.ObjectValue claims = object(StrictJson.parse(payload, 65_536));
        if (!claims.fields().keySet().equals(SetHolder.INNER_PAYLOAD)
                || !expectedAccountKid.equals(text(claims.fields(), "account"))
                || !oldKeyThumbprint.equals(jwk(object(claims.fields().get("oldKey"))).thumbprint())
                || replacement.thumbprint().equals(oldKeyThumbprint)) {
            throw new AcmeProblem("unauthorized");
        }
        verifySignature(flattened, replacement.key());
        return new Verified(payload, replacement.thumbprint(), Optional.empty(), replacement.key());
    }

    private static void verifySignature(Flattened flattened, PublicKey key) {
        byte[] signature = decodeCanonical(flattened.signature(), 64);
        if (signature.length != 64) throw new AcmeProblem("malformed");
        byte[] signingInput = (flattened.protectedValue() + "." + flattened.payload())
                .getBytes(StandardCharsets.US_ASCII);
        try {
            Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
            verifier.initVerify(key); verifier.update(signingInput);
            if (!verifier.verify(signature)) throw new AcmeProblem("unauthorized");
        } catch (AcmeProblem failure) {
            throw failure;
        } catch (Exception failure) {
            throw new AcmeProblem("serverInternal");
        } finally {
            java.util.Arrays.fill(signature, (byte) 0);
        }
    }

    /** Safe finite protocol failure, never carrying provider or parser details. */
    public static final class AcmeProblem extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        /** Stable RFC-style problem suffix. */
        private final String type;
        /**
         * Creates a safe ACME problem classification.
         *
         * @param type stable RFC-style problem suffix
         */
        public AcmeProblem(String type) { super("ACME request rejected"); this.type = type; }
        /**
         * Returns the safe problem classification.
         *
         * @return stable RFC-style problem suffix
         */
        public String type() { return type; }
    }

    private static Flattened parseFlattened(byte[] document, int maximum) {
        if (document == null || document.length == 0 || maximum < 1
                || maximum > StrictJson.MAXIMUM_DOCUMENT_BYTES || document.length > maximum) {
            throw malformed("ACME JWS framing is invalid");
        }
        JsonFactory factory = factory(maximum);
        try (JsonParser parser = factory.createParser(ObjectReadContext.empty(), document, 0, document.length)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) throw malformed("ACME JWS framing is invalid");
            String protectedValue = null; String payload = null; String signature = null;
            int count = 0;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.PROPERTY_NAME || ++count > 3) throw malformed("ACME JWS framing is invalid");
                String name = parser.currentName();
                if (parser.nextToken() != JsonToken.VALUE_STRING) throw malformed("ACME JWS field type is invalid");
                String value = parser.getString();
                switch (name) {
                    case "protected" -> protectedValue = once(protectedValue, value);
                    case "payload" -> payload = once(payload, value);
                    case "signature" -> signature = once(signature, value);
                    default -> throw malformed("Unknown ACME JWS field");
                }
            }
            if (parser.nextToken() != null || protectedValue == null || payload == null || signature == null) {
                throw malformed("ACME JWS is incomplete");
            }
            return new Flattened(protectedValue, payload, signature);
        } catch (AcmeProblem failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw malformed("ACME JWS cannot be decoded");
        }
    }

    private static JsonFactory factory(int maximum) {
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(2)
                .maxDocumentLength(maximum).maxTokenCount(16).maxNumberLength(4)
                .maxStringLength(maximum).maxNameLength(16).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) builder.disable(feature);
        return builder.build();
    }

    private static Jwk jwk(PkiOperationValue.ObjectValue value) {
        Map<String, PkiOperationValue> fields = value.fields();
        if (!fields.keySet().equals(SetHolder.JWK_FIELDS)
                || !"EC".equals(text(fields, "kty")) || !"P-256".equals(text(fields, "crv"))) {
            throw malformed("ACME account JWK is invalid");
        }
        byte[] x = decodeCanonical(text(fields, "x"), 32);
        byte[] y = decodeCanonical(text(fields, "y"), 32);
        if (x.length != 32 || y.length != 32) throw malformed("ACME account JWK coordinate is invalid");
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            PublicKey key = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
            String canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""
                    + text(fields, "x") + "\",\"y\":\"" + text(fields, "y") + "\"}";
            return new Jwk(key, sha256(canonical.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception failure) {
            throw malformed("ACME account JWK is invalid");
        } finally {
            java.util.Arrays.fill(x, (byte) 0); java.util.Arrays.fill(y, (byte) 0);
        }
    }

    private static byte[] decodeCanonical(String value, int maximumDecoded) {
        if (value == null || value.indexOf('=') >= 0 || !value.matches("[A-Za-z0-9_-]*")) {
            throw malformed("ACME Base64url value is invalid");
        }
        try {
            byte[] decoded = URL_DECODER.decode(value);
            if (decoded.length > maximumDecoded
                    || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) {
                throw malformed("ACME Base64url value is not canonical");
            }
            return decoded;
        } catch (IllegalArgumentException failure) {
            if (failure instanceof AcmeProblem problem) throw problem;
            throw malformed("ACME Base64url value is invalid");
        }
    }

    private static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ObjectValue object) return object;
        throw malformed("ACME JSON object is required");
    }
    private static String text(Map<String, PkiOperationValue> fields, String name) {
        if (fields.get(name) instanceof PkiOperationValue.Text text) return text.value();
        throw malformed("ACME protected field is missing");
    }
    private static String once(String previous, String value) {
        if (previous != null) throw malformed("Duplicate ACME JWS field");
        return value;
    }
    private static void requireId(String value) {
        if (value == null || !value.matches("[a-z0-9][a-z0-9._:-]{0,127}")) throw malformed("ACME identity is invalid");
    }
    private static void digest(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw malformed("ACME commitment is invalid");
    }
    private static String sha256(byte[] value) {
        try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static AcmeProblem malformed(String ignored) { return new AcmeProblem("malformed"); }

    private record Flattened(String protectedValue, String payload, String signature) { }
    private record Jwk(PublicKey key, String thumbprint) { }
    private static final class SetHolder {
        private static final java.util.Set<String> PROTECTED = java.util.Set.of("alg", "nonce", "url", "jwk", "kid");
        private static final java.util.Set<String> JWK_PROTECTED = java.util.Set.of("alg", "nonce", "url", "jwk");
        private static final java.util.Set<String> KID_PROTECTED = java.util.Set.of("alg", "nonce", "url", "kid");
        private static final java.util.Set<String> INNER_PROTECTED = java.util.Set.of("alg", "url", "jwk");
        private static final java.util.Set<String> INNER_PAYLOAD = java.util.Set.of("account", "oldKey");
        private static final java.util.Set<String> JWK_FIELDS = java.util.Set.of("kty", "crv", "x", "y");
        private SetHolder() { }
    }
}
