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
package zeroecho.pki.impl.secrets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import tools.jackson.core.JsonGenerator;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.json.JsonFactory;

import zeroecho.core.KeyUsage;
import zeroecho.core.context.KemContext;
import zeroecho.sdk.Pbkdf2Limits;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.sdk.builders.alg.AesDataContentBuilder;
import zeroecho.sdk.content.builtin.PlainBytes;
import zeroecho.sdk.guard.MultiRecipientContent;
import zeroecho.sdk.guard.MultiRecipientDataSourceBuilder;
import zeroecho.sdk.guard.UnlockMaterial;

/**
 * Encrypted publisher secrets store.
 *
 * <p>Secrets are serialised as a flat UTF-8 JSON object and encrypted inside a
 * ZeroEcho multi-recipient AES-256-GCM envelope. The outer file is also JSON
 * and carries the protection profile and optional BIKE-256 public key as
 * plaintext metadata so that decryption can proceed without additional context.</p>
 *
 * <h2>File format</h2>
 * <pre>{@code
 * {
 *   "version": 1,
 *   "protection": "HYBRID",
 *   "bikePublicKey": "<base64-X.509-DER>",
 *   "encryptedSecrets": "<base64-ZeroEcho-envelope>"
 * }
 * }</pre>
 *
 * <p>Configuration values and secret values must never appear in log output.</p>
 *
 * <p>Password recipients use PBKDF2-HMAC-SHA256 with 600,000 iterations.
 * Both creation and password-based opening enforce that upper bound; decoded iteration counts
 * must also satisfy the library's PBKDF2 minimum.</p>
 */
public final class PublisherSecretsStore {
    private static final String ENCRYPTED_SECRETS = "encryptedSecrets";
    private static final int FORMAT_VERSION = 1;
    private static final int PASSWORD_ITERATIONS = 600_000;
    private static final Pbkdf2Limits PASSWORD_LIMITS =
            new Pbkdf2Limits(PASSWORD_ITERATIONS, PASSWORD_ITERATIONS);

    private PublisherSecretsStore() {}

    /**
     * Creates or replaces the secrets store at the given path.
     * The write truncates an existing file and is not atomic or crash-durable.
     * Callers requiring transactional replacement must write a separate file
     * and arrange a durable replacement themselves. Access permissions are
     * managed by the caller and the filesystem; this method does not tighten them.
     *
     * @param storePath  destination file (created if absent, truncated if present)
     * @param protection encryption protection profile
     * @param secrets    secret identifier to secret value map (values must not be logged)
     * @param password   passphrase for CLASSIC and HYBRID recipients; may be {@code null} for PQC
     * @param bikePub    BIKE-256 public key for PQC and HYBRID recipients; may be {@code null} for CLASSIC
     * @throws IOException if serialization or writing the store fails
     * @throws GeneralSecurityException if protection or recipient-key processing fails
     */
    public static void create(Path storePath, PublisherSecretsProtection protection,
            Map<String, String> secrets, char[] password, PublicKey bikePub)
            throws IOException, GeneralSecurityException {
        validateArgs(protection, password, bikePub);
        byte[] plaintext = serializeSecrets(secrets);
        byte[] ciphertext = encrypt(protection, plaintext, password, bikePub);
        writeTo(storePath, protection, bikePub, ciphertext);
    }

    /**
     * Opens and decrypts the secrets store.
     *
     * @param storePath path to the store file
     * @param material  {@link UnlockMaterial.Password} for CLASSIC or HYBRID;
     *                  {@link UnlockMaterial.Private} with the BIKE private key for PQC or HYBRID
     * @return immutable map of secret identifier to secret value
     * @throws IOException if reading or parsing the store fails
     * @throws GeneralSecurityException if the material cannot unlock the store or decryption fails
     */
    public static Map<String, String> open(Path storePath, UnlockMaterial material)
            throws IOException, GeneralSecurityException {
        byte[] file = Files.readAllBytes(storePath);
        byte[] ciphertext = readEncryptedSecrets(file);
        byte[] plaintext = decrypt(ciphertext, material);
        return parseSecrets(plaintext);
    }

    // --- encryption/decryption ---

    private static byte[] encrypt(PublisherSecretsProtection protection, byte[] plaintext,
            char[] password, PublicKey bikePub) throws IOException, GeneralSecurityException {
        ZeroEchoSession session = new ZeroEchoSession().withPbkdf2Limits(PASSWORD_LIMITS);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)) {
            builder.payloadKeyBytes(32)
                   .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader());
            if (protection == PublisherSecretsProtection.CLASSIC
                    || protection == PublisherSecretsProtection.HYBRID) {
                builder.addPasswordRecipient(password, PASSWORD_ITERATIONS, 32, 32);
            }
            if (protection == PublisherSecretsProtection.PQC
                    || protection == PublisherSecretsProtection.HYBRID) {
                KemContext kem = session.createContext("BIKE", KeyUsage.ENCAPSULATE, bikePub); // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
                builder.addRecipient(kem, 32, 32);
            }
            MultiRecipientContent content = builder.build(true); // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
            content.setInput(new PlainBytes(plaintext));
            try (InputStream enc = content.getStream()) {
                enc.transferTo(buf);
            }
        }
        return buf.toByteArray();
    }

    private static byte[] decrypt(byte[] ciphertext, UnlockMaterial material)
            throws IOException, GeneralSecurityException {
        ZeroEchoSession session = new ZeroEchoSession().withPbkdf2Limits(PASSWORD_LIMITS);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (MultiRecipientDataSourceBuilder builder = MultiRecipientDataSourceBuilder.builder(session)) {
            builder.payloadKeyBytes(32)
                   .withAes(AesDataContentBuilder.builder(session).modeGcm(128).withHeader())
                   .unlockWith(material);
            MultiRecipientContent content = builder.build(false); // NOPMD CloseResource - Ownership is transferred to the enclosing lifecycle and its explicit close/stream completion; not a local resource.
            content.setInput(new PlainBytes(ciphertext));
            try (InputStream dec = content.getStream()) {
                dec.transferTo(buf);
            }
        }
        return buf.toByteArray();
    }

    // --- JSON serialization ---

    private static byte[] serializeSecrets(Map<String, String> secrets) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (JsonGenerator gen = new JsonFactory().createGenerator(buf)) {
            gen.writeStartObject();
            for (Map.Entry<String, String> entry : secrets.entrySet()) {
                gen.writeStringProperty(entry.getKey(), entry.getValue());
            }
            gen.writeEndObject();
        }
        return buf.toByteArray();
    }

    private static Map<String, String> parseSecrets(byte[] json) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        try (JsonParser parser = new JsonFactory().createParser(json)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("Invalid secrets payload: expected JSON object");
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String key = parser.currentName();
                if (parser.nextToken() != JsonToken.VALUE_STRING) {
                    throw new IOException("Invalid secrets payload: expected string value for key: " + key);
                }
                result.put(key, parser.getText());
            }
        }
        return Map.copyOf(result);
    }

    private static void writeTo(Path storePath, PublisherSecretsProtection protection,
            PublicKey bikePub, byte[] ciphertext) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (JsonGenerator gen = new JsonFactory().createGenerator(buf)) {
            gen.writeStartObject();
            gen.writeNumberProperty("version", FORMAT_VERSION);
            gen.writeStringProperty("protection", protection.name());
            if (bikePub != null) {
                gen.writeStringProperty("bikePublicKey",
                        Base64.getEncoder().encodeToString(bikePub.getEncoded()));
            }
            gen.writeStringProperty(ENCRYPTED_SECRETS,
                    Base64.getEncoder().encodeToString(ciphertext));
            gen.writeEndObject();
        }
        Files.write(storePath, buf.toByteArray());
    }

    private static byte[] readEncryptedSecrets(byte[] file) throws IOException {
        try (JsonParser parser = new JsonFactory().createParser(file)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("Invalid store file format: expected JSON object");
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String name = parser.currentName();
                parser.nextToken();
                if (ENCRYPTED_SECRETS.equals(name)) {
                    return Base64.getDecoder().decode(parser.getText());
                }
                // Skip other scalar fields; no nested objects in this format.
            }
        }
        throw new IOException("Invalid store file: missing encryptedSecrets field");
    }

    private static void validateArgs(PublisherSecretsProtection protection,
            char[] password, PublicKey bikePub) {
        if ((protection == PublisherSecretsProtection.CLASSIC
                || protection == PublisherSecretsProtection.HYBRID) && password == null) {
            throw new IllegalArgumentException(
                    "Password required for " + protection + " protection");
        }
        if ((protection == PublisherSecretsProtection.PQC
                || protection == PublisherSecretsProtection.HYBRID) && bikePub == null) {
            throw new IllegalArgumentException(
                    "BIKE public key required for " + protection + " protection");
        }
    }
}
