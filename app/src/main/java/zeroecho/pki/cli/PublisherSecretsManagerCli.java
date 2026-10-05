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
package zeroecho.pki.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.json.JsonFactory;

import zeroecho.pki.impl.secrets.PublisherSecretsProtection;
import zeroecho.pki.impl.secrets.PublisherSecretsStore;
import zeroecho.sdk.guard.UnlockMaterial;
import zeroecho.sdk.util.BikeKeySupport;

/**
 * Operator tool for managing the publisher secrets store.
 *
 * <p>This is a deployment-only entry point separate from the main PKI CLI.
 * It is not part of the public CLI catalog and has no interactive interface.</p>
 *
 * <h2>Commands</h2>
 * <dl>
 *   <dt>{@code generate-bike-key --pub <path> --priv <path>}</dt>
 *   <dd>Generates a BIKE-256 key pair. Public key is written as X.509 DER;
 *       private key is written as PKCS#8 DER. Keep the private key on a secure,
 *       access-controlled storage (HSM or restricted filesystem).</dd>
 *
 *   <dt>{@code write-store --store <path> --secrets <json> --protection CLASSIC|PQC|HYBRID
 *       [--password-env VAR] [--bike-pub <path>]}</dt>
 *   <dd>Encrypts a plaintext secrets JSON file into the store.
 *       The secrets JSON must be a flat object: {@code {"id": "value", ...}}.
 *       The plaintext file must be kept on secure storage and deleted after
 *       the store is written.</dd>
 *
 *   <dt>{@code verify-store --store <path> [--password-env VAR] [--bike-priv <path>]}</dt>
 *   <dd>Decrypts the store and prints the secret identifiers (not values)
 *       as a verification check.</dd>
 * </dl>
 */
@SuppressWarnings("PMD")
public final class PublisherSecretsManagerCli {
    private static final String HELP = """
            Usage: zeroecho-pki-publisher-secrets <command> [options]

            Commands:
              generate-bike-key   Generate a BIKE-256 key pair
              write-store         Encrypt a secrets JSON file into the store
              verify-store        Verify the store and list secret identifiers

            generate-bike-key options:
              --pub <path>          Output path for X.509 DER public key
              --priv <path>         Output path for PKCS#8 DER private key

            write-store options:
              --store <path>        Path to the store file (created/replaced)
              --secrets <path>      Path to the plaintext secrets JSON file
              --protection <level>  CLASSIC | PQC | HYBRID
              --password-env <var>  Environment variable with the password (CLASSIC/HYBRID)
              --bike-pub <path>     Path to BIKE X.509 DER public key file (PQC/HYBRID)

            verify-store options:
              --store <path>        Path to the store file
              --password-env <var>  Environment variable with the password (CLASSIC/HYBRID)
              --bike-priv <path>    Path to BIKE PKCS#8 DER private key file (PQC)

            Secret reference formats for publisher configuration:
              keyring:<id>          Look up <id> in the publisher secrets store
              env:<VAR>             Read from environment variable VAR
              dev-plaintext:<val>   Use literal value (UNSAFE — development only)
            """;

    private PublisherSecretsManagerCli() {}

    /** Entry point for the publisher secrets manager.
     * @param arguments command name and command-specific options
     */
    public static void main(String[] arguments) {
        int result = run(arguments, System.out, System.err);
        if (result != 0) System.exit(result);
    }

    static int run(String[] arguments, PrintStream out, PrintStream err) {
        try {
            if (arguments.length == 0 || "--help".equals(arguments[0])) {
                out.print(HELP);
                return 0;
            }
            String command = arguments[0];
            String[] rest = Arrays.copyOfRange(arguments, 1, arguments.length);
            return switch (command) {
                case "generate-bike-key" -> generateBikeKey(rest, out, err);
                case "write-store" -> writeStore(rest, out, err);
                case "verify-store" -> verifyStore(rest, out, err);
                default -> {
                    err.println("Unknown command: " + command);
                    err.println("Run with --help for usage.");
                    yield 2;
                }
            };
        } catch (IllegalArgumentException e) {
            err.println("Invalid arguments: " + e.getMessage());
            return 2;
        } catch (IOException | GeneralSecurityException e) {
            err.println("Operation failed: " + e.getMessage());
            return 1;
        }
    }

    // --- generate-bike-key ---

    private static int generateBikeKey(String[] args, PrintStream out, PrintStream err)
            throws IOException, GeneralSecurityException {
        String pubPath = require(args, "--pub");
        String privPath = require(args, "--priv");
        KeyPair pair = BikeKeySupport.generateKeyPair();
        Files.write(Path.of(pubPath), pair.getPublic().getEncoded());
        Files.write(Path.of(privPath), pair.getPrivate().getEncoded());
        out.println("BIKE-256 key pair generated.");
        out.println("  Public key (X.509 DER): " + pubPath);
        out.println("  Private key (PKCS#8 DER): " + privPath);
        out.println("  WARNING: Keep the private key on secure, access-controlled storage.");
        return 0;
    }

    // --- write-store ---

    private static int writeStore(String[] args, PrintStream out, PrintStream err)
            throws IOException, GeneralSecurityException {
        String storePath = require(args, "--store");
        String secretsPath = require(args, "--secrets");
        String protectionStr = require(args, "--protection");
        PublisherSecretsProtection protection = parseProtection(protectionStr);

        char[] password = resolvePassword(args, "--password-env", protection,
                List.of(PublisherSecretsProtection.CLASSIC, PublisherSecretsProtection.HYBRID));
        PublicKey bikePub = resolvePublicKey(args, "--bike-pub", protection,
                List.of(PublisherSecretsProtection.PQC, PublisherSecretsProtection.HYBRID));

        Map<String, String> secrets = loadSecretsJson(Path.of(secretsPath));
        PublisherSecretsStore.create(Path.of(storePath), protection, secrets, password, bikePub);

        if (password != null) Arrays.fill(password, '\0');
        out.println("Publisher secrets store written: " + storePath);
        out.println("  Protection: " + protection);
        out.println("  Secret IDs: " + String.join(", ", secrets.keySet()));
        return 0;
    }

    // --- verify-store ---

    private static int verifyStore(String[] args, PrintStream out, PrintStream err)
            throws IOException, GeneralSecurityException {
        String storePath = require(args, "--store");

        UnlockMaterial material = resolveUnlockMaterial(args);
        Map<String, String> secrets = PublisherSecretsStore.open(Path.of(storePath), material);

        out.println("Store verified: " + storePath);
        out.println("  Secret IDs (" + secrets.size() + "):");
        for (String id : secrets.keySet()) {
            out.println("    - " + id);
        }
        return 0;
    }

    // --- argument parsing helpers ---

    private static String require(String[] args, String flag) {
        List<String> list = Arrays.asList(args);
        int idx = list.indexOf(flag);
        if (idx < 0 || idx + 1 >= list.size()) {
            throw new IllegalArgumentException("Missing required argument: " + flag);
        }
        return list.get(idx + 1);
    }

    private static String optional(String[] args, String flag) {
        List<String> list = Arrays.asList(args);
        int idx = list.indexOf(flag);
        if (idx < 0 || idx + 1 >= list.size()) return null;
        return list.get(idx + 1);
    }

    private static PublisherSecretsProtection parseProtection(String value) {
        try {
            return PublisherSecretsProtection.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Protection must be CLASSIC, PQC, or HYBRID; got: " + value);
        }
    }

    private static char[] resolvePassword(String[] args, String flag,
            PublisherSecretsProtection protection,
            List<PublisherSecretsProtection> required) throws IOException {
        if (!required.contains(protection)) return null;
        String envName = require(args, flag);
        String value = System.getenv(envName);
        if (value == null || value.isEmpty()) {
            throw new IOException(
                    "Password environment variable is not set or empty: " + envName);
        }
        return value.toCharArray();
    }

    private static PublicKey resolvePublicKey(String[] args, String flag,
            PublisherSecretsProtection protection,
            List<PublisherSecretsProtection> required) throws IOException, GeneralSecurityException {
        if (!required.contains(protection)) return null;
        String path = require(args, flag);
        byte[] der = Files.readAllBytes(Path.of(path));
        return BikeKeySupport.loadPublicKey(der);
    }

    private static UnlockMaterial resolveUnlockMaterial(String[] args)
            throws IOException, GeneralSecurityException {
        String passwordEnv = optional(args, "--password-env");
        String bikePrivPath = optional(args, "--bike-priv");
        if (passwordEnv != null) {
            String value = System.getenv(passwordEnv);
            if (value == null || value.isEmpty()) {
                throw new IOException(
                        "Password environment variable is not set or empty: " + passwordEnv);
            }
            return new UnlockMaterial.Password(value.toCharArray());
        }
        if (bikePrivPath != null) {
            byte[] der = Files.readAllBytes(Path.of(bikePrivPath));
            PrivateKey key = BikeKeySupport.loadPrivateKey(der);
            return new UnlockMaterial.Private(key);
        }
        throw new IllegalArgumentException(
                "verify-store requires --password-env or --bike-priv");
    }

    private static Map<String, String> loadSecretsJson(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        Map<String, String> result = new LinkedHashMap<>();
        try (JsonParser parser = new JsonFactory().createParser(bytes)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw new IOException("Secrets file must be a JSON object");
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String key = parser.currentName();
                if (parser.nextToken() != JsonToken.VALUE_STRING) {
                    throw new IOException(
                            "Secrets file values must be strings; invalid value for key: " + key);
                }
                result.put(key, parser.getText());
            }
        }
        return Map.copyOf(result);
    }
}
