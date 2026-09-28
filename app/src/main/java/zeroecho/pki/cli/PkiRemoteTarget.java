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

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/**
 * Validated mutual-TLS connection target for remote execution against a running
 * {@code pki-server} admin API.
 *
 * <p>Remote mode is selected purely by parameters: supplying a base URL together
 * with client-connection certificate material selects remote mode; otherwise the
 * CLI runs its existing local in-process mode. The client presents its TLS client
 * certificate directly (auth mode {@code DIRECT_MTLS}); no forwarded-identity
 * headers are used.</p>
 *
 * @param baseUri validated {@code https} base URL
 * @param clientKeystore PKCS#12 holding the client certificate and private key
 * @param clientKeystorePasswordEnv environment variable holding the keystore password
 * @param clientCertificate PEM client certificate chain (alternative to a keystore)
 * @param clientKey PEM PKCS#8 private key (alternative to a keystore)
 * @param trustStore PKCS#12 or PEM bundle of CAs that verify the server certificate
 * @param trustStorePasswordEnv environment variable holding the truststore password
 */
record PkiRemoteTarget(URI baseUri, Optional<Path> clientKeystore, Optional<String> clientKeystorePasswordEnv,
        Optional<Path> clientCertificate, Optional<Path> clientKey, Optional<Path> trustStore,
        Optional<String> trustStorePasswordEnv) {

    /** Validates the closed connection target. */
    PkiRemoteTarget {
        Objects.requireNonNull(baseUri, "baseUri");
        Objects.requireNonNull(clientKeystore, "clientKeystore");
        Objects.requireNonNull(clientKeystorePasswordEnv, "clientKeystorePasswordEnv");
        Objects.requireNonNull(clientCertificate, "clientCertificate");
        Objects.requireNonNull(clientKey, "clientKey");
        Objects.requireNonNull(trustStore, "trustStore");
        Objects.requireNonNull(trustStorePasswordEnv, "trustStorePasswordEnv");
        if (!"https".equalsIgnoreCase(baseUri.getScheme()) || baseUri.getHost() == null) {
            throw new IllegalArgumentException("Remote base URL must be an absolute https URL");
        }
        if (clientKeystorePasswordEnv.isPresent() && clientKeystore.isEmpty()
                || trustStorePasswordEnv.isPresent() && trustStore.isEmpty()) {
            throw new IllegalArgumentException("Password environment option requires its corresponding store");
        }
        boolean keystore = clientKeystore.isPresent();
        boolean pem = clientCertificate.isPresent() && clientKey.isPresent();
        if (keystore == pem) {
            throw new IllegalArgumentException(
                    "Remote mode requires either --client-keystore or a --client-cert/--client-key PEM pair");
        }
        if (clientCertificate.isPresent() != clientKey.isPresent()) {
            throw new IllegalArgumentException("--client-cert and --client-key must be supplied together");
        }
    }

    /** @return {@code true} when the client identity is a PEM certificate and key pair */
    /* default */ boolean usesPemClientIdentity() {
        return clientCertificate.isPresent();
    }

    /**
     * Parses and validates a remote target from the raw option values, applying the
     * documented mode-selection rule.
     *
     * @param url base URL value, {@code null} when {@code --url} is absent
     * @param clientKeystore keystore path value or {@code null}
     * @param clientKeystorePasswordEnv keystore password environment name or {@code null}
     * @param clientCertificate PEM certificate path value or {@code null}
     * @param clientKey PEM key path value or {@code null}
     * @param trustStore truststore path value or {@code null}
     * @param trustStorePasswordEnv truststore password environment name or {@code null}
     * @return the validated target
     * @throws IllegalArgumentException when the URL is malformed or the option combination is invalid
     */
    /* default */ static PkiRemoteTarget parse(String url, String clientKeystore, String clientKeystorePasswordEnv,
            String clientCertificate, String clientKey, String trustStore, String trustStorePasswordEnv) {
        URI baseUri = parseUri(Objects.requireNonNull(url, "url"));
        return new PkiRemoteTarget(baseUri, optionalPath(clientKeystore), optionalText(clientKeystorePasswordEnv),
                optionalPath(clientCertificate), optionalPath(clientKey), optionalPath(trustStore),
                optionalText(trustStorePasswordEnv));
    }

    // URISyntaxException diagnostics repeat the raw URL, which may contain user-info or query secrets.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static URI parseUri(String url) {
        try {
            return new URI(url);
        } catch (URISyntaxException invalid) {
            throw new IllegalArgumentException("Remote base URL is invalid");
        }
    }

    private static Optional<Path> optionalPath(String value) {
        return value == null ? Optional.empty() : Optional.of(Path.of(value));
    }

    private static Optional<String> optionalText(String value) {
        return Optional.ofNullable(value);
    }
}
