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
package zeroecho.pki.server.http;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import zeroecho.pki.server.spi.PkiServerTlsProvider;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Production JSSE provider using externally protected PKCS#12 identity and trust
 * stores.
 *
 * <p>Configuration contains only store paths and names of environment variables.
 * Passwords are resolved into short-lived character arrays, cleared after JSSE
 * initialization, and never returned or logged.</p>
 */
@SuppressWarnings("PMD")
public final class Pkcs12TlsProvider implements PkiServerTlsProvider {
    /** Stable explicit provider identity. */
    public static final String ID = "jsse-pkcs12";
    private static final Set<String> KEYS = Set.of("keyStore", "keyStorePasswordEnvironment",
            "trustStore", "trustStorePasswordEnvironment");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public SSLContext create(ProviderConfig configuration) throws Exception {
        ProviderConfig exact = Objects.requireNonNull(configuration, "configuration");
        if (!ID.equals(exact.backendId()) || !exact.properties().keySet().equals(KEYS)) {
            throw new IllegalArgumentException("TLS provider configuration is invalid");
        }
        Path keyStorePath = path(exact.require("keyStore"));
        Path trustStorePath = path(exact.require("trustStore"));
        char[] keyPassword = secret(exact.require("keyStorePasswordEnvironment"));
        char[] trustPassword = secret(exact.require("trustStorePasswordEnvironment"));
        try {
            KeyStore keyStore = load(keyStorePath, keyPassword);
            KeyStore trustStore = load(trustStorePath, trustPassword);
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(keyStore, keyPassword);
            TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trust.init(trustStore);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keys.getKeyManagers(), trust.getTrustManagers(), new SecureRandom());
            return context;
        } finally {
            Arrays.fill(keyPassword, '\0');
            Arrays.fill(trustPassword, '\0');
        }
    }

    private static KeyStore load(Path path, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(path)) {
            store.load(input, password);
        }
        return store;
    }

    private static Path path(String value) {
        Path result = Path.of(value).toAbsolutePath().normalize();
        if (result.getParent() == null || Files.isSymbolicLink(result)) {
            throw new IllegalArgumentException("TLS material path is invalid");
        }
        return result;
    }

    private static char[] secret(String environmentName) {
        if (!environmentName.matches("[A-Z][A-Z0-9_]{0,127}")) {
            throw new IllegalArgumentException("TLS secret reference is invalid");
        }
        String value = System.getenv(environmentName);
        if (value == null || value.isEmpty()) {
            throw new IllegalStateException("TLS material is unavailable");
        }
        return value.toCharArray();
    }
}
