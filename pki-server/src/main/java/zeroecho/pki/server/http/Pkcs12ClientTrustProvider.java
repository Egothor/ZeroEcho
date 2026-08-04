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
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import zeroecho.pki.server.spi.PkiServerClientTrustProvider;
import zeroecho.pki.spi.ProviderConfig;

/** External PKCS#12 trust-store provider for forwarded administrative clients. */
@SuppressWarnings("PMD")
public final class Pkcs12ClientTrustProvider implements PkiServerClientTrustProvider {
    /** Stable provider identity. */
    public static final String ID = "jsse-pkcs12-client-trust";
    private static final Set<String> KEYS = Set.of("trustStore", "trustStorePasswordEnvironment");

    @Override
    public String id() {
        return ID;
    }

    @Override
    public X509TrustManager create(ProviderConfig configuration) throws Exception {
        ProviderConfig exact = Objects.requireNonNull(configuration, "configuration");
        if (!ID.equals(exact.backendId()) || !exact.properties().keySet().equals(KEYS)) {
            throw new IllegalArgumentException("Administrative-client trust configuration is invalid");
        }
        Path path = Path.of(exact.require("trustStore")).toAbsolutePath().normalize();
        if (path.getParent() == null || Files.isSymbolicLink(path)) {
            throw new IllegalArgumentException("Administrative-client trust source is invalid");
        }
        String environment = exact.require("trustStorePasswordEnvironment");
        if (!environment.matches("[A-Z][A-Z0-9_]{0,127}")) {
            throw new IllegalArgumentException("Administrative-client trust secret reference is invalid");
        }
        String secret = System.getenv(environment);
        if (secret == null || secret.isEmpty()) {
            throw new IllegalStateException("Administrative-client trust material is unavailable");
        }
        char[] password = secret.toCharArray();
        try {
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(path)) {
                store.load(input, password);
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            factory.init(store);
            X509TrustManager result = null;
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager candidate) {
                    if (result != null) throw new IllegalStateException("Administrative-client trust is ambiguous");
                    result = candidate;
                }
            }
            if (result == null) throw new IllegalStateException("Administrative-client trust is unavailable");
            return result;
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
