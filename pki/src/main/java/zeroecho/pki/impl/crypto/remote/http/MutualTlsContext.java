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
package zeroecho.pki.impl.crypto.remote.http;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Objects;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Builds a mutually-authenticated {@link SSLContext} for the remote signing
 * transport from a PKCS#12 client-identity keystore and a PKCS#12 trust store
 * pinning the remote service's issuer.
 *
 * <p>The client identity authenticates this PKI to the remote signing service;
 * the trust store constrains which server the transport will talk to. Passwords
 * are cleared from working arrays after use and are never retained.</p>
 */
public final class MutualTlsContext {

    private MutualTlsContext() {
    }

    /**
     * Builds a client {@link SSLContext} that presents the configured client
     * identity and trusts only the configured anchors.
     *
     * @param keystore PKCS#12 file holding the client private key and chain
     * @param keystorePassword keystore and key password
     * @param truststore PKCS#12 file holding the trusted remote issuer(s)
     * @param truststorePassword trust-store password
     * @param protocol TLS protocol (for example {@code TLSv1.3})
     * @return an initialised client context
     * @throws IllegalArgumentException if any input is missing or unreadable
     */
    public static SSLContext fromPkcs12(Path keystore, char[] keystorePassword, Path truststore,
            char[] truststorePassword, String protocol) {
        Objects.requireNonNull(keystore, "keystore");
        Objects.requireNonNull(keystorePassword, "keystorePassword");
        Objects.requireNonNull(truststore, "truststore");
        Objects.requireNonNull(truststorePassword, "truststorePassword");
        Objects.requireNonNull(protocol, "protocol");
        try {
            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(load(keystore, keystorePassword), keystorePassword);
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(load(truststore, truststorePassword));
            SSLContext context = SSLContext.getInstance(protocol);
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            return context;
        } catch (java.security.GeneralSecurityException | java.io.IOException failure) {
            throw new IllegalArgumentException("Unable to build remote signing TLS context", failure);
        } finally {
            Arrays.fill(keystorePassword, '\0');
            Arrays.fill(truststorePassword, '\0');
        }
    }

    // Password is one mutable PKCS#12 secret buffer, not a variable argument sequence.
    @SuppressWarnings("PMD.UseVarargs")
    private static KeyStore load(Path pkcs12, char[] password)
            throws java.security.GeneralSecurityException, java.io.IOException {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream input = Files.newInputStream(pkcs12)) {
            store.load(input, password);
        }
        return store;
    }
}
