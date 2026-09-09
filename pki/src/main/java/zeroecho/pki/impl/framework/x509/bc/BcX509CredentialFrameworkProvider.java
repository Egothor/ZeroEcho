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
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Set;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialFrameworkProvider;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;

/**
 * ServiceLoader provider for the Bouncy Castle backed X.509 credential
 * framework.
 *
 * <p>
 * This provider exposes the internal X.509 framework implementation to the PKI
 * runtime through the {@link CredentialFrameworkProvider} SPI. It is
 * responsible for identifying the backend, advertising any provider-specific
 * configuration keys it supports, and allocating a new
 * {@link CredentialFramework} instance when selected by bootstrap or runtime
 * wiring logic.
 * </p>
 *
 * <p>
 * The allocated framework instance is {@link BcX509CredentialFramework} in its
 * default partially wired form. In that state, the framework provides X.509 CSR
 * parsing, proof-of-possession verification, and attribute mapping, while
 * issuance and status-object generation remain intentionally unsupported until
 * a caller supplies concrete backend components through the framework's
 * {@code wired(...)} methods.
 * </p>
 *
 * <h2>Service registration</h2>
 * <p>
 * This class is intended to be discovered through
 * {@link java.util.ServiceLoader} via the {@code CredentialFrameworkProvider}
 * SPI registration in {@code META-INF/services}.
 * </p>
 *
 * <h2>Configuration model</h2>
 * <p>
 * The current implementation does not consume any provider-specific
 * configuration keys beyond backend selection through
 * {@link ProviderConfig#backendId()}. Consequently, {@link #supportedKeys()}
 * returns an empty set and bootstrap will reject any
 * {@code zeroecho.pki.framework.*} configuration keys other than the backend
 * selector itself.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless and thread-safe.
 * </p>
 */
public final class BcX509CredentialFrameworkProvider implements CredentialFrameworkProvider {

    private static final Logger LOG = Logger.getLogger(BcX509CredentialFrameworkProvider.class.getName());

    /** Creates a provider that supplies the Bouncy Castle X.509 framework. */
    public BcX509CredentialFrameworkProvider() {
        // Stateless provider descriptor.
    }

    /**
     * Returns the stable provider identifier used to select this X.509 framework
     * backend.
     *
     * @return provider identifier {@code x509-bc}
     */
    @Override
    public String id() {
        return "x509-bc";
    }

    /**
     * Returns the provider-specific configuration keys supported by this provider.
     *
     * <p>
     * The current implementation does not define any provider-specific keys.
     * Backend selection is performed only through
     * {@link ProviderConfig#backendId()}.
     * </p>
     *
     * @return empty immutable set
     */
    @Override
    public Set<String> supportedKeys() {
        return Set.of();
    }

    /**
     * Validates configuration for the Bouncy Castle backed X.509 credential
     * framework provider.
     * 
     * <p>
     * This provider currently defines no provider-specific keys. Unknown keys are
     * ignored for forward compatibility and are reported only by name through JUL
     * warning output. The backend id must match {@link #id()}.
     * </p>
     * 
     * @param config provider configuration used to select this backend; must not be
     *               {@code null}
     * @throws IllegalArgumentException if the backend id does not match this
     *                                  provider identifier
     */
    @Override
    public void validateConfig(final ProviderConfig config) {
        CredentialFrameworkProvider.super.validateConfig(config);

        for (String key : config.properties().keySet()) {
            if (!supportedKeys().contains(key) && LOG.isLoggable(Level.WARNING)) {
                LOG.warning("Ignoring unknown credential framework configuration key: " + key);
            }
        }
    }

    /**
     * Allocates a new Bouncy Castle backed X.509 credential framework instance.
     *
     * <p>
     * The supplied configuration must target this provider by using a backend id
     * equal to {@link #id()}. The returned framework is a new
     * {@link BcX509CredentialFramework} instance in its default partially wired
     * form.
     * </p>
     *
     * @param config provider configuration used to select this backend; must not be
     *               {@code null}
     * @return newly allocated X.509 credential framework instance
     * @throws IllegalArgumentException if {@code config} is {@code null} or if its
     *                                  backend id does not match this provider
     *                                  identifier
     */
    @Override
    public CredentialFramework allocate(ProviderConfig config) {
        validateConfig(config);
        BcX509VerificationExecutor executor = new BcX509VerificationExecutor();
        X509AlgorithmResolver.Policy policy = (suite, direction) -> true;
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(executor),
                List.of(X509AuthoritySnapshot.bindExecutor(BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        zeroecho.core.spi.AlgorithmExecutionCapability.Direction.VERIFY, executor)),
                policy);
        return new BcX509CredentialFramework(authority, executor);
    }
}
