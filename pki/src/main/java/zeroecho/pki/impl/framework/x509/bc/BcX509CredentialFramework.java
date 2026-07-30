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

import java.util.Objects;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.spi.framework.CertificationRequestParser;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.FrameworkAttributeMapper;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;
import zeroecho.pki.spi.framework.StatusObjectGenerator;

/**
 * Bouncy Castle backed X.509 implementation of {@link CredentialFramework}.
 *
 * <p>
 * This class groups the X.509-specific framework components used by the PKI
 * runtime under the common {@link CredentialFramework} contract. It provides
 * the X.509 format identifier, CSR parsing, proof-of-possession verification,
 * status-object generation, and framework-specific attribute mapping. It does
 * not expose credential-minting backends.
 * </p>
 *
 * <p>
 * The default constructor provides parsing, proof verification, and attribute
 * mapping with an unsupported status generator. A {@code wired(...)} method can
 * supply status generation without exposing the privileged issuer backend.
 *
 * <p>
 * This split allows the runtime to use X.509 request parsing and proof-of-
 * possession verification independently from certificate issuance.
 * </p>
 *
 * <h2>Immutability and lifecycle</h2>
 * <p>
 * Instances of this class are immutable. The {@code wired(...)} methods do not
 * mutate the current instance; instead they create and return a new framework
 * instance sharing the existing parser and attribute-mapper components while
 * replacing the status generator.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This class is an orchestration and component-aggregation object; it does
 * not itself process private key material.</li>
 * <li>Credential issuance remains owned by proof-gated core services rather than
 * this framework facade.</li>
 * <li>The default instance intentionally fails fast for issuance and
 * status-object generation so that partially wired deployments do not silently
 * degrade into incomplete behavior.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is thread-safe provided that the injected framework components are
 * themselves thread-safe for the intended runtime model.
 * </p>
 */
public final class BcX509CredentialFramework implements CredentialFramework {

    /**
     * X.509 format identifier used by this framework.
     *
     * <p>
     * All framework instances of this class report the same format identifier,
     * regardless of their wiring mode.
     * </p>
     */
    public static final FormatId FORMAT_ID = new FormatId("x509");

    private final CertificationRequestParser requestParser;
    private final ProofOfPossessionVerifier popVerifier;
    private final StatusObjectGenerator status;
    private final FrameworkAttributeMapper attributeMapper;

    /**
     * Creates a partially wired X.509 framework instance with default components.
     *
     * <p>
     * The created instance supports:
     * </p>
     * <ul>
     * <li>X.509 PKCS#10 certification request parsing,</li>
     * <li>X.509 proof-of-possession verification,</li>
     * <li>X.509-specific framework attribute mapping.</li>
     * </ul>
     *
     * <p>
     * Status-object generation is intentionally left unsupported in this default
     * configuration and may be supplied explicitly through
     * {@link #wired(BcX509StatusObjectGenerator)}. Credential issuance is not exposed by the
     * framework facade.
     * </p>
     */
    public BcX509CredentialFramework() {
        this(new BcX509CertificationRequestParser(), new BcX509ProofOfPossessionVerifier(),
                new UnsupportedStatusObjectGenerator(), new BcX509FrameworkAttributeMapper());
    }

    /**
     * Creates a framework instance from explicitly supplied components.
     *
     * <p>
     * This constructor is private because external callers are expected to use the
     * public default constructor and then derive a status-wired instance through
     * the provided {@code wired(...)} methods.
     * </p>
     *
     * @param requestParser   certification request parser; must not be {@code null}
     * @param popVerifier     proof-of-possession verifier; must not be {@code null}
     * @param status          status-object generator; must not be {@code null}
     * @param attributeMapper framework-specific attribute mapper; must not be
     *                        {@code null}
     * @throws NullPointerException if any component argument is {@code null}
     */
    private BcX509CredentialFramework(CertificationRequestParser requestParser, ProofOfPossessionVerifier popVerifier,
            StatusObjectGenerator status, FrameworkAttributeMapper attributeMapper) {
        this.requestParser = Objects.requireNonNull(requestParser, "requestParser");
        this.popVerifier = Objects.requireNonNull(popVerifier, "popVerifier");
        this.status = Objects.requireNonNull(status, "status");
        this.attributeMapper = Objects.requireNonNull(attributeMapper, "attributeMapper");
    }

    /**
     * Creates a fully wired X.509 framework instance using the current parser,
     * proof-of-possession verifier and attribute mapper together with the supplied
     * status-object generator.
     *
     * <p>
     * The current instance is not modified. A new immutable framework instance is
     * returned.
     * </p>
     *
     * @param statusObjectGenerator concrete X.509 status-object generator; must not
     *                              be {@code null}
     * @return new fully wired framework instance
     * @throws NullPointerException if {@code statusObjectGenerator} is {@code null}
     */
    public BcX509CredentialFramework wired(BcX509StatusObjectGenerator statusObjectGenerator) {
        Objects.requireNonNull(statusObjectGenerator, "statusObjectGenerator");
        return new BcX509CredentialFramework(requestParser, popVerifier, statusObjectGenerator, attributeMapper);
    }

    /**
     * Creates a fully wired X.509 framework instance with an explicitly supplied
     * proof-of-possession verifier.
     *
     * <p>
     * This variant is intended for deployments that need to override the default
     * X.509 proof-of-possession verification behavior while keeping the existing
     * parser and framework attribute mapper.
     * </p>
     *
     * <p>
     * The current instance is not modified. A new immutable framework instance is
     * returned.
     * </p>
     *
     * @param statusObjectGenerator     concrete X.509 status-object generator; must
     *                                  not be {@code null}
     * @param proofOfPossessionVerifier explicit proof-of-possession verifier to use
     *                                  in the returned instance; must not be
     *                                  {@code null}
     * @return new fully wired framework instance using the supplied proof-of-
     *         possession verifier
     * @throws NullPointerException if any argument is {@code null}
     */
    public BcX509CredentialFramework wired(BcX509StatusObjectGenerator statusObjectGenerator,
            ProofOfPossessionVerifier proofOfPossessionVerifier) {
        Objects.requireNonNull(statusObjectGenerator, "statusObjectGenerator");
        Objects.requireNonNull(proofOfPossessionVerifier, "proofOfPossessionVerifier");
        return new BcX509CredentialFramework(requestParser, proofOfPossessionVerifier, statusObjectGenerator,
                attributeMapper);
    }

    /**
     * Returns the framework format identifier.
     *
     * @return the constant X.509 format identifier
     */
    @Override
    public FormatId formatId() {
        return FORMAT_ID;
    }

    /**
     * Returns the certification request parser used by this framework instance.
     *
     * @return certification request parser, never {@code null}
     */
    @Override
    public CertificationRequestParser requestParser() {
        return requestParser;
    }

    /**
     * Returns the proof-of-possession verifier used by this framework instance.
     *
     * @return proof-of-possession verifier, never {@code null}
     */
    @Override
    public ProofOfPossessionVerifier proofOfPossessionVerifier() {
        return popVerifier;
    }

    /**
     * Returns the status-object generator used by this framework instance.
     *
     * <p>
     * For a default partially wired instance, this may be an internal placeholder
     * generator that fails explicitly with {@link UnsupportedOperationException}.
     * </p>
     *
     * @return status-object generator, never {@code null}
     */
    @Override
    public StatusObjectGenerator statusObjectGenerator() {
        return status;
    }

    /**
     * Returns the framework-specific attribute mapper used by this framework
     * instance.
     *
     * @return framework attribute mapper, never {@code null}
     */
    @Override
    public FrameworkAttributeMapper attributeMapper() {
        return attributeMapper;
    }

    /**
     * Placeholder status-object generator used by partially wired framework
     * instances.
     *
     * <p>
     * This generator exists to make unsupported wiring explicit. Any attempt to use
     * status-object generation before a real X.509 generator has been supplied is
     * rejected immediately.
     * </p>
     */
    private static final class UnsupportedStatusObjectGenerator implements StatusObjectGenerator {

        /**
         * Always rejects status-object generation because no concrete X.509
         * status-object generator has been wired.
         *
         * @param command ignored command parameter
         * @param crlEntries ignored structured CRL entries
         * @return never returns normally
         * @throws UnsupportedOperationException always
         */
        @Override
        public zeroecho.pki.api.status.StatusObject generate(
                zeroecho.pki.api.status.StatusObjectGenerateCommand command,
                java.util.List<zeroecho.pki.spi.framework.CrlEntry> crlEntries) {
            throw new UnsupportedOperationException("X.509 status object generator not wired");
        }
    }
}
