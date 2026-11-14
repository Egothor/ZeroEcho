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
package zeroecho.pki.impl.framework.x509.bc;

import java.util.Objects;

import zeroecho.pki.api.FormatId;
import zeroecho.pki.spi.framework.CertificationRequestParser;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.FrameworkAttributeMapper;
import zeroecho.pki.spi.framework.ProofOfPossessionVerifier;
import zeroecho.pki.spi.framework.StatusObjectGenerator;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;

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
 * <li>Credential issuance remains owned by proof-gated core services rather
 * than this framework facade.</li>
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
    private final X509AuthoritySnapshot authority;

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
     * Status-object generation and credential issuance are intentionally not
     * exposed by this verification-only framework.
     * </p>
     *
     * @param authority trusted authority snapshot used for parsing and proof verification
     * @param executor algorithm executor used for proof verification
     */
    public BcX509CredentialFramework(X509AuthoritySnapshot authority, BcX509VerificationExecutor executor) {
        this(new BcX509CertificationRequestParser(), new BcX509ProofOfPossessionVerifier(authority, executor),
                new UnsupportedStatusObjectGenerator(), new BcX509FrameworkAttributeMapper(), authority);
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
            StatusObjectGenerator status, FrameworkAttributeMapper attributeMapper, X509AuthoritySnapshot authority) {
        this.requestParser = Objects.requireNonNull(requestParser, "requestParser");
        this.popVerifier = Objects.requireNonNull(popVerifier, "popVerifier");
        this.status = Objects.requireNonNull(status, "status");
        this.attributeMapper = Objects.requireNonNull(attributeMapper, "attributeMapper");
        this.authority = Objects.requireNonNull(authority, "authority");
    }

    /**
     * Returns the immutable algorithm authority owned by this framework graph.
     *
     * @return shared authority snapshot
     */
    public X509AuthoritySnapshot authority() {
        return authority;
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

    @Override
    public String displayName() { return "X.509"; }

    @Override
    public SubjectInput subjectInput() {
        return new SubjectInput("Subject — X.509 distinguished name",
                "Use attribute=value syntax, for example CN=Example Root CA. Full profile rules are checked by the server.",
                "CN=Example Root CA", java.util.Optional.of(
                        "^\\s*(?:[A-Za-z][A-Za-z0-9-]*|(?:[Oo][Ii][Dd]\\.)?[0-9]+(?:\\.[0-9]+)+)\\s*=.*$"));
    }

    @Override
    public java.util.List<CredentialRepresentation> credentialRepresentations(zeroecho.pki.api.Encoding storedEncoding) {
        if (storedEncoding != zeroecho.pki.api.Encoding.DER) throw new IllegalArgumentException("X.509 stored credential must be DER");
        return java.util.List.of(new CredentialRepresentation("original", "DER", "application/pkix-cert", "der", storedEncoding),
                new CredentialRepresentation("pem", "PEM", "application/x-pem-file", "pem", zeroecho.pki.api.Encoding.PEM));
    }

    @Override
    public zeroecho.pki.api.EncodedObject exportCredential(zeroecho.pki.api.EncodedObject stored, String representation,
            zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException {
        java.util.Objects.requireNonNull(stored, "stored");
        java.util.Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        if (stored.encoding() != zeroecho.pki.api.Encoding.DER || stored.byteLength() > 1024 * 1024) {
            throw new IllegalArgumentException("X.509 stored credential encoding or length is invalid");
        }
        if (!"original".equals(representation) && !"pem".equals(representation)) {
            throw new UnsupportedOperationException("Unsupported X.509 credential representation");
        }
        byte[] der = stored.bytes();
        try {
            if (!java.util.Arrays.equals(der, zeroecho.pkix.Pkix.parseCertificate(der).getEncoded())) {
                throw new java.io.IOException("X.509 credential is not canonical DER");
            }
        } catch (IllegalArgumentException | java.security.cert.CertificateEncodingException failure) {
            throw new java.io.IOException("X.509 credential is not canonical DER", failure);
        }
        cancellation.throwIfCancelled();
        if ("original".equals(representation)) return stored;
        var output = new java.io.ByteArrayOutputStream();
        output.write("-----BEGIN CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        output.write(java.util.Base64.getMimeEncoder(64, new byte[]{'\n'}).encode(der));
        output.write("\n-----END CERTIFICATE-----\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        cancellation.throwIfCancelled();
        return new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.PEM, output.toByteArray());
    }

    @Override
    public java.util.List<CredentialRepresentation> statusRepresentations(zeroecho.pki.api.status.StatusObjectType type,zeroecho.pki.api.Encoding encoding) {
        if((type==zeroecho.pki.api.status.StatusObjectType.CRL||type==zeroecho.pki.api.status.StatusObjectType.DELTA_CRL)&&encoding==zeroecho.pki.api.Encoding.DER) {
            return java.util.List.of(new CredentialRepresentation("original","DER","application/pkix-crl","crl",encoding),
                    new CredentialRepresentation("pem","PEM","application/x-pem-file","pem",zeroecho.pki.api.Encoding.PEM));
        }
        return CredentialFramework.super.statusRepresentations(type,encoding);
    }

    @Override
    public zeroecho.core.io.RepeatableContent exportStatusContent(zeroecho.pki.api.status.StatusObjectType type,zeroecho.pki.api.Encoding encoding,
            zeroecho.core.io.RepeatableContent content,String representation,zeroecho.core.io.CancellationSignal cancellation)throws java.io.IOException {
        if((type==zeroecho.pki.api.status.StatusObjectType.CRL||type==zeroecho.pki.api.status.StatusObjectType.DELTA_CRL)&&encoding==zeroecho.pki.api.Encoding.DER) {
            new zeroecho.pki.impl.framework.x509.StreamingDerReader().inspectSignedObject(content,
                    zeroecho.pki.impl.framework.x509.StreamingDerReader.SignedObjectKind.CRL,cancellation);
            if("original".equals(representation))return content;
            if("pem".equals(representation))return new zeroecho.pki.impl.framework.x509.StreamingPemContent(content,"X509 CRL",cancellation);
        }
        return CredentialFramework.super.exportStatusContent(type,encoding,content,representation,cancellation);
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
         * @param command    ignored command parameter
         * @param crlEntries ignored structured CRL entries
         * @return never returns normally
         * @throws UnsupportedOperationException always
         */
        @Override
        public zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion generate(
                zeroecho.pki.api.status.StatusObjectGenerateCommand command,
                zeroecho.pki.spi.framework.CrlEntrySource crlEntries) {
            throw new UnsupportedOperationException("X.509 status object generator not wired");
        }
    }
}
