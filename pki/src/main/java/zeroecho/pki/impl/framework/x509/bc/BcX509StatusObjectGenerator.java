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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.attr.AttributeValue.IntegerValue;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.framework.StatusObjectGenerator;

/**
 * Bouncy Castle backed generator of X.509 status objects.
 *
 * <p>
 * The current implementation supports only generation of X.509 certificate
 * revocation lists (CRLs). It assembles a version 2 CRL from issuer-side wiring
 * attributes, optional revoked-certificate serial numbers supplied through the
 * attribute set, and delegated signing performed via {@link PkiSigningBus}.
 * </p>
 *
 * <p>
 * The generator expects the following framework-specific issuer attributes to
 * be present in the supplied {@link StatusObjectGenerateCommand}:
 * </p>
 * <ul>
 * <li>{@link BcX509Attributes#ISSUER_CERT_DER} as an
 * {@link AttributeValue.BytesValue} containing the issuer certificate in DER
 * form,</li>
 * <li>{@link BcX509Attributes#ISSUER_KEYREF} as an
 * {@link AttributeValue.StringValue} identifying the issuer signing key,</li>
 * <li>optionally one or more {@link #CRL_REVOKED_SERIAL} values as
 * {@link AttributeValue.IntegerValue} instances representing serial numbers of
 * revoked certificates.</li>
 * </ul>
 *
 * <p>
 * The produced {@link StatusObject} always carries:
 * </p>
 * <ul>
 * <li>type {@link StatusObjectType#CRL},</li>
 * <li>format {@link BcX509CredentialFramework#FORMAT_ID},</li>
 * <li>DER-encoded CRL content,</li>
 * <li>a deterministic object identifier derived from the SHA-256 digest of the
 * resulting CRL bytes.</li>
 * </ul>
 *
 * <h2>Revoked-entry handling</h2>
 * <p>
 * Revoked certificate serial numbers are read from all values associated with
 * {@link #CRL_REVOKED_SERIAL}. Only {@link IntegerValue} entries with a
 * positive numeric value are included as CRL entries. Non-positive serials and
 * non-integer attribute values are ignored.
 * </p>
 *
 * <h2>Update semantics</h2>
 * <p>
 * The generated CRL uses the current instant as {@code thisUpdate} and a fixed
 * {@code nextUpdate} of seven days later.
 * </p>
 *
 * <h2>Signing model</h2>
 * <p>
 * This class never accesses private key material directly. Signing is delegated
 * to {@link PkiSigningBus} through {@link PkiBusContentSigner}.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Issuer certificate bytes, issuer key references, and revoked-serial input
 * values are operationally sensitive and must not be logged unsafely.</li>
 * <li>This generator produces CRL content only. It does not evaluate revocation
 * policy, validate issuer authorization, or determine revoked serials on its
 * own.</li>
 * <li>The correctness of the produced CRL depends on the validity of issuer
 * wiring attributes and on the downstream signing boundary honoring the
 * requested signature algorithm.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is immutable and safe for concurrent use provided that the
 * supplied {@link PkiSigningBus} is safe for the intended runtime model.
 * </p>
 */
public final class BcX509StatusObjectGenerator implements StatusObjectGenerator {

    /**
     * Attribute identifier used to carry one revoked certificate serial number for
     * CRL generation.
     *
     * <p>
     * Multiple values associated with this identifier may be supplied in the input
     * {@link AttributeSet}. Each positive {@link IntegerValue} contributes one CRL
     * entry.
     * </p>
     */
    private static final AttributeId CRL_REVOKED_SERIAL = new AttributeId("urn:zeroecho:pki:x509:crl:revoked");

    private final PkiSigningBus signingBus;
    private final String signatureAlgorithmId;
    private final Duration signingTtl;

    /**
     * Creates the X.509 status object generator.
     *
     * @param signingBus           signing bus used to delegate CRL signing; must
     *                             not be {@code null}
     * @param signatureAlgorithmId non-blank signature algorithm identifier in JCA
     *                             naming form; must not be {@code null} or blank
     * @param signingTtl           positive maximum signing TTL used for delegated
     *                             signing operations; must not be {@code null},
     *                             zero, or negative
     * @throws IllegalArgumentException if any argument violates the described
     *                                  contract
     */
    public BcX509StatusObjectGenerator(PkiSigningBus signingBus, String signatureAlgorithmId, Duration signingTtl) {
        if (signingBus == null) {
            throw new IllegalArgumentException("signingBus must not be null");
        }
        if (signatureAlgorithmId == null || signatureAlgorithmId.isBlank()) {
            throw new IllegalArgumentException("signatureAlgorithmId must not be null/blank");
        }
        if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        this.signingBus = signingBus;
        this.signatureAlgorithmId = signatureAlgorithmId;
        this.signingTtl = signingTtl;
    }

    /**
     * Generates an X.509 CRL status object.
     *
     * <p>
     * The supplied command must request {@link StatusObjectType#CRL} and must use
     * the X.509 format identifier {@link BcX509CredentialFramework#FORMAT_ID}. The
     * method validates the command, resolves issuer material, assembles the CRL,
     * adds revoked entries and authority key identifier, delegates signing, and
     * returns the resulting status object.
     * </p>
     *
     * <p>
     * The returned {@link StatusObject} contains:
     * </p>
     * <ul>
     * <li>a deterministic identifier of the form
     * {@code crl:&lt;sha256-of-crl-der&gt;},</li>
     * <li>the original issuer CA identifier from the command,</li>
     * <li>the current instant as {@code thisUpdate},</li>
     * <li>a {@code nextUpdate} seven days later,</li>
     * <li>the DER-encoded CRL,</li>
     * <li>the original command attributes unchanged.</li>
     * </ul>
     *
     * @param command status object generation command; must not be {@code null}
     * @return generated CRL status object
     * @throws IllegalArgumentException if {@code command} is {@code null}, if the
     *                                  requested status object type is unsupported,
     *                                  or if the requested format identifier is
     *                                  unsupported
     * @throws PkiException             if issuer wiring attributes are missing or
     *                                  invalid, if the issuer certificate cannot be
     *                                  parsed, if CRL extension construction fails,
     *                                  if signing fails, or if CRL encoding fails
     */
    @Override
    public StatusObject generate(StatusObjectGenerateCommand command) {
        validateCommandOrThrow(command);

        IssuerMaterial issuerMaterial = extractIssuerMaterialOrThrow(command.attributes());
        Instant thisUpdate = Instant.now();
        Instant nextUpdate = thisUpdate.plus(Duration.ofDays(7));
        Date thisUpdateDate = Date.from(thisUpdate);

        X509v2CRLBuilder builder = newCrlBuilder(issuerMaterial.issuerHolder(), thisUpdateDate, nextUpdate);
        addRevokedEntries(builder, command.attributes(), thisUpdateDate);
        addAuthorityKeyIdentifierOrThrow(builder, issuerMaterial.issuerHolder());

        X509CRLHolder crl = buildSignedCrlOrThrow(builder, issuerMaterial.keyRef());
        byte[] crlDer = encodeCrlOrThrow(crl);

        return toStatusObject(command, crlDer, thisUpdate, nextUpdate);
    }

    /**
     * Validates the high-level command contract for CRL generation.
     *
     * @param command command to validate; must not be {@code null}
     * @throws IllegalArgumentException if {@code command} is {@code null}, if the
     *                                  requested status object type is unsupported,
     *                                  or if the requested format identifier is
     *                                  unsupported
     */
    private static void validateCommandOrThrow(StatusObjectGenerateCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (command.type() != StatusObjectType.CRL) {
            throw new IllegalArgumentException("Unsupported status object type: " + command.type());
        }

        FormatId formatId = command.formatId();
        if (!BcX509CredentialFramework.FORMAT_ID.equals(formatId)) {
            throw new IllegalArgumentException("Unsupported formatId: " + formatId.value());
        }
    }

    /**
     * Resolves issuer material required for CRL generation from framework
     * attributes.
     *
     * @param attributes source attributes; must not be {@code null}
     * @return resolved issuer material
     * @throws PkiException if required issuer attributes are missing, use an
     *                      unexpected type, or contain an invalid issuer
     *                      certificate
     */
    private static IssuerMaterial extractIssuerMaterialOrThrow(AttributeSet attributes) {
        Optional<AttributeValue> issuerCertAttr = attributes.get(BcX509Attributes.ISSUER_CERT_DER);
        Optional<AttributeValue> issuerKeyAttr = attributes.get(BcX509Attributes.ISSUER_KEYREF);

        if (issuerCertAttr.isEmpty() || !(issuerCertAttr.get() instanceof AttributeValue.BytesValue)) {
            throw new PkiException("Missing issuer certificate");
        }
        if (issuerKeyAttr.isEmpty() || !(issuerKeyAttr.get() instanceof AttributeValue.StringValue)) {
            throw new PkiException("Missing issuer keyRef");
        }

        byte[] issuerDer = ((AttributeValue.BytesValue) issuerCertAttr.get()).value();
        KeyRef keyRef = new KeyRef(((AttributeValue.StringValue) issuerKeyAttr.get()).value());

        X509CertificateHolder issuerHolder;
        try {
            issuerHolder = new X509CertificateHolder(issuerDer);
        } catch (Exception ex) {
            throw new PkiException("Invalid issuer certificate", ex);
        }

        return new IssuerMaterial(issuerHolder, keyRef);
    }

    /**
     * Creates a CRL builder initialized with issuer and update information.
     *
     * @param issuerHolder parsed issuer certificate holder; must not be
     *                     {@code null}
     * @param thisUpdate   current update timestamp as {@link Date}; must not be
     *                     {@code null}
     * @param nextUpdate   next update timestamp as {@link Instant}; must not be
     *                     {@code null}
     * @return initialized CRL builder
     */
    private static X509v2CRLBuilder newCrlBuilder(X509CertificateHolder issuerHolder, Date thisUpdate,
            Instant nextUpdate) {
        X500Name issuerDn = issuerHolder.getSubject();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(issuerDn, thisUpdate);
        builder.setNextUpdate(Date.from(nextUpdate));
        return builder;
    }

    /**
     * Adds revoked-certificate entries to the CRL builder from framework
     * attributes.
     *
     * <p>
     * Only positive {@link IntegerValue} attribute values associated with
     * {@link #CRL_REVOKED_SERIAL} are added. Non-integer and non-positive values
     * are ignored.
     * </p>
     *
     * @param builder        target CRL builder; must not be {@code null}
     * @param attributes     source attributes; must not be {@code null}
     * @param revocationDate date to use for all generated CRL entries; must not be
     *                       {@code null}
     */
    private static void addRevokedEntries(X509v2CRLBuilder builder, AttributeSet attributes, Date revocationDate) {
        List<AttributeValue> revoked = attributes.getAll(CRL_REVOKED_SERIAL);
        for (AttributeValue value : revoked) {
            if (!(value instanceof IntegerValue)) {
                continue;
            }

            long serial = ((IntegerValue) value).value();
            if (serial <= 0) {
                continue;
            }

            builder.addCRLEntry(BigInteger.valueOf(serial), revocationDate, 0);
        }
    }

    /**
     * Adds the authority key identifier extension to the CRL builder.
     *
     * @param builder      target CRL builder; must not be {@code null}
     * @param issuerHolder parsed issuer certificate holder; must not be
     *                     {@code null}
     * @throws PkiException if the extension cannot be derived or added
     */
    private static void addAuthorityKeyIdentifierOrThrow(X509v2CRLBuilder builder, X509CertificateHolder issuerHolder) {
        try {
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            AuthorityKeyIdentifier authorityKeyIdentifier = extensionUtils
                    .createAuthorityKeyIdentifier(issuerHolder.getSubjectPublicKeyInfo());
            builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        } catch (Exception ex) {
            throw new PkiException("Failed to build CRL extensions", ex);
        }
    }

    /**
     * Builds and signs the CRL using the configured PKI signing boundary.
     *
     * @param builder      prepared CRL builder; must not be {@code null}
     * @param issuerKeyRef issuer signing key reference; must not be {@code null}
     * @return signed CRL holder
     * @throws PkiException if delegated signing fails
     */
    private X509CRLHolder buildSignedCrlOrThrow(X509v2CRLBuilder builder, KeyRef issuerKeyRef) {
        ContentSigner signer = new PkiBusContentSigner(signingBus, issuerKeyRef, signatureAlgorithmId, signingTtl);
        try {
            return builder.build(signer);
        } catch (Exception ex) {
            throw new PkiException("CRL signing failed", ex);
        }
    }

    /**
     * Encodes the signed CRL into DER form.
     *
     * @param crl signed CRL holder; must not be {@code null}
     * @return DER-encoded CRL bytes
     * @throws PkiException if CRL encoding fails
     */
    private static byte[] encodeCrlOrThrow(X509CRLHolder crl) {
        try {
            return crl.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("CRL encoding failed", ex);
        }
    }

    /**
     * Creates the PKI status object representation of the generated CRL.
     *
     * @param command    original generation command; must not be {@code null}
     * @param crlDer     DER-encoded CRL bytes; must not be {@code null}
     * @param thisUpdate generated {@code thisUpdate} timestamp; must not be
     *                   {@code null}
     * @param nextUpdate generated {@code nextUpdate} timestamp; must not be
     *                   {@code null}
     * @return resulting status object
     */
    private static StatusObject toStatusObject(StatusObjectGenerateCommand command, byte[] crlDer, Instant thisUpdate,
            Instant nextUpdate) {
        PkiId id = new PkiId("crl:" + sha256Hex(crlDer));
        EncodedObject encoded = new EncodedObject(Encoding.DER, crlDer);
        return new StatusObject(id, command.formatId(), command.issuerCaId(), command.type(), thisUpdate,
                Optional.of(nextUpdate), encoded, command.attributes());
    }

    /**
     * Computes the SHA-256 digest of the supplied bytes and returns it as a
     * lowercase hexadecimal string.
     *
     * @param in input bytes; must not be {@code null}
     * @return hexadecimal SHA-256 digest
     * @throws IllegalStateException if SHA-256 is unexpectedly unavailable in the
     *                               runtime
     */
    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(in));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

    /**
     * Immutable issuer-side material required for CRL generation.
     *
     * @param issuerHolder parsed issuer certificate holder
     * @param keyRef       issuer signing key reference
     */
    private record IssuerMaterial(X509CertificateHolder issuerHolder, KeyRef keyRef) {
    }
}
