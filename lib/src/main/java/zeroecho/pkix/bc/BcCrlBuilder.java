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
package zeroecho.pkix.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;

import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.crl.CrlBuilder;
import zeroecho.pkix.crl.CrlEntry;
import zeroecho.pkix.sign.ContentSigner;

/** BouncyCastle-backed {@link CrlBuilder} yielding a JDK CRL. */
final class BcCrlBuilder implements CrlBuilder {

    private X500Principal issuer;
    private Instant thisUpdate;
    private Instant nextUpdate;
    private BigInteger crlNumber;
    private byte[] authorityKeyIdentifier;
    private BigInteger deltaBaseCrlNumber;
    private final java.util.List<CrlEntry> entries = new java.util.ArrayList<>();
    private final java.util.List<CertificateExtension> extraExtensions = new java.util.ArrayList<>();

    @Override
    public CrlBuilder issuer(X500Principal issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public CrlBuilder thisUpdate(Instant thisUpdate) {
        this.thisUpdate = thisUpdate;
        return this;
    }

    @Override
    public CrlBuilder nextUpdate(Instant nextUpdate) {
        this.nextUpdate = nextUpdate;
        return this;
    }

    @Override
    public CrlBuilder crlNumber(BigInteger crlNumber) {
        this.crlNumber = crlNumber;
        return this;
    }

    @Override
    public CrlBuilder authorityKeyIdentifier(byte[] keyIdentifier) {
        this.authorityKeyIdentifier = keyIdentifier == null ? null : keyIdentifier.clone();
        return this;
    }

    @Override
    public CrlBuilder deltaCrlIndicator(BigInteger baseCrlNumber) {
        this.deltaBaseCrlNumber = baseCrlNumber;
        return this;
    }

    @Override
    public CrlBuilder addEntry(CrlEntry entry) {
        entries.add(Objects.requireNonNull(entry, "entry"));
        return this;
    }

    @Override
    public CrlBuilder addEntries(Iterator<CrlEntry> newEntries) {
        while (newEntries.hasNext()) {
            entries.add(Objects.requireNonNull(newEntries.next(), "entry"));
        }
        return this;
    }

    @Override
    public CrlBuilder addExtension(CertificateExtension extension) {
        extraExtensions.add(Objects.requireNonNull(extension, "extension"));
        return this;
    }

    @Override
    public X509CRL build(ContentSigner signer) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(thisUpdate, "thisUpdate");
        Objects.requireNonNull(signer, "signer");
        X509v2CRLBuilder builder = new X509v2CRLBuilder(BcExtensions.toX500Name(issuer), Date.from(thisUpdate));
        if (nextUpdate != null) {
            builder.setNextUpdate(Date.from(nextUpdate));
        }
        for (CrlEntry entry : entries) {
            builder.addCRLEntry(entry.serialNumber(), Date.from(entry.revocationTime()), entry.reason().code());
        }
        try {
            if (crlNumber != null) {
                builder.addExtension(Extension.cRLNumber, false, new CRLNumber(crlNumber));
            }
            if (authorityKeyIdentifier != null) {
                builder.addExtension(BcExtensions.authorityKeyIdentifier(authorityKeyIdentifier));
            }
            if (deltaBaseCrlNumber != null) {
                builder.addExtension(Extension.deltaCRLIndicator, true, new CRLNumber(deltaBaseCrlNumber));
            }
            for (CertificateExtension extension : extraExtensions) {
                builder.addExtension(BcExtensions.generic(extension));
            }
            X509CRLHolder holder = builder.build(new BcContentSignerAdapter(signer));
            return toJdk(holder);
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot assemble CRL", failure);
        }
    }

    private static X509CRL toJdk(X509CRLHolder holder) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509CRL) factory.generateCRL(new ByteArrayInputStream(holder.getEncoded()));
        } catch (CertificateException | CRLException | IOException failure) {
            throw new IllegalStateException("Cannot materialize CRL", failure);
        }
    }
}
