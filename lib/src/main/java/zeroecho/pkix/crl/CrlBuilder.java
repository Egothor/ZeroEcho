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
package zeroecho.pkix.crl;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.time.Instant;
import java.util.Iterator;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.sign.ContentSigner;

/**
 * A fluent builder for a signed X.509 CRL that yields a standard {@link X509CRL}.
 *
 * <p>
 * Entries may be added individually or streamed from an {@link Iterator} so that
 * very large revocation sets are encoded without materializing them in memory.
 * The {@code tbsCertList} is signed by a caller supplied {@link ContentSigner}.
 * </p>
 *
 * <p>
 * Instances are single-use and not thread-safe.
 * </p>
 */
public interface CrlBuilder {

    /**
     * Sets the CRL issuer distinguished name (required).
     *
     * @param issuer the issuer DN
     * @return this builder
     */
    CrlBuilder issuer(X500Principal issuer);

    /**
     * Sets {@code thisUpdate} (required).
     *
     * @param thisUpdate the time of this CRL
     * @return this builder
     */
    CrlBuilder thisUpdate(Instant thisUpdate);

    /**
     * Sets {@code nextUpdate} (optional but recommended).
     *
     * @param nextUpdate the time of the next scheduled CRL
     * @return this builder
     */
    CrlBuilder nextUpdate(Instant nextUpdate);

    /**
     * Adds the {@code CRLNumber} extension.
     *
     * @param crlNumber the monotonically increasing CRL number
     * @return this builder
     */
    CrlBuilder crlNumber(BigInteger crlNumber);

    /**
     * Adds the {@code AuthorityKeyIdentifier} extension.
     *
     * @param keyIdentifier the issuer subject-key-identifier bytes
     * @return this builder
     */
    CrlBuilder authorityKeyIdentifier(byte[] keyIdentifier);

    /**
     * Marks this as a delta CRL by adding the {@code DeltaCRLIndicator} extension.
     *
     * @param baseCrlNumber the base CRL number this delta is relative to
     * @return this builder
     */
    CrlBuilder deltaCrlIndicator(BigInteger baseCrlNumber);

    /**
     * Adds one revoked-certificate entry.
     *
     * @param entry the entry to add
     * @return this builder
     */
    CrlBuilder addEntry(CrlEntry entry);

    /**
     * Adds all entries produced by the given iterator, in order.
     *
     * @param entries a (possibly large) stream of entries
     * @return this builder
     */
    CrlBuilder addEntries(Iterator<CrlEntry> entries);

    /**
     * Adds an arbitrary CRL extension.
     *
     * @param extension the extension to add
     * @return this builder
     */
    CrlBuilder addExtension(CertificateExtension extension);

    /**
     * Signs the assembled {@code tbsCertList} with the given signer and returns the
     * resulting CRL.
     *
     * @param signer the content signer supplying the signature and algorithm
     * @return the signed CRL
     */
    X509CRL build(ContentSigner signer);
}
