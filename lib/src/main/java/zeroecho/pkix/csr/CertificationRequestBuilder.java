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
package zeroecho.pkix.csr;

import java.security.PublicKey;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.CertificateExtension;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.sign.ContentSigner;

/**
 * A fluent builder for a signed PKCS#10 certification request.
 *
 * <p>
 * Provided so that ZeroEcho tools and tests can generate CSRs natively rather than
 * shelling out to an external tool. The request is signed by a caller supplied
 * {@link ContentSigner}, keeping the private key outside the builder.
 * </p>
 *
 * <p>
 * Instances are single-use and not thread-safe.
 * </p>
 */
public interface CertificationRequestBuilder {

    /**
     * Sets the requested subject distinguished name (required).
     *
     * @param subject the subject DN
     * @return this builder
     */
    CertificationRequestBuilder subject(X500Principal subject);

    /**
     * Sets the subject public key (required).
     *
     * @param publicKey the subject public key
     * @return this builder
     */
    CertificationRequestBuilder publicKey(PublicKey publicKey);

    /**
     * Requests the given subject alternative names via the extension-request
     * attribute.
     *
     * @param names the general names
     * @param critical whether the SAN extension is critical
     * @return this builder
     */
    CertificationRequestBuilder subjectAlternativeNames(List<GeneralName> names, boolean critical);

    /**
     * Requests an arbitrary extension via the extension-request attribute.
     *
     * @param extension the extension to request
     * @return this builder
     */
    CertificationRequestBuilder requestExtension(CertificateExtension extension);

    /**
     * Adds an arbitrary PKCS#10 attribute.
     *
     * @param attribute the attribute to add
     * @return this builder
     */
    CertificationRequestBuilder addAttribute(CsrAttribute attribute);

    /**
     * Signs the assembled {@code certificationRequestInfo} and returns the request.
     *
     * @param signer the content signer supplying the signature and algorithm
     * @return the signed certification request
     */
    CertificationRequest build(ContentSigner signer);
}
