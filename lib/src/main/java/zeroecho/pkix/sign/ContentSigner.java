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
package zeroecho.pkix.sign;

import java.io.OutputStream;

import zeroecho.pkix.AlgorithmIdentifier;

/**
 * A streaming producer of a signature over to-be-signed content, used by the
 * ZeroEcho PKIX builders to sign certificates, CRLs, CSRs, and OCSP responses.
 *
 * <p>
 * The contract is deliberately minimal and toolkit-independent: a signer declares
 * the signature {@link AlgorithmIdentifier} that will appear in the produced
 * object, exposes an {@link OutputStream} into which the builder writes the exact
 * to-be-signed DER, and yields the raw signature bytes on completion. This lets a
 * caller keep the private key wherever it lives — in a local {@code KeyStore}, an
 * HSM, or a remote signing service — without exposing key material to the
 * builder.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <p>
 * An instance is single-use: the builder writes the content, closes the stream if
 * appropriate, then calls {@link #signature()} exactly once. Implementations need
 * not be thread-safe.
 * </p>
 */
public interface ContentSigner {

    /**
     * Returns the signature algorithm identifier that will be recorded in the
     * signed object's {@code signatureAlgorithm} field.
     *
     * @return the signature algorithm identifier
     */
    AlgorithmIdentifier algorithm();

    /**
     * Returns the stream into which the to-be-signed bytes are written.
     *
     * <p>
     * The builder writes the exact DER of the {@code tbsCertificate},
     * {@code tbsCertList}, {@code certificationRequestInfo}, or
     * {@code tbsResponseData} to this stream before requesting the signature.
     * </p>
     *
     * @return the to-be-signed content output stream
     */
    OutputStream contentStream();

    /**
     * Finalizes and returns the raw signature over the bytes written to
     * {@link #contentStream()}.
     *
     * @return the raw signature bytes
     */
    byte[] signature();
}
