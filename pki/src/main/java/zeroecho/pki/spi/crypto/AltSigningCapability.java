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
package zeroecho.pki.spi.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;

import zeroecho.pki.api.KeyRef;

/**
 * Optional extension for signing providers capable of performing a direct
 * synchronous alternative signature without the full signing infrastructure.
 *
 * <p>
 * Implement this interface in addition to {@link SigningProvider} to indicate
 * that the provider can sign content directly for use in hybrid certificate
 * issuance (X.509 2019 Amendment 2 alternative-signature mode). The raw
 * signature bytes are returned immediately without dispatching through the
 * asynchronous signing pipeline.
 * </p>
 *
 * <p>
 * The returned bytes are the raw external-format signature (IDENTITY encoding
 * for PQC algorithms such as ML-DSA), suitable for placement in the
 * AltSignatureValue BIT STRING.
 * </p>
 *
 * @since 1.0
 */
@FunctionalInterface
public interface AltSigningCapability {

    /**
     * Signs the given content using the specified key and algorithm.
     *
     * @param keyRef      reference to the signing key managed by this provider
     * @param algorithmId canonical signature algorithm identifier
     * @param content     the bytes to sign; must not be {@code null}
     * @return raw signature bytes in the algorithm's external encoding
     * @throws IOException              if key access or I/O fails
     * @throws GeneralSecurityException if the signing operation fails
     */
    byte[] sign(KeyRef keyRef, String algorithmId, byte[] content)
            throws IOException, GeneralSecurityException;
}
