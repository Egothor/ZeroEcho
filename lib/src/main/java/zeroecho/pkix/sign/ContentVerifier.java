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

/**
 * A streaming verifier of a signature over to-be-signed content.
 *
 * <p>
 * Callers write the exact to-be-signed DER to {@link #contentStream()} and then
 * call {@link #verify(byte[])} with the signature to check. Verification is
 * performed against a public key that was fixed when the verifier was created
 * (see the {@code zeroecho.pkix} factory methods).
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <p>
 * An instance is single-use and need not be thread-safe.
 * </p>
 */
public interface ContentVerifier {

    /**
     * Returns the stream into which the to-be-signed bytes are written.
     *
     * @return the to-be-signed content output stream
     */
    OutputStream contentStream();

    /**
     * Verifies the given signature against the content written to
     * {@link #contentStream()}.
     *
     * @param signature the signature bytes to verify
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    boolean verify(byte[] signature);
}
