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
package zeroecho.pki.spi.framework;

import zeroecho.core.io.CancellationSignal;

import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.impl.framework.x509.X509SignedObjectCompletion;

/**
 * Generates status objects for a credential framework (e.g., CRL/delta CRL/OCSP
 * for X.509).
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface StatusObjectGenerator {

    /**
     * Generates a status object.
     *
     * @param command    generation command
     * @param crlEntries stable streamed CRL entries
     * @return generated status object
     * @throws IllegalArgumentException if {@code command} or {@code crlEntries} is
     *                                  invalid
     * @throws RuntimeException         if generation fails
     */
    X509SignedObjectCompletion generate(StatusObjectGenerateCommand command, CrlEntrySource crlEntries);

    /**
     * Generates a status object while carrying originating cancellation to signing.
     *
     * @param command validated generation command
     * @param crlEntries stable streamed CRL entries
     * @param cancellation originating cooperative cancellation signal
     * @return generated signed status object
     */
    default X509SignedObjectCompletion generate(StatusObjectGenerateCommand command, CrlEntrySource crlEntries,
            CancellationSignal cancellation) {
        java.util.Objects.requireNonNull(cancellation, "cancellation");
        return generate(command, crlEntries);
    }
}
