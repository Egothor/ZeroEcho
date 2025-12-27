/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.spi.framework;

import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;

/**
 * Issues credentials for a credential framework.
 *
 * <p>
 * This backend assembles framework-specific "to-be-signed" structures and
 * produces encoded credentials. Actual signing operations are expected to be
 * delegated to runtime wiring (e.g., crypto providers/HSM) and not hard-coded
 * into this interface.
 * </p>
 */
public interface CredentialIssuerBackend {

    /**
     * Issues an end-entity credential.
     *
     * @param command issuance command
     * @return credential bundle
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws RuntimeException         if issuance fails
     */
    CredentialBundle issueEndEntity(IssueEndEntityCommand command);

    /**
     * Issues a CA credential for an existing CA entity (e.g., intermediate issuance
     * or cross-sign).
     *
     * @param command intermediate CA credential issuance command
     * @return CA credential
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws RuntimeException         if issuance fails
     */
    Credential issueIntermediateCertificate(IntermediateCertIssueCommand command);
}
