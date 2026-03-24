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

import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;

/**
 * SPI contract for framework-specific credential issuance backends.
 *
 * <p>
 * Implementations of this interface are responsible for constructing the
 * framework-specific credential content required by a concrete credential
 * format, such as X.509 certificates or equivalent encoded artifacts in another
 * framework. This includes assembling the to-be-signed structure, applying
 * framework-specific extensions or metadata, and returning the resulting
 * encoded credential object model expected by the PKI runtime.
 * </p>
 *
 * <p>
 * This contract deliberately does not require implementations to own or expose
 * private key material directly. Actual signing is expected to be delegated
 * through runtime wiring, such as a signing service, crypto provider, HSM, or
 * other key-management boundary selected by the enclosing PKI deployment.
 * </p>
 *
 * <h2>Architectural role</h2>
 * <ul>
 * <li>{@link CredentialFramework} selects the concrete backend appropriate for
 * a credential format.</li>
 * <li>PKI core services prepare validated issuance commands and call this
 * backend to obtain framework-specific credentials.</li>
 * <li>This backend performs format-specific credential assembly, not CA policy
 * orchestration, lifecycle control, or long-term persistence.</li>
 * </ul>
 *
 * <h2>Implementation expectations</h2>
 * <ul>
 * <li>Implementations should validate that the supplied command contains the
 * framework-specific material required for issuance.</li>
 * <li>Implementations should fail explicitly when mandatory issuer material,
 * subject material, or framework-specific overrides are missing or
 * invalid.</li>
 * <li>Implementations may assume that higher layers have already selected the
 * correct framework and issuer context, but they must still protect themselves
 * against structurally inconsistent commands.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Implementations must never expose private key material through returned
 * values, thrown exceptions, or logs.</li>
 * <li>Returned credentials should contain only the public credential artifacts
 * appropriate for the target framework.</li>
 * <li>Inputs such as issuer wiring attributes, CSR payloads, and subject public
 * key encodings may be operationally sensitive and must not be logged
 * unsafely.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Thread-safety is implementation-specific. Implementations intended for shared
 * runtime use should document their concurrency guarantees explicitly.
 * </p>
 */
public interface CredentialIssuerBackend {

    /**
     * Issues an end-entity credential.
     *
     * <p>
     * This operation produces a credential for a non-CA subject, typically from a
     * validated certification request or equivalent subject input carried by the
     * {@link IssueEndEntityCommand}. The returned {@link CredentialBundle} may
     * contain the issued leaf credential together with any additional runtime
     * bundle material defined by the concrete framework, such as chain elements or
     * accompanying metadata.
     * </p>
     *
     * <p>
     * The command is expected to carry all framework-specific issuance inputs
     * required by the concrete implementation, including any issuer wiring
     * attributes, profile identifiers, validity overrides, and subject request
     * material. The exact interpretation of those fields is framework-specific.
     * </p>
     *
     * @param command end-entity issuance command; must not be {@code null}
     * @return issued credential bundle, never {@code null}
     * @throws IllegalArgumentException if {@code command} is {@code null} or
     *                                  structurally invalid for the concrete
     *                                  framework implementation
     * @throws RuntimeException         if credential assembly, delegated signing,
     *                                  or other framework-specific issuance
     *                                  processing fails
     */
    CredentialBundle issueEndEntity(IssueEndEntityCommand command);

    /**
     * Issues a CA credential for an existing CA subject entity.
     *
     * <p>
     * This operation is intended for issuance scenarios in which the CA subject
     * already exists in the PKI domain model and requires a new CA credential, such
     * as intermediate CA issuance, CA rollover support, or cross-signing. The exact
     * certificate profile and extension semantics remain framework- specific.
     * </p>
     *
     * <p>
     * The supplied {@link IntermediateCertIssueCommand} is expected to contain the
     * issuer CA reference, subject CA reference, profile selection, and any
     * framework-specific attributes needed to construct the CA credential.
     * </p>
     *
     * @param command CA credential issuance command; must not be {@code null}
     * @return issued CA credential, never {@code null}
     * @throws IllegalArgumentException if {@code command} is {@code null} or
     *                                  structurally invalid for the concrete
     *                                  framework implementation
     * @throws RuntimeException         if credential assembly, delegated signing,
     *                                  or other framework-specific issuance
     *                                  processing fails
     */
    Credential issueIntermediateCertificate(IntermediateCertIssueCommand command);
}
