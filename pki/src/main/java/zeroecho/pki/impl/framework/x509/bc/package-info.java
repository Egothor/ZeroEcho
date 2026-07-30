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
/**
 * Internal Bouncy Castle backed X.509 credential framework implementation for
 * the PKI runtime.
 *
 * <p>
 * This package contains the internal X.509 framework adapter used by the PKI
 * implementation layer to process X.509 and PKCS#10 based credential workflows.
 * It provides the concrete {@code CredentialFramework} implementation, parsing
 * and proof-of-possession verification of certification requests, X.509
 * credential issuance support, status-object generation, framework-specific
 * attribute handling, and supporting interop utilities.
 * </p>
 *
 * <p>
 * The package is intentionally internal. Bouncy Castle specific classes and
 * ASN.1 details must not leak through the public PKI API or SPI surfaces except
 * where explicitly required by higher-level contracts. Public PKI callers
 * should interact through {@code zeroecho.pki.api.*} and
 * {@code zeroecho.pki.spi.*} abstractions rather than through types in this
 * package.
 * </p>
 *
 * <h2>Contained responsibilities</h2>
 * <ul>
 * <li>X.509 {@link zeroecho.pki.spi.framework.CredentialFramework}
 * implementation and provider registration,</li>
 * <li>PKCS#10 certification request parsing and proof-of-possession
 * verification,</li>
 * <li>X.509 end-entity and intermediate CA credential issuance,</li>
 * <li>X.509 status object generation, currently focused on CRLs,</li>
 * <li>X.509-specific framework attribute identifiers and attribute
 * normalization,</li>
 * <li>algorithm identifier mapping between ASN.1 OIDs and ZeroEcho canonical
 * algorithm identifiers,</li>
 * <li>bridging of Bouncy Castle signing interfaces to the PKI signing
 * orchestration boundary.</li>
 * </ul>
 *
 * <h2>Architectural boundaries</h2>
 * <ul>
 * <li>This package is an implementation package, not a consumer-facing API
 * package.</li>
 * <li>Framework-neutral contracts remain defined in
 * {@code zeroecho.pki.spi.framework}.</li>
 * <li>Persistent state and higher-level PKI lifecycle orchestration remain
 * outside this package.</li>
 * <li>Private key operations are not performed directly here; signing is
 * delegated through PKI signing boundaries such as
 * {@link zeroecho.pki.impl.core.async.PkiSigningBus} and
 * {@link zeroecho.pki.spi.crypto.SignatureWorkflow}.</li>
 * </ul>
 *
 * <h2>Wiring model</h2>
 * <p>
 * The framework implementation in this package supports a partially wired mode
 * and a fully wired mode. In partially wired mode, request parsing,
 * proof-of-possession verification, and attribute mapping are available, while
 * issuance and status-object generation remain intentionally unsupported until
 * concrete backend components are supplied. This allows bootstrap and runtime
 * composition to separate framework selection from full cryptographic and PKI
 * service wiring. The package is exposed to runtime composition only through
 * the framework SPI and its ServiceLoader provider; bootstrap code must not
 * depend on these implementation classes directly.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Private key material must never be exposed by classes in this
 * package.</li>
 * <li>Operationally sensitive inputs such as CSR bytes, issuer certificate
 * encodings, subject public key data, signatures, and key references must not
 * be logged unsafely.</li>
 * <li>Proof-of-possession verification performed in this package validates only
 * possession of the request key pair; it does not by itself imply issuance
 * authorization or policy compliance.</li>
 * <li>Algorithm identifier mapping and attribute wiring in this package are
 * explicit by design and should be extended deliberately rather than by
 * heuristic guesswork.</li>
 * </ul>
 *
 * <h2>Implementation style</h2>
 * <p>
 * Implementations in this package favor explicit validation, fail-fast handling
 * of missing framework wiring, deterministic identifier mapping, and clear
 * separation between framework-neutral PKI contracts and X.509-specific
 * processing details.
 * </p>
 */
package zeroecho.pki.impl.framework.x509.bc;
