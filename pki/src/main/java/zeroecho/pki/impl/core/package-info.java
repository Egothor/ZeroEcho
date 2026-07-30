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
 * Default store-backed PKI core service implementations and supporting internal
 * contracts.
 *
 * <p>
 * This package contains the primary runtime implementations of the PKI core
 * services declared in {@code zeroecho.pki.api}. The classes in this package
 * coordinate PKI operations by combining:
 * </p>
 * <ul>
 * <li>persistent state and lookup through
 * {@link zeroecho.pki.spi.store.PkiStore},</li>
 * <li>format-specific credential, request, and status-object processing through
 * {@link zeroecho.pki.spi.framework.CredentialFramework},</li>
 * <li>key indirection through {@link zeroecho.pki.api.KeyRef}, and</li>
 * <li>delegated signing through the asynchronous signing boundary used by the
 * PKI runtime.</li>
 * </ul>
 *
 * <p>
 * The package intentionally acts as an orchestration layer rather than as the
 * location of cryptographic primitive implementations. It validates
 * service-side invariants, prepares runtime input for downstream framework
 * backends, persists resulting domain objects, and enforces explicit failure
 * behavior when required runtime capabilities are unavailable.
 * </p>
 *
 * <h2>Contained responsibilities</h2>
 * <p>
 * The current package content covers default implementations for:
 * </p>
 * <ul>
 * <li>certification authority lifecycle operations,</li>
 * <li>certification request fingerprinting, parsing, optional persistence, and
 * proof-of-possession verification orchestration,</li>
 * <li>end-entity issuance orchestration and minimal bundle construction,</li>
 * <li>revocation record creation and lookup,</li>
 * <li>status object generation and listing,</li>
 * <li>public key information resolution through internal runtime
 * contracts.</li>
 * </ul>
 *
 * <h2>Architectural boundaries</h2>
 * <ul>
 * <li>This package is part of the PKI core runtime implementation and is not
 * the primary public extension surface for consumers.</li>
 * <li>Domain contracts remain defined in {@code zeroecho.pki.api}.</li>
 * <li>Framework-specific issuance, request parsing, proof-of-possession
 * verification, and status object generation remain delegated to
 * {@link zeroecho.pki.spi.framework.CredentialFramework}.</li>
 * <li>Persistent state remains delegated to
 * {@link zeroecho.pki.spi.store.PkiStore}.</li>
 * <li>Private key operations are not performed directly by these classes and
 * are instead routed through key references and signing boundaries.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Private key material is never loaded, returned, or persisted by the
 * classes in this package.</li>
 * <li>Implementations must not log private keys, seed material, plaintext
 * payloads, raw signatures, shared secrets, or equivalent sensitive operational
 * material.</li>
 * <li>The correctness and assurance level of PKI outcomes depend on the
 * configured store, framework, and signing runtime honoring their respective
 * contracts.</li>
 * <li>Some operations intentionally expose contract methods that are not yet
 * implemented in the current runtime build; such cases fail explicitly rather
 * than silently degrading behavior.</li>
 * </ul>
 *
 * <h2>Implementation style</h2>
 * <p>
 * Implementations in this package favor explicit validation, deterministic
 * control flow, limited hidden behavior, and straightforward failure semantics.
 * The design goal is operational auditability and predictable service behavior
 * rather than compact or implicit programming style.
 * </p>
 */
package zeroecho.pki.impl.core;
