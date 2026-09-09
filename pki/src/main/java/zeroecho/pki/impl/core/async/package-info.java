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
 * Internal asynchronous orchestration support for PKI signing workflows.
 *
 * <p>
 * This package contains the PKI-core runtime components that bridge PKI service
 * operations to the durable asynchronous execution infrastructure used for
 * delegated signing. The classes in this package are internal implementation
 * types and are not intended to serve as the primary public extension surface
 * for consumers of the PKI API.
 * </p>
 *
 * <p>
 * The package provides three closely related responsibilities:
 * </p>
 * <ul>
 * <li>canonicalization of operation identifiers used for durable async
 * orchestration,</li>
 * <li>stable codecs for PKI-specific identifiers and payload objects used by
 * the async persistence layer,</li>
 * <li>store-backed orchestration of asynchronous signature execution, status
 * polling, result retrieval, and workflow continuation persistence.</li>
 * </ul>
 *
 * <h2>Architectural role</h2>
 * <p>
 * The package sits between the PKI core service layer and the generic async
 * utility layer. It adapts PKI concepts such as {@code PkiId},
 * {@code Principal}, {@code EncodedObject}, key references, and signing
 * workflow state to the signing store used by the runtime.
 * </p>
 *
 * <p>
 * The main orchestration entry point is the signing bus, which persists
 * submission, execution progress, terminal state, recovery, and result
 * consumption through {@link zeroecho.pki.spi.store.SignWorkflowStore} as one
 * authoritative state. Generic async persistence remains separate for
 * non-signing consumers. Operation identifiers are normalized
 * to a canonical base form so that re-attach and lookup remain deterministic
 * even when human-readable display suffixes are present.
 * </p>
 *
 * <h2>Persistence and re-attach semantics</h2>
 * <ul>
 * <li>Operation identifiers are derived deterministically from the owner and
 * the client-provided operation identifier.</li>
 * <li>Display-oriented suffixes may be appended for operator readability, but
 * backend persistence and lookup use only the canonical base identifier.</li>
 * <li>Fenced signing records contain continuation, status, and terminal evidence
 * needed to re-attach after restart without a redundant projection.</li>
 * <li>Result and identifier encodings are intentionally stable for durable store
 * records.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Classes in this package orchestrate signing but do not directly expose or
 * handle private key material.</li>
 * <li>Sensitive operational payloads, including to-be-signed content and raw
 * signature results, may transit through authoritative signing records;
 * implementations and callers must therefore avoid
 * unsafe logging and must treat persisted payloads according to the applicable
 * durability and data-protection policy.</li>
 * <li>Canonical operation identifiers are designed to avoid owner collisions
 * and escaping ambiguities in persistence keys.</li>
 * <li>The assurance of the overall signing workflow depends on the configured
 * {@link zeroecho.pki.spi.crypto.SignatureWorkflow},
 * {@link zeroecho.pki.spi.store.PkiStore}, and signing durability layer honoring
 * their respective contracts.</li>
 * </ul>
 *
 * <h2>Implementation notes</h2>
 * <p>
 * Implementations in this package favor deterministic identifier construction,
 * explicit validation, bounded orchestration semantics, and separation between
 * display-oriented identifiers and persistence-oriented identifiers. The design
 * goal is durable operational behavior, restart safety, and audit-friendly
 * control flow.
 * </p>
 */
package zeroecho.pki.impl.core.async;
