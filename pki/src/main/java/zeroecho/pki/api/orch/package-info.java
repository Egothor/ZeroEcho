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
 * Orchestration and workflow durability API for ZeroEcho PKI.
 *
 * <p>
 * This package defines stable domain abstractions related to <em>long-running
 * PKI workflows</em> and their durability requirements. It is concerned with
 * describing <strong>what must be persisted and how durable such persistence
 * must be</strong>, not with <em>how</em> the persistence is implemented.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <p>
 * The orchestration layer in ZeroEcho PKI coordinates multi-step operations
 * such as certificate issuance, revocation processing, key rollover, or
 * publication workflows. These operations:
 * </p>
 * <ul>
 * <li>may span multiple logical steps,</li>
 * <li>may involve external systems or asynchronous callbacks,</li>
 * <li>must tolerate restarts, crashes, or redeployments.</li>
 * </ul>
 *
 * <p>
 * This package provides the minimal API necessary to:
 * </p>
 * <ul>
 * <li>describe the required durability guarantees for workflow state,</li>
 * <li>represent persisted workflow state in a storage-agnostic form,</li>
 * <li>enable deterministic recovery and audit of workflow progression.</li>
 * </ul>
 *
 * <h2>Key abstractions</h2>
 * <ul>
 * <li>{@link zeroecho.pki.api.orch.OrchestrationDurabilityPolicy
 * OrchestrationDurabilityPolicy} defines <em>how durable</em> orchestration
 * state must be (e.g. write-through, buffered, best-effort), allowing different
 * operational trade-offs without changing orchestration logic.</li>
 * <li>{@link zeroecho.pki.api.orch.WorkflowStateRecord WorkflowStateRecord}
 * represents an immutable, persisted snapshot of workflow state at a specific
 * point in time, suitable for recovery, audit, and historical inspection.</li>
 * </ul>
 *
 * <h2>Immutability and history</h2>
 * <p>
 * Workflow state records are designed to be immutable once persisted.
 * Implementations are expected to append new state records rather than
 * overwrite existing ones, enabling:
 * </p>
 * <ul>
 * <li>full audit trails,</li>
 * <li>temporal queries ("state at time T"),</li>
 * <li>post-mortem analysis of failed or aborted workflows.</li>
 * </ul>
 *
 * <p>
 * Whether and for how long historical records are retained is governed by
 * policy and implementation, but the API itself is intentionally compatible
 * with history-preserving stores.
 * </p>
 *
 * <h2>API stability and integration</h2>
 * <p>
 * The types in this package are part of the public PKI API surface. They are
 * intended to be usable across different runtime environments, including:
 * </p>
 * <ul>
 * <li>standalone CLI applications,</li>
 * <li>long-running server processes,</li>
 * <li>container-managed frameworks such as Spring or Micronaut.</li>
 * </ul>
 *
 * <p>
 * No assumptions are made about the underlying persistence mechanism
 * (filesystem, database, distributed log, etc.). Such concerns are handled by
 * SPI and implementation layers.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.pki.api.orch;
