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
package zeroecho.pki.api.orch;

/**
 * Durability policy for workflow continuation data managed by orchestrators.
 *
 * <p>
 * Orchestrators coordinate long-running operations (e.g., human approvals,
 * remote signing, certificate issuance). Some workflows require local
 * continuation state to resume after a JVM restart. This enum defines how such
 * state is handled.
 * </p>
 *
 * <h2>Examples</h2>
 * <ul>
 * <li>A remote signature workflow may wait for hours. If the remote system is
 * the source of truth and all necessary data can be re-derived from external
 * references (operation ID, request ID), the workflow can run in a durable mode
 * without storing sensitive material locally.</li>
 * <li>If a workflow requires local ephemeral secrets (e.g., a one-time approval
 * challenge that cannot be recomputed), strict mode should abort on restart
 * (fail-closed) unless encrypted persistence is configured.</li>
 * </ul>
 */
public enum OrchestrationDurabilityPolicy {

    /**
     * Fail-closed behavior.
     *
     * <p>
     * The orchestrator does not persist continuation state that would be required
     * to resume the workflow after a process restart. If the process restarts,
     * operations that cannot be safely resumed must be cancelled or marked as
     * failed deterministically.
     * </p>
     *
     * <p>
     * Example: A workflow requires an ephemeral secret that is only available in
     * memory. In this mode, the operation is aborted on restart and the client must
     * resubmit.
     * </p>
     */
    STRICT_ABORT_ON_RESTART,

    /**
     * Durable operation using minimal non-sensitive state.
     *
     * <p>
     * The orchestrator persists only references and non-sensitive continuation
     * state, sufficient to resume the workflow after restart. Sensitive payloads
     * must remain outside the local state (e.g., in dedicated stores or remote
     * systems).
     * </p>
     *
     * <p>
     * Example: An operation persists a reference to a stored CSR and a reference to
     * the selected certificate profile, but does not persist raw key material or
     * private tokens.
     * </p>
     */
    DURABLE_MIN_STATE,

    /**
     * Durable operation with encrypted continuation state.
     *
     * <p>
     * The orchestrator persists continuation state encrypted (e.g., AES-256/GCM)
     * using a key supplied by external configuration (environment variable, secret
     * store, or KMS). This allows workflows to resume after restart even when they
     * require sensitive local state.
     * </p>
     *
     * <p>
     * Example: A workflow stores an encrypted blob containing a transient approval
     * context. The encryption uses authenticated data derived from operation ID,
     * operation type, and owner identity to prevent swapping blobs across
     * operations.
     * </p>
     */
    DURABLE_ENCRYPTED_STATE
}
