/* *****************************************************************************
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
package zeroecho.pki.api.audit;

import java.util.Optional;

/**
 * Verifies the tamper-evidence of a hash-chained audit log.
 *
 * <p>An audit sink that maintains a verifiable hash chain may also expose this
 * capability so an operator or a durable cross-store anchor can confirm the log
 * has not been mutated, truncated, reordered, or rewritten. The returned
 * {@link AuditIntegrityReport} is payload-free: it carries only sequence
 * positions and hashes, never event content.</p>
 */
public interface AuditIntegrityService {

    /**
     * Verifies the audit-log hash chain, optionally against a trusted head.
     *
     * <p>When {@code expectedHead} is present, a self-consistent full rewrite is
     * detected by comparing the recomputed head to the supplied anchor; when it
     * is empty, only internal chain consistency is checked.</p>
     *
     * @param expectedHead optional trusted head anchor to compare against
     * @return payload-free integrity report
     * @throws IllegalArgumentException if {@code expectedHead} is null
     * @throws RuntimeException on storage failure
     */
    AuditIntegrityReport verifyIntegrity(Optional<AuditChainHead> expectedHead);

    /**
     * Verifies internal chain consistency and that {@code anchor} is an authentic prefix of the log.
     *
     * <p>Unlike {@link #verifyIntegrity(Optional)}, which requires the supplied head to equal the current
     * final head, this tolerates records appended after the anchored sequence (legitimate growth, including
     * after a crash restart). It fails when the anchored sequence is missing (truncation below the anchor),
     * when its record hash differs (history before the anchor was rewritten), or when the chain is internally
     * broken. A genesis anchor ({@link AuditChainHead#empty()}) is a valid prefix of any consistent chain.</p>
     *
     * @param anchor durable trusted prefix anchor from a separate store
     * @return payload-free integrity report whose observed head is the current log head
     * @throws IllegalArgumentException if {@code anchor} is null
     * @throws RuntimeException on storage failure
     */
    AuditIntegrityReport verifyAnchoredPrefix(AuditChainHead anchor);
}
