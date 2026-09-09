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
package zeroecho.pki.api.audit;

/**
 * Immutable anchor describing the tamper-evident head of an append-only audit
 * log: the highest assigned record sequence and the record hash that closes the
 * hash chain at that point.
 *
 * <p>
 * A caller that has independently retained a trusted head (for example a
 * periodically exported checkpoint) can pass it to audit integrity verification
 * so that whole-tail truncation — which an internally consistent prefix chain
 * cannot otherwise reveal — is detected as a head mismatch. The anchor carries
 * no event payload and is safe to persist or transmit.
 * </p>
 *
 * @param sequence   highest record sequence covered by this head; {@code -1} for
 *                   an empty log
 * @param recordHash lowercase 64-hex record hash closing the chain, or
 *                   {@link #GENESIS_RECORD_HASH} for an empty log
 */
public record AuditChainHead(long sequence, String recordHash) {

    /** Chain seed used before the first record and as the empty-log head hash. */
    public static final String GENESIS_RECORD_HASH =
            "0000000000000000000000000000000000000000000000000000000000000000";

    /**
     * Validates the head anchor.
     *
     * @throws IllegalArgumentException if the sequence is below {@code -1} or the
     *                                  record hash is not lowercase 64-hex
     */
    public AuditChainHead {
        if (sequence < -1L) {
            throw new IllegalArgumentException("sequence must not be below -1");
        }
        if (recordHash == null || !recordHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("recordHash must be lowercase 64-hex");
        }
        if (sequence == -1L && !GENESIS_RECORD_HASH.equals(recordHash)) {
            throw new IllegalArgumentException("empty-log head must carry the genesis hash");
        }
    }

    /**
     * Returns the head of an empty audit log.
     *
     * @return an empty-log head (sequence {@code -1}, genesis hash)
     */
    public static AuditChainHead empty() {
        return new AuditChainHead(-1L, GENESIS_RECORD_HASH);
    }

    /**
     * Indicates whether this head describes an empty log.
     *
     * @return {@code true} if no records are covered
     */
    public boolean isEmpty() {
        return sequence == -1L;
    }
}
