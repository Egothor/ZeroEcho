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
package zeroecho.pki.server.confirmation;

import java.util.Arrays;

/**
 * Bounded copied client response without a caller-selected proof-suite identity.
 *
 * <p>Access returns a copy. {@link #clear()} explicitly erases the retained bytes;
 * callers serialize access and erasure and must erase their own previously returned copies.</p>
 */
final class ProofResponseEnvelope {

    private final byte[] response;

    /**
     * Snapshots a client proof response after enforcing its suite-selected byte bound.
     *
     * @param response nonempty response bytes; copied
     * @param maximumBytes permitted response length, from 1 through 16,384 bytes inclusive
     * @throws IllegalArgumentException if the response is null, empty or exceeds the bound,
     *         or the bound is outside the supported range
     */
    /* default */ ProofResponseEnvelope(byte[] response, int maximumBytes) {
        if (maximumBytes < 1 || maximumBytes > 16_384 || response == null || response.length == 0
                || response.length > maximumBytes) {
            throw new IllegalArgumentException("Proof response has an invalid length");
        }
        this.response = response.clone();
    }

    /**
     * Copies the retained client proof response.
     *
     * @return caller-owned copy, containing zeroes after {@link #clear()}
     */
    /* default */ byte[] response() {
        return response.clone();
    }

    /**
     * Erases retained proof-response bytes; previously returned copies remain caller-owned.
     */
    /* default */ void clear() {
        Arrays.fill(response, (byte) 0);
    }
}
