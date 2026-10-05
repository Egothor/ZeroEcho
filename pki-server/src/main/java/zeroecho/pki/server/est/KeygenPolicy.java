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
package zeroecho.pki.server.est;

import java.util.List;
import java.util.Objects;

/**
 * Controls server-keygen eligibility for an EST endpoint.
 *
 * <p>Server-generated key pairs are ephemeral by default ({@link #storeGeneratedKeys} = false):
 * the server never retains a copy after the response is delivered. The operation requires
 * explicit enablement per label because it exposes private key material on the wire.</p>
 *
 * @param enabled              {@code true} iff POST {@code /serverkeygen} is allowed on this endpoint
 * @param permittedAlgorithms  JCA key algorithm names permitted for generation (e.g. {@code "RSA"}, {@code "EC"})
 * @param maximumKeySizeBits   upper bound on key size in bits; protects against memory exhaustion during generation
 * @param storeGeneratedKeys   if {@code true}, the generated private key is written to the CA's keyring (escrow)
 * @since 1.0
 */
public record KeygenPolicy(
        boolean enabled,
        List<String> permittedAlgorithms,
        int maximumKeySizeBits,
        boolean storeGeneratedKeys) {

    /** Sentinel policy for endpoints where server-side key generation is disabled. */
    public static final KeygenPolicy DISABLED = new KeygenPolicy(false, List.of(), 0, false);

    /** Validates and defensively copies all mutable fields. */
    public KeygenPolicy {
        Objects.requireNonNull(permittedAlgorithms, "permittedAlgorithms");
        permittedAlgorithms = List.copyOf(permittedAlgorithms);
        if (enabled && permittedAlgorithms.isEmpty()) {
            throw new IllegalArgumentException(
                    "KeygenPolicy: permittedAlgorithms must not be empty when enabled");
        }
        if (enabled && maximumKeySizeBits < 256) {
            throw new IllegalArgumentException(
                    "KeygenPolicy: maximumKeySizeBits must be at least 256 when enabled");
        }
    }
}
