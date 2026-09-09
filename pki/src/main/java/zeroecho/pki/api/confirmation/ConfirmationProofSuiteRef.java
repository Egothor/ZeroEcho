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
package zeroecho.pki.api.confirmation;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Immutable reference to one exact credential-confirmation proof-suite profile.
 *
 * @param suiteId lowercase ASCII suite identifier ending in a positive {@code .vN} version, at most 128 characters
 * @param configurationCommitment lowercase hexadecimal SHA-256 commitment of the suite configuration
 */
public record ConfirmationProofSuiteRef(String suiteId, String configurationCommitment) {
    private static final int MAXIMUM_SUITE_ID_LENGTH = 128;
    private static final Pattern CANONICAL_SUITE_ID =
            Pattern.compile("[a-z0-9][a-z0-9._-]*\\.v[1-9][0-9]*");
    private static final Pattern SHA_256 = Pattern.compile("[0-9a-f]{64}");

    /**
     * Validates the canonical suite identity and exact configuration commitment.
     *
     * @throws NullPointerException if either component is {@code null}
     * @throws IllegalArgumentException if either component is not canonical
     */
    public ConfirmationProofSuiteRef {
        Objects.requireNonNull(suiteId, "suiteId");
        Objects.requireNonNull(configurationCommitment, "configurationCommitment");
        if (suiteId.length() > MAXIMUM_SUITE_ID_LENGTH || !CANONICAL_SUITE_ID.matcher(suiteId).matches()) {
            throw new IllegalArgumentException("Confirmation proof-suite identity is not canonical");
        }
        if (!SHA_256.matcher(configurationCommitment).matches()) {
            throw new IllegalArgumentException("Confirmation proof-suite commitment is not canonical");
        }
    }
}
