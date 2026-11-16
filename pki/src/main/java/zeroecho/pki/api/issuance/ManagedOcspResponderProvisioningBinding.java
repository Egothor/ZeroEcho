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

package zeroecho.pki.api.issuance;

import java.util.Objects;

/**
 * Immutable public selection used to verify provisioning slot coordinates, without exposing a key resolver.
 * @param retainedBinding exact normalized issuance target
 * @param primarySpkiSha256 lowercase SHA256 of the actual managed primary SPKI
 * @param alternativeSpkiSha256 lowercase SHA256 of the actual managed alternative SPKI
 */
public record ManagedOcspResponderProvisioningBinding(RetainedIssuanceBinding retainedBinding,
        String primarySpkiSha256, String alternativeSpkiSha256) {
    /**
     * Validates the closed immutable public tuple.
     * @param retainedBinding exact normalized issuance target
     * @param primarySpkiSha256 lowercase SHA256 of the actual managed primary SPKI
     * @param alternativeSpkiSha256 lowercase SHA256 of the actual managed alternative SPKI
     * @throws NullPointerException if retainedBinding is null
     * @throws IllegalArgumentException if a public-key digest is not canonical SHA-256 or both roles name the
     *     same public key
     */
    public ManagedOcspResponderProvisioningBinding {
        Objects.requireNonNull(retainedBinding, "retainedBinding");
        IssuanceIntent.requireDigest(primarySpkiSha256);
        IssuanceIntent.requireDigest(alternativeSpkiSha256);
        if (primarySpkiSha256.equals(alternativeSpkiSha256)) {
            throw new IllegalArgumentException("Managed responder roles require distinct public keys");
        }
    }
}
