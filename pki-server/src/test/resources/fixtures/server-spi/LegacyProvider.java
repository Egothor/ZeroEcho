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

package legacy.spi;
import java.util.Set;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.server.spi.AcmeChallengeProvider;

/** Compiled against the pre-change server artifact for binary compatibility validation. */
public final class LegacyProvider implements AcmeChallengeProvider {
    public String id() { return "legacy-challenge"; }
    public Set<AcmeState.ChallengeType> challengeTypes() { return Set.of(AcmeState.ChallengeType.DNS_01); }
    public Result validate(Context context, ProviderConfig configuration, CancellationSignal cancellation) {
        Context copied = new Context(context.directoryId(), context.authorizationId(), context.identifier(),
                context.challengeType(), context.token(), context.expectedKeyAuthorization(), context.attempt(),
                context.validationTime(), context.deadline());
        if (!copied.identifier().wildcard() || copied.attempt() != 3 || cancellation.isCancelled()) {
            throw new AssertionError("Legacy context binding changed");
        }
        return new Result(true, "LEGACY_VERIFIED", copied.validationTime(), copied.deadline());
    }
}
