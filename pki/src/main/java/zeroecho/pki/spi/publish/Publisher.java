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
package zeroecho.pki.spi.publish;

import java.util.Optional;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.publication.PublicationTarget;

/**
 * Publishes an encoded artifact to a configured publication target.
 */
public interface Publisher {

    /**
     * Returns the exact administrator-configured destination served by this instance.
     *
     * @return immutable destination identity
     */
    PublicationTarget target();

    /**
     * Publishes the payload for one durably prepared attempt.
     *
     * @param attempt exact attempt and idempotency identity
     * @param payload repeatable immutable payload; implementations must stream it
     * @return definitive classified outcome
     * @throws IllegalArgumentException if inputs are null
     * @throws RuntimeException if the outcome cannot be established; callers treat
     *         every such exception as externally unknown and discard its details
     */
    PublicationOutcome publish(PublicationAttempt attempt, RepeatableContent payload);

    /**
     * Resolves an existing unknown attempt without creating a new external effect.
     *
     * @param attempt original exact attempt identity
     * @return definitive outcome, or empty when reliable reconciliation is unsupported
     * @throws RuntimeException if the lookup outcome itself is unknown
     */
    default Optional<PublicationOutcome> reconcile(PublicationAttempt attempt) {
        return Optional.empty();
    }
}
