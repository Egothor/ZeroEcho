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
package zeroecho.core.spi;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;

/**
 * Trusted-code declaration of an installed cryptographic execution domain.
 *
 * <p>
 * A capability describes implementation availability; it never defines
 * algorithm identity, X.509 semantics, defaults, or policy. Implementations must
 * provide a stable semantic fingerprint for deterministic conflict diagnostics.
 * Administrative configuration cannot provide implementation classes.
 * </p>
 */
public interface AlgorithmExecutionCapability {

    /**
     * Supported execution direction.
     */
    enum Direction {
        /** Signature generation. */
        SIGN,
        /** Signature verification. */
        VERIFY
    }

    /**
     * Returns a stable installed implementation identifier.
     *
     * @return namespaced provider implementation identifier
     */
    String implementationId();

    /**
     * Returns a deterministic description of the supported typed domain.
     *
     * @return stable non-secret domain fingerprint
     */
    String domainFingerprint();

    /**
     * Tests whether this implementation supports an exact identity and suite.
     *
     * @param identity  requested exact operation identity
     * @param suite     complete key and signature suite
     * @param direction requested direction
     * @return {@code true} only for tuples implemented exactly
     */
    boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction);
}
