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
package zeroecho.pki.server.spi;

/**
 * Internal transport-neutral server authentication composition boundary.
 * This unexported interface is not a public ServiceLoader extension contract.
 *
 * <p>Implementations resolve one per-request principal identity from a TLS
 * peer without inspecting operation arguments or request bodies. The result
 * is a closed, safe value that the authorization engine can act on without
 * further I/O.
 *
 * <h2>Thread safety</h2>
 * <p>Implementations must be thread-safe; the server calls
 * {@link #authenticate(PkiServerAuthenticationContext)} from multiple threads
 * concurrently for independent requests.
 *
 * @since 1.0
 */
@FunctionalInterface
public interface PkiServerAuthenticator extends AutoCloseable {
    /**
     * Authenticates one already TLS-validated peer without inspecting operation
     * arguments.
     *
     * @param context bounded trusted TLS context; never {@code null}
     * @return safe authentication result; never {@code null}
     * @throws NullPointerException if {@code context} is {@code null}
     */
    PkiServerAuthenticationResult authenticate(PkiServerAuthenticationContext context);

    /**
     * Releases optional provider resources.
     *
     * <p>The default implementation owns no closeable resources. Stateful
     * implementations may override this; repeated close calls should be
     * harmless. Checked resource failures must retain their original cause when
     * translated to I/O failures, and interrupted closure must restore interruption.</p>
     *
     * @throws java.io.IOException if a provider resource cannot be released
     */
    @Override
    default void close() throws java.io.IOException {
        // No resource by default.
    }
}
