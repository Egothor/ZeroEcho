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
/**
 * Exception types used by the core to signal configuration errors and
 * unexpected provider failures.
 *
 * <p>
 * This package defines a small, clear taxonomy of exceptions thrown when
 * constructing or running cryptographic contexts. Use these types to
 * distinguish programming/configuration mistakes from lower-level provider
 * failures.
 * </p>
 *
 * <h2>Exception categories</h2>
 * <ul>
 * <li>{@link UnsupportedRoleException} - the requested
 * {@link zeroecho.core.KeyUsage} is not supported by the selected algorithm, or
 * the role is incompatible with the supplied key/spec.</li>
 * <li>{@link UnsupportedSpecException} - the provided
 * {@link zeroecho.core.spec.ContextSpec} is invalid or incompatible with the
 * requested role or key.</li>
 * <li>{@link ProviderFailureException} - an unexpected failure surfaced by an
 * underlying JCA/JCE/PQC provider; the operation cannot proceed safely.</li>
 * </ul>
 *
 * <h2>Usage notes</h2>
 * <ul>
 * <li>Treat {@link UnsupportedRoleException} and
 * {@link UnsupportedSpecException} as programming or configuration errors that
 * should be fixed by adjusting inputs.</li>
 * <li>Treat {@link ProviderFailureException} as an operational fault (provider
 * bug, environment issue); log with context and surface a safe error to
 * callers.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * try {
 *     zeroecho.core.context.EncryptionContext ctx =
 *         algo.createContext(zeroecho.core.KeyUsage.ENCRYPT, key, spec);
 *     // use ctx...
 * } catch (zeroecho.core.err.UnsupportedRoleException
 *        | zeroecho.core.err.UnsupportedSpecException e) {
 *     // programming error: wrong role or incompatible key/spec
 *     throw new IllegalArgumentException("Bad configuration", e);
 * } catch (java.io.IOException e) {
 *     // I/O failure when initializing context
 *     ...
 * } catch (zeroecho.core.err.ProviderFailureException e) {
 *     // unexpected provider failure: wrap, log, or abort
 *     ...
 * }
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho.core.err;
