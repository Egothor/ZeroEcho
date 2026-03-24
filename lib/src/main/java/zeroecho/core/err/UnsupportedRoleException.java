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
package zeroecho.core.err;

/**
 * Exception indicating that an algorithm does not support the requested role.
 *
 * <p>
 * This is thrown when a {@link zeroecho.core.CryptoAlgorithm} (or helpers such
 * as {@link zeroecho.core.CryptoAlgorithms}) is asked to create a context for a
 * {@link zeroecho.core.KeyUsage} that the algorithm never advertises. In other
 * words, the operation is unavailable regardless of the provided key or spec.
 * </p>
 *
 * <h2>When it is thrown</h2>
 * <ul>
 * <li>During
 * {@link zeroecho.core.CryptoAlgorithms#create(String, zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)}
 * after policy validation, if the resolved algorithm exposes no bindings for
 * the given role.</li>
 * <li>Directly from
 * {@link zeroecho.core.CryptoAlgorithm#create(zeroecho.core.KeyUsage, java.security.Key, zeroecho.core.spec.ContextSpec)}
 * when no binding exists for the role.</li>
 * </ul>
 *
 * <p>
 * Contrast with {@link UnsupportedSpecException}, which means the role exists
 * but no binding accepts the supplied key/spec types.
 * </p>
 *
 * <h2>Example</h2> <pre>{@code
 * // Suppose "SHA-256" supports DIGEST only.
 * var algo = zeroecho.core.CryptoAlgorithms.require("SHA-256");
 * try {
 *     // Asking for ENCRYPT on a digest algorithm will fail with UnsupportedRoleException.
 *     zeroecho.core.CryptoAlgorithms.create("SHA-256", zeroecho.core.KeyUsage.ENCRYPT,
 *         zeroecho.core.NullKey.INSTANCE, null);
 * } catch (UnsupportedRoleException e) {
 *     // Handle: algorithm does not implement the ENCRYPT role.
 * }
 * }</pre>
 *
 * @since 1.0
 */
public class UnsupportedRoleException extends RuntimeException {
    private static final long serialVersionUID = 1653286859112182562L;

    /**
     * Creates a new exception with a detail message.
     *
     * @param m detail message describing the missing role for the algorithm
     */
    public UnsupportedRoleException(String m) {
        super(m);
    }
}
