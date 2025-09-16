/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.err;

/**
 * Exception indicating that a provided key/spec combination is not supported by
 * the algorithm for the requested role.
 *
 * <p>
 * This is thrown by {@link zeroecho.core.CryptoAlgorithm#create} when:
 * </p>
 * <ul>
 * <li>The algorithm supports the requested {@link zeroecho.core.KeyUsage} role,
 * but none of its bindings accept the given {@link java.security.Key} and
 * {@code ContextSpec} type.</li>
 * <li>The provided {@code spec} is incompatible with the key type or context
 * expected by the binding.</li>
 * </ul>
 *
 * <p>
 * Unlike {@link UnsupportedRoleException}, which signals that a role is
 * completely unavailable for an algorithm, this exception means that the role
 * exists but cannot be realized with the supplied parameters.
 * </p>
 *
 * <h2>Example</h2> <pre>{@code
 * CryptoAlgorithm aes = CryptoAlgorithms.require("AES/GCM");
 * SecretKey wrongKey = ... // an RSA key by mistake
 * try {
 *     aes.create(KeyUsage.ENCRYPT, wrongKey, null);
 * } catch (UnsupportedSpecException e) {
 *     // no binding accepted the RSA key for ENCRYPT role
 * }
 * }</pre>
 *
 * @since 1.0
 */
public class UnsupportedSpecException extends RuntimeException {
    private static final long serialVersionUID = -4569004728562695244L;

    /**
     * Creates a new exception with the given message.
     *
     * @param m detail message describing the rejected key/spec combination
     */
    public UnsupportedSpecException(String m) {
        super(m);
    }
}
