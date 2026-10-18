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
package zeroecho.pki.impl.core;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.KeyRef;

/**
 * Functional contract for resolving public key information for a
 * {@link KeyRef}.
 *
 * <p>
 * This abstraction allows the PKI core to obtain SubjectPublicKeyInfo-encoded
 * public key material without introducing a direct dependency on a concrete key
 * storage or key management implementation. Typical implementations may resolve
 * public keys from a local keyring, a hardware-backed provider, or a remote key
 * management service.
 * </p>
 *
 * <p>
 * The returned object is expected to contain the public key encoded as
 * SubjectPublicKeyInfo (SPKI) in DER form so that downstream certificate and
 * PKI components can consume it in a format-stable manner.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Only public key material may be returned by this contract.</li>
 * <li>Implementations must never expose private key material, seed material, or
 * any other secret keying material through this API.</li>
 * <li>Implementations should avoid logging raw key identifiers, resolved key
 * bytes, or storage-specific internal lookup details unless such logging is
 * explicitly approved and adequately sanitized.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Thread-safety depends on the concrete implementation. Implementations
 * intended for shared runtime use should document their concurrency guarantees
 * explicitly.
 * </p>
 */
@FunctionalInterface
public interface PublicKeyInfoResolver {

    /**
     * Resolves the subject public key information for the supplied key reference.
     *
     * <p>
     * The result must contain the public key encoded as DER-encoded
     * SubjectPublicKeyInfo. The method does not imply that the referenced key is
     * usable for any specific algorithm, certificate profile, or issuance policy;
     * it only resolves the public key representation associated with the supplied
     * {@link KeyRef}.
     * </p>
     *
     * @param keyRef opaque key reference whose associated public key information is
     *               to be resolved; must not be {@code null}
     * @return DER-encoded SubjectPublicKeyInfo for the referenced public key; never
     *         {@code null}
     * @throws IllegalArgumentException if {@code keyRef} is {@code null}
     * @throws RuntimeException         if the resolution process fails or if the
     *                                  key reference cannot be resolved by the
     *                                  underlying implementation
     */
    EncodedObject resolveSpkiDer(KeyRef keyRef);
}
