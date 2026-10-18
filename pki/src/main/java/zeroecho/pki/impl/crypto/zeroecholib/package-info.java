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
/**
 * ZeroEcho-lib backed signing-provider implementation.
 *
 * <p>
 * This package contains the ZeroEcho-lib based implementation of the PKI crypto
 * boundary represented by {@link zeroecho.pki.spi.crypto.SigningProvider}. It
 * adapts PKI-facing signing requests to ZeroEcho core cryptographic execution
 * backed by {@link zeroecho.core.storage.KeyringStore}.
 * </p>
 *
 * <p>
 * The implementation resolves opaque {@link zeroecho.pki.api.KeyRef} values to
 * provider-local keyring aliases, loads the corresponding key material within
 * this boundary, performs signature generation or verification through ZeroEcho
 * core cryptographic APIs, and returns one bounded operation observation to the
 * PKI orchestration layer.
 * </p>
 *
 * <h2>Architectural role</h2>
 * <ul>
 * <li>The package acts as an implementation-side crypto boundary, not as a
 * generic public crypto API.</li>
 * <li>The provider contract remains defined in
 * {@link zeroecho.pki.spi.crypto.SigningProvider}.</li>
 * <li>Private key material is never exported outside this package
 * boundary.</li>
 * <li>Key lookup and key loading are delegated to
 * {@link zeroecho.core.storage.KeyringStore}.</li>
 * </ul>
 *
 * <h2>Execution model</h2>
 * <p>
 * The implementation executes signing inline in the caller thread and retains
 * no per-operation state. The authoritative store owns lifecycle, fencing,
 * retry, and recovery; a dispatched local operation cannot be replayed after a
 * restart and is therefore reconciled as unrecoverable.
 * </p>
 *
 * <h2>KeyRef mapping</h2>
 * <p>
 * This package supports provider-specific key reference mappings intended for
 * practical deployments, typically:
 * </p>
 * <ul>
 * <li>{@code zeroecho-lib:&lt;alias&gt;.prv} for signing,</li>
 * <li>{@code zeroecho-lib:&lt;alias&gt;.pub} for verification.</li>
 * </ul>
 *
 * <p>
 * The alias component may be a UUID string, although the package does not
 * require UUIDs unless stricter deployment policy is configured externally. PKI
 * callers must still treat {@link zeroecho.pki.api.KeyRef} as opaque and must
 * not rely on these internal parsing rules.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Private keys are materialized only inside this implementation
 * boundary.</li>
 * <li>The package must not log key references, private key material, raw
 * payload bytes, or raw signature bytes.</li>
 * <li>Supported algorithm reporting is informational and does not by itself
 * imply key availability or policy acceptance.</li>
 * <li>The assurance of the signing outcome depends on the integrity of the
 * configured keyring content and on ZeroEcho core cryptographic
 * implementations.</li>
 * </ul>
 */
package zeroecho.pki.impl.crypto.zeroecholib;
