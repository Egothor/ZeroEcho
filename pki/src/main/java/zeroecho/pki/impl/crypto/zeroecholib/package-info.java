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
/**
 * Reference crypto boundary provider backed by ZeroEcho lib and
 * {@code KeyringStore}.
 *
 * <p>
 * This provider resolves {@link zeroecho.pki.api.KeyRef} values to key aliases
 * managed by {@code zeroecho.core.storage.KeyringStore}. Private key material
 * is never returned to PKI; it is materialized only inside the provider
 * implementation to perform signing.
 * </p>
 *
 * <h2>KeyRef mapping</h2>
 * <p>
 * This provider supports simple mappings intended for practical deployments:
 * </p>
 * <ul>
 * <li>{@code zeroecho-lib:&lt;alias&gt;.prv} for signing</li>
 * <li>{@code zeroecho-lib:&lt;alias&gt;.pub} for verification</li>
 * </ul>
 *
 * <p>
 * The alias component may be a UUID string (recommended). The provider does not
 * require UUIDs by default, but a stricter mode can be enabled by
 * configuration.
 * </p>
 *
 * <h2>Configuration</h2>
 * <ul>
 * <li>{@code keyringPath} (required): path to the KeyringStore text file</li>
 * <li>{@code keyRefPrefix} (optional, default {@code "zeroecho-lib:"})</li>
 * <li>{@code requireComponentSuffix} (optional, default {@code true}): require
 * {@code .prv}/{@code .pub}</li>
 * </ul>
 */
package zeroecho.pki.impl.crypto.zeroecholib;
