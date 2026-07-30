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
 * Crypto boundary SPI for the PKI module.
 *
 * <p>
 * The PKI module must never store, expose, nor directly handle private key
 * material. It operates exclusively on opaque {@link zeroecho.pki.api.KeyRef}
 * values resolved at runtime by a selected
 * {@link java.util.ServiceLoader}-driven provider.
 * </p>
 *
 * <h2>Trust boundary</h2>
 * <ul>
 * <li><strong>PKI (caller):</strong> submits sign/verify requests using
 * {@code KeyRef}, algorithm id, and payload bytes. It must not parse nor
 * interpret {@code KeyRef}.</li>
 * <li><strong>Crypto provider (callee):</strong> resolves {@code KeyRef} to an
 * internal key handle, enforces policy (including multi-hop approvals in other
 * implementations), performs crypto, and returns only non-secret outputs
 * (signature bytes or verification decision).</li>
 * </ul>
 *
 * <h2>Security constraints</h2>
 * <ul>
 * <li>{@code KeyRef} is sensitive metadata and must not be logged.</li>
 * <li>Payload bytes and signature bytes must not be logged.</li>
 * <li>Implementations must avoid persisting secrets; audit evidence must
 * contain only non-secret metadata.</li>
 * </ul>
 */
package zeroecho.pki.spi.crypto;
