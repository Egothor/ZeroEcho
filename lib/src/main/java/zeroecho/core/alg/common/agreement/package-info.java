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
 * Adapters and generic contexts for key agreement built on the core SPI.
 *
 * <p>
 * This package provides a generic JCA-backed agreement context and a thin
 * adapter that exposes a KEM as a message-based agreement primitive. The goal
 * is to keep provider-specific details encapsulated while presenting clear
 * roles and lifecycles that higher layers can compose.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Expose a generic agreement context that delegates to the JCA
 * {@code KeyAgreement} API for algorithms such as ECDH and XDH.</li>
 * <li>Adapt KEM contexts to a two-message agreement API suitable for initiator/
 * responder protocols.</li>
 * <li>Preserve clear separation between algorithm descriptors, runtime
 * contexts, and higher-level composition utilities.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>GenericJcaAgreementContext</b>: an
 * {@link zeroecho.core.context.AgreementContext} backed by
 * {@link javax.crypto.KeyAgreement}; constructed with a local private key and
 * configured using a JCA algorithm name and optional provider.</li>
 * <li><b>KemMessageAgreementAdapter</b>: a
 * {@link zeroecho.core.context.MessageAgreementContext} built on a
 * {@link zeroecho.core.context.KemContext}, modeling initiator/responder roles
 * and exchanging a single peer message (ciphertext) when required.</li>
 * </ul>
 *
 * <h2>Lifecycle and usage notes</h2>
 * <ul>
 * <li>Agreement contexts should be created with the correct local key and
 * configured before deriving secrets; KDF application remains the caller's
 * responsibility.</li>
 * <li>KEM-based adapters encapsulate or decapsulate depending on role and
 * memoize results for repeated reads within a single exchange.</li>
 * <li>Instances are not thread-safe; synchronize externally if they are
 * shared.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.common.agreement;
