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
 * Common algorithm infrastructure shared across multiple cryptographic
 * families.
 *
 * <p>
 * This package contains reusable building blocks and adapters that are not tied
 * to a single primitive family but are needed by several of them. It provides
 * generic JCA wrappers, abstract base classes for key builders, adapters to map
 * KEM into agreement workflows, and streaming helpers for signature engines.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Expose abstract base classes for asymmetric key generation and encoded
 * key import so that concrete algorithms can implement only variant-specific
 * details.</li>
 * <li>Provide generic JCA adapters for key agreement and signature processing
 * that integrate with the core streaming context model.</li>
 * <li>Offer thin adapters to reinterpret existing primitives (for example, KEM
 * as a two-message agreement) for higher-level composition layers.</li>
 * </ul>
 *
 * <h2>Subpackages</h2>
 * <ul>
 * <li>{@link zeroecho.core.alg.common.agreement} – generic JCA-based agreement
 * contexts and KEM-to-agreement adapters.</li>
 * <li>{@link zeroecho.core.alg.common.eddsa} – EdDSA infrastructure: abstract
 * key builders, encoded key importers, and signature contexts for Ed25519 and
 * Ed448.</li>
 * <li>{@link zeroecho.core.alg.common.sig} – streaming JCA-backed signature
 * contexts and internal stream helpers for sign/verify pipelines.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Abstract builders separate generation from import paths, and unsupported
 * operations fail fast with clear exceptions.</li>
 * <li>Contexts adapt JCA primitives into the core’s streaming model, handling
 * resource lifecycles and fixed tag lengths where applicable.</li>
 * <li>All components are designed to be composable and reusable across multiple
 * algorithms, reducing duplication and ensuring consistent behavior.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.common;
