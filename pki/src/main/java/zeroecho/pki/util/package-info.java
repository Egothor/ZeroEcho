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
 * Utility types and helper functions for ZeroEcho PKI.
 *
 * <p>
 * This package contains small, focused utility components that support the PKI
 * domain model and its surrounding infrastructure without introducing
 * additional domain semantics. Utilities provided here are intended to be:
 * </p>
 * <ul>
 * <li>deterministic and side-effect free,</li>
 * <li>safe to use across different runtime environments,</li>
 * <li>independent of persistence, networking, or cryptographic providers.</li>
 * </ul>
 *
 * <h2>Package structure</h2>
 * <p>
 * The package is intentionally shallow at its top level and consists of:
 * </p>
 * <ul>
 * <li>A single direct utility class: {@link zeroecho.pki.util.PkiIds PkiIds},
 * which provides helper methods for creation and handling of PKI identifiers in
 * a consistent and deterministic manner.</li>
 * <li>Several subordinate utility subpackages, each grouping helpers for a
 * specific technical concern (e.g. formatting, validation, or internal
 * conventions), without polluting the top-level namespace.</li>
 * </ul>
 *
 * <h2>Design principles</h2>
 * <p>
 * Utilities in this package follow strict design rules:
 * </p>
 * <ul>
 * <li>no global mutable state,</li>
 * <li>no hidden caching with externally visible effects,</li>
 * <li>no dependency on environment-specific configuration,</li>
 * <li>no leakage of sensitive material (keys, secrets, plaintext).</li>
 * </ul>
 *
 * <p>
 * Where randomness or uniqueness is required (e.g. identifier generation), the
 * semantics are explicitly documented and predictable within the guarantees of
 * the underlying platform.
 * </p>
 *
 * <h2>Relation to other layers</h2>
 * <p>
 * This package is deliberately orthogonal to:
 * </p>
 * <ul>
 * <li>API domain packages (such as {@code zeroecho.pki.api.*}),</li>
 * <li>SPI and implementation layers,</li>
 * <li>application bootstrap and orchestration code.</li>
 * </ul>
 *
 * <p>
 * As such, utilities defined here may be freely reused by API, SPI, and
 * implementation code without creating circular dependencies or architectural
 * coupling.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.pki.util;
