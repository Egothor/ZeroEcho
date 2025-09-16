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
 * Core cryptography engine and registry for ZeroEcho.
 *
 * <p>
 * This package defines the low-level algorithm model, discovery and registry
 * surface, capability descriptors, key usage taxonomy, and a small set of
 * helpers required by concrete cryptographic algorithms. It is intentionally
 * minimal and policy-agnostic so that higher layers can compose flows without
 * duplicating concerns defined here.
 * </p>
 *
 * <h2>Relationship to the overall library</h2>
 * <p>
 * The core provides the foundation on which the higher-level SDK composes
 * developer-facing workflows. The intent is clear separation of
 * responsibilities: the core focuses on algorithms and correctness, while the
 * SDK focuses on composition and ergonomics.
 * </p>
 *
 * <h2>Algorithm model</h2>
 * <p>
 * Algorithms are declared by implementing {@link CryptoAlgorithm} and exposing
 * canonical identifiers, human-readable names, provider names, priorities, role
 * bindings, capabilities, and key builders. Roles are enumerated by
 * {@link KeyUsage} and may be grouped by {@link AlgorithmFamily}. Each role
 * binding specifies the context to be created for that role, the accepted key
 * type, an optional specification object, and a factory used to create the
 * context instance. Capabilities are advertised through
 * {@link CryptoAlgorithm#listCapabilities()} and described by immutable
 * {@link Capability} descriptors.
 * </p>
 *
 * <h2>Discovery and registry</h2>
 * <p>
 * Algorithms are discovered through standard Java provider mechanisms and
 * indexed by canonical identifier. The facade {@link CryptoAlgorithms} offers:
 * </p>
 * <ul>
 * <li>Lookup of algorithms by identifier and family.</li>
 * <li>Creation of role-specific contexts using supplied keys and optional
 * specifications.</li>
 * <li>Enumeration utilities for tooling and documentation.</li>
 * </ul>
 *
 * <h2>Selection and catalogs</h2>
 * <p>
 * Utility types such as {@link CatalogSelector} assist with filtering available
 * algorithms by family and required roles. For documentation, validation, or
 * export, {@link CryptoCatalog} can build a snapshot of the registry and
 * serialize metadata for external consumers.
 * </p>
 *
 * <h2>Transient parameters and sentinels</h2>
 * <p>
 * Algorithms that exchange ephemeral parameters at runtime can use typed keys
 * from {@link ConfluxKeys}. When an API requires a key reference but no secret
 * exists, {@link NullKey#INSTANCE} can be supplied as a sentinel. Symmetric
 * algorithms that need to prepend or parse a compact header for IVs, tag sizes,
 * or other runtime fields may implement the optional SPI
 * {@link SymmetricHeaderCodec}.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li>Stratification: the core concentrates on algorithms and correctness;
 * higher layers provide composition.</li>
 * <li>Composability: predictable, chainable behavior across contexts and
 * builders.</li>
 * <li>Extensibility: new algorithms, formats, and flows can be added with
 * minimal impact.</li>
 * <li>Safety: explicit roles and clear intent around key usage and algorithm
 * capabilities.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core;
