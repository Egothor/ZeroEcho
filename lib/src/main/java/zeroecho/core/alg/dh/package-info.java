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
 * Diffie-Hellman (DH) algorithm integration.
 *
 * <p>
 * This package provides the core support for Diffie-Hellman key agreement
 * within the ZeroEcho framework. It includes the algorithm descriptor, a
 * builder for generating key pairs, immutable parameter specifications, and
 * encoded key specs for import/export. The implementation favors use of
 * standardized RFC 7919 finite-field DH groups and encapsulates JCA
 * interoperability.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register the DH algorithm with a canonical identifier and declare its
 * {@link zeroecho.core.KeyUsage#AGREEMENT} capability.</li>
 * <li>Provide a builder for generating key pairs from known parameter sets or
 * ad-hoc parameter generation.</li>
 * <li>Expose predefined RFC 7919 FFDHE groups for safe parameter selection.
 * </li>
 * <li>Allow import/export of encoded keys via immutable key specs supporting
 * PKCS#8 and X.509.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>DhAlgorithm</b>: registers the algorithm under id {@code "DH"}, binds
 * agreement contexts to the JCA {@code "DiffieHellman"} implementation, and
 * wires key builders.</li>
 * <li><b>DhKeyGenBuilder</b>: generates key pairs using
 * {@link java.security.AlgorithmParameterGenerator} or supplied
 * {@link javax.crypto.spec.DHParameterSpec} instances.</li>
 * <li><b>DhSpec</b>: immutable container for DH parameters; provides static
 * factories for FFDHE groups (2048–8192 bits).</li>
 * <li><b>DhPublicKeySpec</b> and <b>DhPrivateKeySpec</b>: immutable encoded key
 * specs for importing/exporting X.509 and PKCS#8 encodings, with
 * {@link zeroecho.core.marshal.PairSeq} marshalling support.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe for reuse.</li>
 * <li>Builders are stateless; contexts produced for key agreement are not
 * thread-safe and should be used per operation.</li>
 * <li>Use of standardized groups is strongly recommended over ad-hoc parameter
 * generation for interoperability and safety.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.dh;