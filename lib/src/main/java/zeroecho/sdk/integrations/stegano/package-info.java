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
 * Steganographic integrations for ZeroEcho SDK.
 *
 * <p>
 * This package provides abstractions and implementations for hiding and
 * recovering messages in digital images. Steganography allows information to be
 * concealed in carrier media so that its presence is not apparent to a casual
 * observer.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li>All algorithms implement the
 * {@link zeroecho.sdk.integrations.stegano.SteganographyMethod} interface,
 * which defines stream-oriented {@code embed} and {@code extract} operations
 * and supplies a metadata descriptor.</li>
 * <li>Supported carrier formats are represented by
 * {@link zeroecho.sdk.integrations.stegano.ImageFormat}. Only lossless formats
 * are suitable for direct bit-level embedding, but some algorithms may also
 * provide support for lossy domains such as JPEG with dedicated
 * techniques.</li>
 * <li>Methods are designed to operate on {@link java.io.InputStream} and
 * {@link java.io.OutputStream} pipelines, making them compatible with large
 * files and streaming workflows.</li>
 * </ul>
 *
 * <h2>Extensibility</h2>
 * <p>
 * The package is not limited to one specific algorithm. In addition to classic
 * spatial-domain approaches, implementors can provide methods that operate in
 * the frequency domain (for example, DCT coefficients for JPEG) or more
 * advanced hybrid techniques. New methods can be registered by implementing the
 * {@code SteganographyMethod} interface and returning appropriate
 * {@link zeroecho.sdk.integrations.stegano.StegoMetadata}.
 * </p>
 *
 * <h2>Typical workflow</h2> <pre>{@code
 * SteganographyMethod method = ...; // e.g. resolved from a registry
 * try (InputStream carrier = Files.newInputStream(Path.of("cover.png"));
 *      InputStream secret  = new ByteArrayInputStream("hello".getBytes(UTF_8));
 *      InputStream stego   = method.embed(carrier, ImageFormat.PNG, secret)) {
 *     Files.write(Path.of("stego.png"), stego.readAllBytes());
 * }
 *
 * try (InputStream stego = Files.newInputStream(Path.of("stego.png"));
 *      InputStream recovered = method.extract(stego)) {
 *     String text = new String(recovered.readAllBytes(), UTF_8);
 * }
 * }</pre>
 */
package zeroecho.sdk.integrations.stegano;