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
 * Covert data embedding and extraction using JPEG EXIF metadata.
 *
 * <p>
 * This package provides utilities for hiding and recovering binary payloads
 * inside EXIF/TIFF fields of JPEG images. The embedder preserves existing
 * metadata where possible and distributes the payload across a caller-defined
 * sequence of slots, transparently applying Base64 for text-only tags. The
 * implementation performs lossless EXIF updates using a JPEG metadata library.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link JpegExifEmbedder} - embeds a length-prefixed binary payload into a
 * JPEG by splitting it across configured slots and writes the result using a
 * lossless EXIF rewrite; also reconstructs the payload by reading the same
 * slots in order.</li>
 * <li>{@link Slot} - an immutable description of one EXIF/TIFF field with a
 * default capacity and grouping; supports a compact specification syntax and a
 * small registry of predefined, high-capacity tags.</li>
 * </ul>
 *
 * <h2>Slot configuration</h2>
 * <p>
 * Slots identify where and in what order payload chunks are written or read.
 * They can be referenced by predefined name (for example, {@code usercomment},
 * {@code makernote}) or specified explicitly using tag metadata. The textual
 * format is:
 * </p>
 * <pre>{@code
 * [group.]name[/tag=tagId,type,count,dir][:capacity]
 * }</pre>
 * <ul>
 * <li><b>group</b>: EXIF, GPS, INTEROP, TIFF, or THUMBNAIL (default EXIF).</li>
 * <li><b>name</b>: registry key or custom tag name.</li>
 * <li><b>tag=...</b>: explicit tag definition for a custom slot.</li>
 * <li><b>capacity</b>: maximum bytes for this slot (default 1024).</li>
 * </ul>
 * <p>
 * Use {@link Slot#parse(String)} for custom definitions,
 * {@link Slot#register(String, Slot.SlotGroup, org.apache.commons.imaging.formats.tiff.taginfos.TagInfo, int)}
 * to extend the registry, and {@link Slot#defaults()} to obtain a conservative
 * default set.
 * </p>
 *
 * <h2>Payload format and processing</h2>
 * <ul>
 * <li><b>Length prefix</b>: Embedding reads the payload using a 7-bit
 * variable-length size prefix, then splits the bytes across slots in order;
 * extraction writes the same prefix back before streaming the reconstructed
 * bytes.</li>
 * <li><b>Text vs binary slots</b>: When a slot is text-only, the embedder
 * Base64-encodes the chunk before storing; binary-capable slots store raw
 * bytes.</li>
 * <li><b>Metadata preservation</b>: Existing EXIF is retained except for fields
 * explicitly overwritten by the chosen slots; updates are written
 * losslessly.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <ul>
 * <li>{@link JpegExifEmbedder} maintains a mutable, ordered slot list and is
 * not intended for concurrent reconfiguration.</li>
 * <li>{@link Slot} instances are immutable and safe to share across
 * threads.</li>
 * </ul>
 *
 * <h2>Use cases and extensions</h2>
 * <ul>
 * <li>Transport encrypted streams disguised within benign JPEG metadata.</li>
 * <li>Covert carriers for small secrets with compatibility across common image
 * tools.</li>
 * <li>Future extension: combine with exporters or steganographic pipelines in
 * other packages to automate deployment to public platforms while keeping
 * payloads concealed.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.integrations.covert.jpeg;
