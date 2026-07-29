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
package zeroecho.pki.api;

/**
 * Immutable container for an encoded artifact.
 *
 * <p>
 * This type intentionally carries only the {@link Encoding} and raw bytes. It
 * does not carry a media type, because DER/PEM/BINARY do not uniquely determine
 * the semantic meaning (a DER payload may represent a certificate, CSR, CRL,
 * etc.). The semantic meaning is carried by the surrounding API context.
 * </p>
 *
 * <p>
 * Security note: implementations must never log the raw bytes in full.
 * </p>
 *
 * @param encoding encoding kind
 * @param bytes    non-empty payload bytes
 */
public record EncodedObject(Encoding encoding, byte[] bytes) {

    /**
     * Creates an encoded object.
     *
     * @param encoding encoding kind
     * @param bytes    non-empty payload bytes
     * @throws IllegalArgumentException if {@code encoding} is null or {@code bytes}
     *                                  is null/empty
     */
    public EncodedObject {
        if (encoding == null) {
            throw new IllegalArgumentException("encoding must not be null");
        }
        if (bytes == null || bytes.length == 0) {
            throw new IllegalArgumentException("bytes must not be null/empty");
        }
        bytes = bytes.clone();
    }

    /**
     * Returns a defensive copy of the encoded payload.
     *
     * @return newly allocated payload copy
     */
    @Override
    public byte[] bytes() {
        return bytes.clone();
    }
}
