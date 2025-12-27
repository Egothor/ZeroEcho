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
package zeroecho.pki.api.attr;

import java.util.List;
import java.util.Map;

/**
 * Structured, human-facing documentation metadata for an attribute definition.
 *
 * <p>
 * This metadata is intended to be rendered in operator tooling, APIs, and UI.
 * It must not contain secrets.
 * </p>
 *
 * @param description normative description of meaning and usage
 * @param notes       additional guidance and security considerations
 * @param examples    example values (must not contain secrets)
 * @param tags        classification tags (e.g., "identity", "x509", "san")
 * @param extra       additional annotations for future extensions
 *                    (non-sensitive)
 */
public record AttributeMeta(String description, List<String> notes, List<String> examples, List<String> tags,
        Map<String, String> extra) {

    /**
     * Creates attribute metadata.
     *
     * @throws IllegalArgumentException if inputs are invalid or collections/maps
     *                                  are null
     */
    public AttributeMeta {
        if (description == null || description.isBlank()) {
            throw new IllegalArgumentException("description must not be null/blank");
        }
        if (notes == null) {
            throw new IllegalArgumentException("notes must not be null");
        }
        if (examples == null) {
            throw new IllegalArgumentException("examples must not be null");
        }
        if (tags == null) {
            throw new IllegalArgumentException("tags must not be null");
        }
        if (extra == null) {
            throw new IllegalArgumentException("extra must not be null");
        }
    }
}
