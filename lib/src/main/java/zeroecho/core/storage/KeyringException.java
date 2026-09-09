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
package zeroecho.core.storage;

import java.io.IOException;
import java.util.Objects;

/**
 * Redacted checked failure raised by encrypted keyring operations.
 *
 * <p>
 * The public message contains only the stable error code. Filesystem paths,
 * aliases, key material, ciphertext, and provider-controlled messages are
 * deliberately excluded.
 * </p>
 */
public final class KeyringException extends IOException {
    private static final long serialVersionUID = 1L;

    /**
     * Stable keyring failure categories.
     */
    // Stable diagnostic codes are externally inspected and must retain their exact names.
    @SuppressWarnings("PMD.LongVariable")
    public enum Code {
        /** Another process or session already owns the keyring lock. */
        KEYRING_ALREADY_OPEN,
        /** Filesystem ownership, permissions, links, or atomicity do not meet the security policy. */
        KEYRING_FILESYSTEM_UNSUPPORTED,
        /** Persisted keyring framing or authenticated metadata is invalid. */
        KEYRING_FORMAT_INVALID,
        /** A configured size, count, or derivation bound was exceeded. */
        KEYRING_LIMIT_EXCEEDED,
        /** Supplied unlock material could not authenticate the keyring. */
        KEYRING_UNLOCK_FAILED,
        /** Keyring storage I/O failed. */
        KEYRING_IO_FAILED,
        /** An update completed without confirmed durable publication. */
        KEYRING_DURABILITY_UNCONFIRMED,
        /** The requested operation used a closed keyring. */
        KEYRING_CLOSED,
        /** The requested key is intentionally non-exportable. */
        KEYRING_NON_EXPORTABLE_KEY,
        /** Imported key metadata cannot be mapped to an exact supported algorithm. */
        KEYRING_IMPORT_MAPPING_INVALID,
        /** Imported key metadata is missing, inconsistent, or malformed. */
        KEYRING_IMPORT_METADATA_INVALID,
        /** Imported key material cannot be converted to its canonical representation. */
        KEYRING_KEY_NOT_CANONICALIZABLE
    }

    /** Stable redacted category returned to callers. */
    private final Code code;

    /**
     * Creates a redacted keyring exception.
     *
     * @param code stable error code
     */
    public KeyringException(Code code) {
        super(Objects.requireNonNull(code, "code must not be null").name());
        this.code = code;
    }

    /**
     * Returns the stable error code.
     *
     * @return failure code
     */
    public Code code() {
        return code;
    }
}
