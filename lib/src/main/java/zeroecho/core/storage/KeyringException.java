/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.io.IOException;
import java.util.Objects;

/**
 * Redacted checked failure raised by encrypted keyring operations.
 *
 * <p>The public message contains only the stable error code. Filesystem paths,
 * aliases, key material, ciphertext, and provider-controlled messages are
 * deliberately excluded.</p>
 */
public final class KeyringException extends IOException {
    private static final long serialVersionUID = 1L;

    /**
     * Stable keyring failure categories.
     */
    public enum Code {
        KEYRING_ALREADY_OPEN,
        KEYRING_FILESYSTEM_UNSUPPORTED,
        KEYRING_FORMAT_INVALID,
        KEYRING_LIMIT_EXCEEDED,
        KEYRING_UNLOCK_FAILED,
        KEYRING_IO_FAILED,
        KEYRING_DURABILITY_UNCONFIRMED,
        KEYRING_CLOSED,
        KEYRING_NON_EXPORTABLE_KEY,
        KEYRING_IMPORT_MAPPING_INVALID,
        KEYRING_IMPORT_METADATA_INVALID,
        KEYRING_KEY_NOT_CANONICALIZABLE
    }

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
