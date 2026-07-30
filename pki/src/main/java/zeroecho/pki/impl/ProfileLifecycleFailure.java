/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl;

import zeroecho.pki.api.PkiException;

/**
 * Internal typed classification for redacted profile lifecycle failures.
 */
public final class ProfileLifecycleFailure extends PkiException {
    private static final long serialVersionUID = -6689413907385449245L;

    /** Closed profile lifecycle failure codes. */
    public enum Code {
        PROFILE_DOCUMENT_INVALID,
        PROFILE_IMPORT_VALIDATION_FAILED,
        BUILT_IN_PROFILE_INVALID,
        PROFILE_VERSION_CONFLICT,
        PROFILE_KIND_CONFLICT,
        PROFILE_VERSION_CORRUPT,
        PROFILE_ACTIVE_POINTER_CORRUPT,
        PROFILE_HASH_MISMATCH,
        PROFILE_STORE_FAILURE,
        PROFILE_DURABILITY_UNCONFIRMED,
        PROFILE_IMPORT_FAILED,
        PROFILE_STATE_CORRUPT,
        PROFILE_VERSION_NOT_FOUND,
        PROFILE_ACTIVATION_FAILED,
        PROFILE_NOT_ACTIVE,
        // Stable public code is intentionally longer than PMD's naming threshold.
        @SuppressWarnings("PMD.LongVariable")
        PROFILE_ACTIVATION_HISTORY_UNAVAILABLE
    }

    private final Code code;

    /** Creates one cause-free failure with a stable code. */
    public ProfileLifecycleFailure(Code code) {
        super("Profile lifecycle operation failed: code=" + code);
        this.code = code;
    }

    /** @return stable failure classification */
    public Code code() {
        return code;
    }
}
