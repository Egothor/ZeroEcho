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
package zeroecho.pki.impl;

import zeroecho.pki.api.PkiException;

/**
 * Internal typed classification for redacted profile lifecycle failures.
 */
public final class ProfileLifecycleFailure extends PkiException {
    private static final long serialVersionUID = -6689413907385449245L;

    /** Closed profile lifecycle failure codes. */
    // These names are emitted as stable sanitized failure codes and asserted by external callers.
    @SuppressWarnings("PMD.LongVariable")
    public enum Code {
        /** Supplied profile document is structurally or semantically invalid. */
        PROFILE_DOCUMENT_INVALID,
        /** Imported profile failed closed validation. */
        PROFILE_IMPORT_VALIDATION_FAILED,
        /** A built-in profile definition is invalid. */
        BUILT_IN_PROFILE_INVALID,
        /** An existing profile version has different canonical content. */
        PROFILE_VERSION_CONFLICT,
        /** Versions of one logical profile disagree on certificate kind. */
        PROFILE_KIND_CONFLICT,
        /** Persisted profile-version metadata is corrupt. */
        PROFILE_VERSION_CORRUPT,
        /** Persisted active-profile pointer is corrupt. */
        PROFILE_ACTIVE_POINTER_CORRUPT,
        /** Persisted content does not match its profile hash. */
        PROFILE_HASH_MISMATCH,
        /** Profile storage operation failed. */
        PROFILE_STORE_FAILURE,
        /** Store could not confirm durable profile persistence. */
        PROFILE_DURABILITY_UNCONFIRMED,
        /** Profile import failed without a more specific classification. */
        PROFILE_IMPORT_FAILED,
        /** Persisted profile lifecycle state is inconsistent. */
        PROFILE_STATE_CORRUPT,
        /** Requested imported profile version does not exist. */
        PROFILE_VERSION_NOT_FOUND,
        /** Profile activation failed. */
        PROFILE_ACTIVATION_FAILED,
        /** No active version exists for the requested profile. */
        PROFILE_NOT_ACTIVE,
        // Stable public code is intentionally longer than PMD's naming threshold.
        /** Historical activation evidence is unavailable or invalid. */
        @SuppressWarnings("PMD.LongVariable")
        PROFILE_ACTIVATION_HISTORY_UNAVAILABLE
    }

    /** Stable sanitized failure classification. */
    private final Code code;

    /**
     * Creates one cause-free failure with a stable code.
     *
     * @param code stable sanitized failure classification
     */
    public ProfileLifecycleFailure(Code code) {
        super("Profile lifecycle operation failed: code=" + code);
        this.code = code;
    }

    /**
     * Returns the stable failure classification.
     *
     * @return stable sanitized code
     */
    public Code code() {
        return code;
    }
}
