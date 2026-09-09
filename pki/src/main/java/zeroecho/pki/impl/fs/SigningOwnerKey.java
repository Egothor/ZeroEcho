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
package zeroecho.pki.impl.fs;

import java.util.Objects;
import java.util.UUID;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;

/** Strict composite identity for one durable signing-content owner edge. */
final class SigningOwnerKey {
    /* default */ static final String NAMESPACE = "io.zeroecho.pki.signing-owner";
    private static final int CONTENT_ID_CHARACTERS = 36;
    private static final char DELIMITER = ':';

    private SigningOwnerKey() {
        // utility class
    }

    /* default */ static MetadataKey exact(DurableContentReference reference,
            PkiId submissionId) {
        Objects.requireNonNull(reference, "reference");
        return exact(reference.contentId(), submissionId);
    }

    private static MetadataKey exact(String contentId, PkiId submissionId) {
        String prefix = prefix(contentId);
        SigningSubmissionId parsed = SigningSubmissionId.parse(
                Objects.requireNonNull(submissionId, "submissionId"));
        return new MetadataKey(NAMESPACE, prefix + parsed.id().value());
    }

    /* default */ static MetadataSnapshot.KeyRange contentRange(
            DurableContentReference reference) {
        Objects.requireNonNull(reference, "reference");
        return MetadataSnapshot.KeyRange.prefix(NAMESPACE, prefix(reference.contentId()));
    }

    /* default */ static Parsed parse(MetadataKey key) {
        Objects.requireNonNull(key, "key");
        if (!NAMESPACE.equals(key.namespace())) {
            throw new IllegalArgumentException("Signing owner key namespace is invalid");
        }
        String value = key.key();
        if (value.length() <= CONTENT_ID_CHARACTERS + 1
                || value.charAt(CONTENT_ID_CHARACTERS) != DELIMITER) {
            throw new IllegalArgumentException("Signing owner key shape is invalid");
        }
        String contentId = value.substring(0, CONTENT_ID_CHARACTERS);
        requireContentId(contentId);
        PkiId submissionId = new PkiId(value.substring(CONTENT_ID_CHARACTERS + 1));
        SigningSubmissionId parsed = SigningSubmissionId.parse(submissionId);
        if (!exact(contentId, parsed.id()).equals(key)) {
            throw new IllegalArgumentException("Signing owner key is not canonical");
        }
        return new Parsed(contentId, parsed.id());
    }

    private static String prefix(String contentId) {
        requireContentId(contentId);
        return contentId + DELIMITER;
    }

    private static void requireContentId(String value) {
        Objects.requireNonNull(value, "contentId");
        UUID parsed;
        try {
            parsed = UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Signing owner content identifier is invalid", exception);
        }
        if (value.length() != CONTENT_ID_CHARACTERS || !parsed.toString().equals(value)
                || parsed.variant() != 2 || parsed.version() != 4) {
            throw new IllegalArgumentException("Signing owner content identifier is not canonical");
        }
    }

    /* default */ record Parsed(String contentId, PkiId submissionId) {
        Parsed {
            Objects.requireNonNull(contentId, "contentId");
            Objects.requireNonNull(submissionId, "submissionId");
        }
    }
}
