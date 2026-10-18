/* *****************************************************************************
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
package zeroecho.pki.api.profile;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable persisted profile version and its canonical configuration bytes.
 */
public final class ImportedCertificateProfileVersion {
    private final CertificateProfileRef reference;
    private final int schemaVersion;
    private final CertificateProfileDefinition definition;
    private final byte[] canonicalJson;
    private final Instant importedAt;

    /**
     * Creates an immutable imported version.
     *
     * @param reference     exact version reference
     * @param schemaVersion document schema version
     * @param definition    validated semantic definition
     * @param canonicalJson canonical JSON document
     * @param importedAt    authoritative import time
     */
    public ImportedCertificateProfileVersion(CertificateProfileRef reference, int schemaVersion,
            CertificateProfileDefinition definition, byte[] canonicalJson, Instant importedAt) {
        this.reference = Objects.requireNonNull(reference, "reference");
        if (schemaVersion != CertificateProfileDefinition.SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported schemaVersion");
        }
        this.schemaVersion = schemaVersion;
        this.definition = Objects.requireNonNull(definition, "definition");
        Objects.requireNonNull(canonicalJson, "canonicalJson");
        if (canonicalJson.length == 0) {
            throw new IllegalArgumentException("canonicalJson must not be empty");
        }
        this.canonicalJson = canonicalJson.clone();
        this.importedAt = Objects.requireNonNull(importedAt, "importedAt");
        if (!reference.profileId().equals(definition.profileId())
                || reference.profileVersion() != definition.profileVersion()) {
            throw new IllegalArgumentException("profile reference does not match definition");
        }
    }

    /**
     * Returns the exact version reference.
     *
     * @return exact version reference
     */
    public CertificateProfileRef reference() {
        return reference;
    }

    /**
     * Returns the document schema version.
     *
     * @return document schema version
     */
    public int schemaVersion() {
        return schemaVersion;
    }

    /**
     * Returns the imported profile definition.
     *
     * @return validated immutable profile definition
     */
    public CertificateProfileDefinition definition() {
        return definition;
    }

    /**
     * Returns the canonical imported document.
     *
     * @return defensive copy of canonical JSON
     */
    public byte[] canonicalJson() {
        return canonicalJson.clone();
    }

    /**
     * Returns the authoritative import time.
     *
     * @return authoritative import time
     */
    public Instant importedAt() {
        return importedAt;
    }

    @Override
    public boolean equals(Object other) {
        return this == other
                || other instanceof ImportedCertificateProfileVersion version && schemaVersion == version.schemaVersion
                        && reference.equals(version.reference) && definition.equals(version.definition)
                        && importedAt.equals(version.importedAt) && Arrays.equals(canonicalJson, version.canonicalJson);
    }

    @Override
    public int hashCode() {
        return Objects.hash(reference, schemaVersion, definition, importedAt, Arrays.hashCode(canonicalJson));
    }

    @Override
    public String toString() {
        return "ImportedCertificateProfileVersion[reference=" + reference + ", schemaVersion=" + schemaVersion
                + ", importedAt=" + importedAt + "]";
    }
}
