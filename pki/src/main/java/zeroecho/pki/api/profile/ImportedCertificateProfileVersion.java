/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
     * @param reference exact version reference
     * @param schemaVersion document schema version
     * @param definition validated semantic definition
     * @param canonicalJson canonical JSON document
     * @param importedAt authoritative import time
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

    /** @return exact version reference */
    public CertificateProfileRef reference() {
        return reference;
    }

    /** @return document schema version */
    public int schemaVersion() {
        return schemaVersion;
    }

    /** @return validated immutable profile definition */
    public CertificateProfileDefinition definition() {
        return definition;
    }

    /** @return defensive copy of canonical JSON */
    public byte[] canonicalJson() {
        return canonicalJson.clone();
    }

    /** @return authoritative import time */
    public Instant importedAt() {
        return importedAt;
    }

    @Override
    public boolean equals(Object other) {
        return this == other || other instanceof ImportedCertificateProfileVersion version
                && schemaVersion == version.schemaVersion
                && reference.equals(version.reference)
                && definition.equals(version.definition)
                && importedAt.equals(version.importedAt)
                && Arrays.equals(canonicalJson, version.canonicalJson);
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
