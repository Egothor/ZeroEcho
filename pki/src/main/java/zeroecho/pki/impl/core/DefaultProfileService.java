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
package zeroecho.pki.impl.core;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Store-backed implementation of the certificate-profile lifecycle.
 */
public final class DefaultProfileService implements ProfileService {
    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose PROFILE_PURPOSE = new Purpose("PROFILE_LIFECYCLE");

    private final PkiStore store;
    private final Clock clock;
    private final AuditSink auditSink;

    /** Creates a profile service using one authoritative clock. */
    public DefaultProfileService(PkiStore store, Clock clock, AuditSink auditSink) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
    }

    @Override
    public CertificateProfileRef importProfile(byte[] jsonDocument) {
        Objects.requireNonNull(jsonDocument, "jsonDocument");
        return executeSanitized(() -> {
            CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(jsonDocument);
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            return importCanonical(definition, canonical, clock.instant());
        }, Code.PROFILE_IMPORT_VALIDATION_FAILED);
    }

    @Override
    public CertificateProfileRef importProfile(InputStream jsonDocument) {
        Objects.requireNonNull(jsonDocument, "jsonDocument");
        return executeSanitized(() -> {
            CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(jsonDocument);
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            return importCanonical(definition, canonical, clock.instant());
        }, Code.PROFILE_IMPORT_VALIDATION_FAILED);
    }

    @Override
    public CertificateProfileRef importBuiltIn(BuiltInCertificateProfileTemplate template) {
        Objects.requireNonNull(template, "template");
        byte[] canonical = template.canonicalJson();
        return executeSanitized(() -> {
            CertificateProfileDefinition parsed = CertificateProfileDocumentCodec.parse(canonical);
            byte[] reserialized = CertificateProfileDocumentCodec.writeCanonical(parsed);
            if (!Arrays.equals(canonical, reserialized) || !parsed.equals(template.definition())
                    || parsed.profileVersion() != template.definition().profileVersion()
                    || !parsed.profileId().equals(template.definition().profileId())
                    || !MessageDigest.isEqual(sha256(canonical), template.canonicalSha256())) {
                throw new ProfileLifecycleFailure(Code.BUILT_IN_PROFILE_INVALID);
            }
            return importProfile(canonical);
        }, Code.BUILT_IN_PROFILE_INVALID);
    }

    @Override
    public CertificateProfileRef activateProfile(String profileId, long profileVersion) {
        requireProfileId(profileId);
        if (profileVersion <= 0) {
            throw new IllegalArgumentException("profileVersion must be positive");
        }
        return executeAudited("PROFILE_ACTIVATE", profileId, profileVersion, Code.PROFILE_ACTIVATION_FAILED, () -> {
            CertificateProfileRef result = store.activateProfile(profileId, profileVersion);
            audit("PROFILE_ACTIVATE", result, "SUCCESS");
            return result;
        });
    }

    @Override
    public ActiveCertificateProfile requireActiveProfile(String profileId) {
        requireProfileId(profileId);
        return executeAudited("PROFILE_RESOLVE", profileId, 0L, Code.PROFILE_STORE_FAILURE,
                () -> store.requireActiveProfile(profileId));
    }

    @Override
    public Optional<ImportedCertificateProfileVersion> getImportedVersion(String profileId, long profileVersion) {
        requireProfileId(profileId);
        if (profileVersion <= 0) {
            throw new IllegalArgumentException("profileVersion must be positive");
        }
        return executeSanitized(() -> store.getProfileVersion(profileId, profileVersion), Code.PROFILE_STORE_FAILURE);
    }

    @Override
    public List<ImportedCertificateProfileVersion> listImportedVersions(String profileId) {
        requireProfileId(profileId);
        return executeSanitized(() -> store.listProfileVersions(profileId), Code.PROFILE_STORE_FAILURE);
    }

    @Override
    public Optional<CertificateProfileRef> getActiveReference(String profileId) {
        requireProfileId(profileId);
        return executeSanitized(() -> store.getActiveProfileRef(profileId), Code.PROFILE_STORE_FAILURE);
    }

    private CertificateProfileRef importCanonical(CertificateProfileDefinition definition, byte[] canonical,
            Instant importedAt) {
        CertificateProfileRef reference = new CertificateProfileRef(definition.profileId(), definition.profileVersion(),
                sha256(canonical));
        ImportedCertificateProfileVersion version = new ImportedCertificateProfileVersion(reference,
                CertificateProfileDefinition.SCHEMA_VERSION, definition, canonical, importedAt);
        return executeAudited("PROFILE_IMPORT", definition.profileId(), definition.profileVersion(),
                Code.PROFILE_IMPORT_FAILED, () -> {
                    ImportedCertificateProfileVersion committed = store.importProfileVersion(version);
                    String result = committed.importedAt().equals(importedAt) ? "SUCCESS" : "UNCHANGED";
                    audit("PROFILE_IMPORT", committed.reference(), result);
                    return committed.reference();
                });
    }

    private void audit(String operation, CertificateProfileRef reference, String result) {
        auditSafe(new AuditEvent(clock.instant(), "PROFILE", operation, SYSTEM_PKI, PROFILE_PURPOSE, Optional.empty(),
                Optional.empty(),
                Map.of("profileId", reference.profileId(), "profileVersion", Long.toString(reference.profileVersion()),
                        "fingerprint", reference.shortFingerprint(), "result", result)));
    }

    private void auditFailure(String operation, String profileId, long profileVersion, String code) {
        Map<String, String> details = profileVersion > 0
                ? Map.of("profileId", profileId, "profileVersion", Long.toString(profileVersion), "code", code)
                : Map.of("profileId", profileId, "code", code);
        auditSafe(new AuditEvent(clock.instant(), "PROFILE", operation + "_REJECTED", SYSTEM_PKI, PROFILE_PURPOSE,
                Optional.empty(), Optional.empty(), details));
    }

    // Audit listeners are external best-effort callbacks and cannot affect state.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void auditSafe(AuditEvent event) {
        try {
            auditSink.record(event);
        } catch (RuntimeException ignored) {
            // Best-effort audit callbacks cannot alter committed profile state.
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static void requireProfileId(String profileId) {
        if (profileId == null || profileId.isBlank()) {
            throw new IllegalArgumentException("profileId must not be null/blank");
        }
    }

    private static ProfileLifecycleFailure sanitize(RuntimeException failure, Code fallback) {
        if (failure instanceof ProfileLifecycleFailure classified) {
            return new ProfileLifecycleFailure(classified.code());
        }
        return new ProfileLifecycleFailure(fallback);
    }

    /*
     * Attacker-controlled parser and store causes are intentionally replaced by
     * stable, cause-free lifecycle failures.
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private static <T> T executeSanitized(Supplier<T> operation, Code fallback) {
        try {
            return operation.get();
        } catch (RuntimeException failure) {
            throw sanitize(failure, fallback);
        }
    }

    /*
     * This is the audited counterpart of executeSanitized; audit runs only after
     * store coordination has returned.
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private <T> T executeAudited(String operation, String profileId, long profileVersion, Code fallback,
            Supplier<T> action) {
        try {
            return action.get();
        } catch (RuntimeException failure) {
            ProfileLifecycleFailure sanitized = sanitize(failure, fallback);
            auditFailure(operation, profileId, profileVersion, sanitized.code().name());
            throw sanitized;
        }
    }
}
