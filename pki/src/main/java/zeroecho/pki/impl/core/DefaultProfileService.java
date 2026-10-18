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
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
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
    private final X509AlgorithmBindingRegistry algorithmBindings;
    private final boolean signingConfigured;
    private final Optional<String> certificateBinding;
    private final Optional<String> crlBinding;
    private final Optional<String> publicKeyBinding;

    /**
     * Creates a profile service using one authoritative clock.
     * @param store authoritative PKI store
     * @param clock authoritative lifecycle clock
     * @param auditSink audit destination
     */
    public DefaultProfileService(PkiStore store, Clock clock, AuditSink auditSink) {
        this(store, clock, auditSink, defaultBindings());
    }

    /**
     * Creates a profile service bound to one immutable algorithm registry.
     *
     * @param store authoritative PKI store
     * @param clock authoritative clock
     * @param auditSink audit sink
     * @param algorithmBindings active immutable binding registry
     */
    public DefaultProfileService(PkiStore store, Clock clock, AuditSink auditSink,
            X509AlgorithmBindingRegistry algorithmBindings) {
        this(store, clock, auditSink, algorithmBindings, false, Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * Creates a profile service with the session's explicit signing bindings.
     * @param store authoritative PKI store
     * @param clock authoritative lifecycle clock
     * @param auditSink audit destination
     * @param algorithmBindings active immutable binding registry
     * @param signingConfigured whether signing capabilities are enabled
     * @param certificateBinding optional explicit certificate-signature binding
     * @param crlBinding optional explicit CRL-signature binding
     * @param publicKeyBinding optional explicit subject-public-key binding
     */
    public DefaultProfileService(PkiStore store, Clock clock, AuditSink auditSink,
            X509AlgorithmBindingRegistry algorithmBindings, boolean signingConfigured,
            Optional<String> certificateBinding, Optional<String> crlBinding, Optional<String> publicKeyBinding) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.algorithmBindings = Objects.requireNonNull(algorithmBindings, "algorithmBindings");
        this.signingConfigured = signingConfigured;
        this.certificateBinding = Objects.requireNonNull(certificateBinding, "certificateBinding");
        this.crlBinding = Objects.requireNonNull(crlBinding, "crlBinding");
        this.publicKeyBinding = Objects.requireNonNull(publicKeyBinding, "publicKeyBinding");
    }

    @Override
    public CertificateProfileRef importProfile(byte[] jsonDocument) {
        Objects.requireNonNull(jsonDocument, "jsonDocument");
        return executeSanitized(() -> {
            CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(jsonDocument);
            validateBindings(definition);
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
            return importCanonical(definition, canonical, clock.instant());
        }, Code.PROFILE_IMPORT_VALIDATION_FAILED);
    }

    @Override
    public CertificateProfileRef importProfile(InputStream jsonDocument) {
        Objects.requireNonNull(jsonDocument, "jsonDocument");
        return executeSanitized(() -> {
            CertificateProfileDefinition definition = CertificateProfileDocumentCodec.parse(jsonDocument);
            validateBindings(definition);
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
            ImportedCertificateProfileVersion version = store.getProfileVersion(profileId, profileVersion)
                    .orElseThrow(() -> new ProfileLifecycleFailure(Code.PROFILE_VERSION_NOT_FOUND));
            validateBindings(version.definition());
            validateRuntimeBindings(version.definition());
            CertificateProfileRef result = store.activateProfile(profileId, profileVersion);
            audit("PROFILE_ACTIVATE", result, "SUCCESS");
            return result;
        });
    }

    @Override
    public ActiveCertificateProfile requireActiveProfile(String profileId) {
        requireProfileId(profileId);
        return executeAudited("PROFILE_RESOLVE", profileId, 0L, Code.PROFILE_STORE_FAILURE, () -> {
            ActiveCertificateProfile active = store.requireActiveProfile(profileId);
            validateBindings(active.definition());
            validateRuntimeBindings(active.definition());
            return active;
        });
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

    private void validateBindings(CertificateProfileDefinition definition) {
        definition.requireSupportedIssuance();
        X509AlgorithmBindingPolicy policy = definition.algorithmBindingPolicy();
        if (policy.mode() == X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY) {
            return;
        }
        validateBinding(policy.subjectPublicKey(), X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY);
        validateBinding(policy.csrSignature(), X509AlgorithmBinding.Role.CSR_SIGNATURE);
        validateBinding(policy.certificateSignature(), X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE);
        validateBinding(policy.crlSignature(), X509AlgorithmBinding.Role.CRL_SIGNATURE);
    }

    private void validateBinding(Optional<X509AlgorithmBindingPolicy.BindingReference> reference,
            X509AlgorithmBinding.Role role) {
        reference.ifPresent(value -> {
            X509AlgorithmBinding binding = algorithmBindings.require(value.bindingId(), value.semanticCommitment());
            if (binding.role() != role || binding.origin() == X509AlgorithmBinding.Origin.STANDARD) {
                throw new IllegalArgumentException("Explicit profile binding is invalid for its role");
            }
        });
    }

    private void validateRuntimeBindings(CertificateProfileDefinition definition) {
        if (!signingConfigured) {
            return;
        }
        X509AlgorithmBindingPolicy policy = definition.algorithmBindingPolicy();
        if (policy.mode() == X509AlgorithmBindingPolicy.Mode.STANDARD_ONLY) {
            if (certificateBinding.isPresent() || crlBinding.isPresent() || publicKeyBinding.isPresent()) {
                throw new IllegalArgumentException("Standard profile cannot use private runtime bindings");
            }
            return;
        }
        requireRuntimeBinding(policy.certificateSignature(), certificateBinding);
        requireRuntimeBinding(policy.subjectPublicKey(), publicKeyBinding);
        if (policy.crlSignature().isPresent()) {
            requireRuntimeBinding(policy.crlSignature(), crlBinding);
        }
    }

    private static void requireRuntimeBinding(Optional<X509AlgorithmBindingPolicy.BindingReference> selected,
            Optional<String> configured) {
        if (selected.isEmpty() || configured.isEmpty()
                || !selected.orElseThrow().bindingId().equals(configured.orElseThrow())) {
            throw new IllegalArgumentException("Profile binding does not match the signing runtime");
        }
    }

    private static X509AlgorithmBindingRegistry defaultBindings() {
        List<X509AlgorithmBinding> descriptors = new java.util.ArrayList<>(
                zeroecho.pki.impl.framework.x509.StandardX509Bindings.descriptors());
        descriptors.addAll(zeroecho.pki.impl.framework.x509.ZeroEchoPrivateX509Bindings.descriptors());
        return zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry.create(descriptors);
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
