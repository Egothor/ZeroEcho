/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api;

import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;

/**
 * Versioned certificate-profile import, activation, and lookup service.
 *
 * <p>
 * Import never activates a profile. All versions of one logical profile ID
 * have one immutable certificate kind. End-entity issuance resolves only an
 * explicitly activated persisted version through
 * {@link #requireActiveProfile(String)}. Root and intermediate issuance use the
 * same authoritative active-profile lookup and bind issued credentials to the
 * exact resolved version.
 * </p>
 */
public interface ProfileService {
    /** Imports a bounded strict JSON profile document. */
    CertificateProfileRef importProfile(byte[] jsonDocument);

    /**
     * Imports a strict JSON profile document without taking ownership of the
     * supplied stream.
     */
    CertificateProfileRef importProfile(InputStream jsonDocument);

    /** Imports a built-in provisioning template through the same document path. */
    CertificateProfileRef importBuiltIn(BuiltInCertificateProfileTemplate template);

    /** Explicitly activates one already imported version. */
    CertificateProfileRef activateProfile(String profileId, long profileVersion);

    /** Resolves and validates the exact active profile. */
    ActiveCertificateProfile requireActiveProfile(String profileId);

    /** Retrieves one immutable imported version for administration. */
    Optional<ImportedCertificateProfileVersion> getImportedVersion(String profileId, long profileVersion);

    /** Lists immutable imported versions for one logical profile. */
    List<ImportedCertificateProfileVersion> listImportedVersions(String profileId);

    /** Retrieves the current active reference without activating anything. */
    Optional<CertificateProfileRef> getActiveReference(String profileId);
}
