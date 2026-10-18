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
 * Import never activates a profile. All versions of one logical profile ID have
 * one immutable certificate kind. End-entity issuance resolves only an
 * explicitly activated persisted version through
 * {@link #requireActiveProfile(String)}. Root and intermediate issuance use the
 * same authoritative active-profile lookup and bind issued credentials to the
 * exact resolved version.
 * </p>
 */
public interface ProfileService {
    /**
     * Imports a bounded strict JSON profile document without activating it.
     * @param jsonDocument canonical profile JSON bytes
     * @return imported immutable profile reference
     */
    CertificateProfileRef importProfile(byte[] jsonDocument);

    /**
     * Imports a strict JSON profile document without taking ownership of the
     * supplied stream.
     * @param jsonDocument bounded profile JSON stream, left open
     * @return imported immutable profile reference
     */
    CertificateProfileRef importProfile(InputStream jsonDocument);

    /**
     * Imports a built-in provisioning template through the same document path.
     * @param template versioned built-in profile template
     * @return imported immutable profile reference
     */
    CertificateProfileRef importBuiltIn(BuiltInCertificateProfileTemplate template);

    /**
     * Explicitly activates one already imported version.
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported version
     * @return exact newly active profile reference
     */
    CertificateProfileRef activateProfile(String profileId, long profileVersion);

    /**
     * Resolves and validates the exact active profile.
     * @param profileId nonblank logical profile identifier
     * @return validated immutable active profile
     */
    ActiveCertificateProfile requireActiveProfile(String profileId);

    /**
     * Retrieves one immutable imported version for administration.
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported version
     * @return imported version, or empty when absent
     */
    Optional<ImportedCertificateProfileVersion> getImportedVersion(String profileId, long profileVersion);

    /**
     * Lists immutable imported versions for one logical profile.
     * @param profileId nonblank logical profile identifier
     * @return immutable versions in ascending version order
     */
    List<ImportedCertificateProfileVersion> listImportedVersions(String profileId);

    /**
     * Retrieves the current active reference without activating anything.
     * @param profileId nonblank logical profile identifier
     * @return active reference, or empty when none is active
     */
    Optional<CertificateProfileRef> getActiveReference(String profileId);
}
