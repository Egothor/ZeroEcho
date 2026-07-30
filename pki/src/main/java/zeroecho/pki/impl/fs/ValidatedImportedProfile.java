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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.impl.ProfileLifecycleFailure;
import zeroecho.pki.impl.ProfileLifecycleFailure.Code;

/**
 * Validated immutable imported profile artifact.
 *
 * @param version strictly decoded and canonically verified version
 */
record ValidatedImportedProfile(ImportedCertificateProfileVersion version) {

    /*
     * Strict decoding may throw several runtime parsing failures. The persisted
     * bytes and their causes must not cross this boundary.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    /* default */ static ValidatedImportedProfile decode(byte[] artifact) {
        try {
            ImportedCertificateProfileVersion decoded = FsCodec.decode(FsCodec.PROFILE_VERSION, artifact);
            return validate(decoded, decoded.reference().profileId(), decoded.reference().profileVersion());
        } catch (ProfileLifecycleFailure failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw versionCorrupt();
        }
    }

    /*
     * Strict decoding may throw several runtime parsing failures. The persisted
     * bytes and their causes must not cross this boundary.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    /* default */ static ValidatedImportedProfile decode(byte[] artifact, String profileId, long profileVersion) {
        try {
            ImportedCertificateProfileVersion decoded = FsCodec.decode(FsCodec.PROFILE_VERSION, artifact);
            return validate(decoded, profileId, profileVersion);
        } catch (ProfileLifecycleFailure failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw versionCorrupt();
        }
    }

    /*
     * Policy constructors and the strict document codec expose multiple runtime
     * failures, all deliberately normalized without input-bearing causes.
     */
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace" })
    /* default */ static ValidatedImportedProfile validate(ImportedCertificateProfileVersion version, String profileId,
            long profileVersion) {
        try {
            byte[] storedCanonical = version.canonicalJson();
            requireDocumentBounds(storedCanonical);
            CertificateProfileDefinition parsed = CertificateProfileDocumentCodec.parse(storedCanonical);
            byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(parsed);
            byte[] expectedHash = sha256(canonical);
            requireCanonicalIdentity(version, profileId, profileVersion, storedCanonical, parsed, canonical);
            if (!MessageDigest.isEqual(expectedHash, version.reference().canonicalSha256())) {
                throw hashMismatch();
            }
            return new ValidatedImportedProfile(version);
        } catch (ProfileLifecycleFailure failure) {
            throw failure;
        } catch (RuntimeException failure) {
            throw versionCorrupt();
        }
    }

    private static void requireDocumentBounds(byte[] canonicalJson) {
        if (canonicalJson.length == 0
                || canonicalJson.length > CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES) {
            throw versionCorrupt();
        }
    }

    private static void requireCanonicalIdentity(ImportedCertificateProfileVersion version, String profileId,
            long profileVersion, byte[] storedCanonical, CertificateProfileDefinition parsed, byte[] canonical) {
        if (!Arrays.equals(canonical, storedCanonical) || !parsed.equals(version.definition())
                || !profileId.equals(version.reference().profileId())
                || profileVersion != version.reference().profileVersion() || !profileId.equals(parsed.profileId())
                || profileVersion != parsed.profileVersion()
                || version.schemaVersion() != CertificateProfileDefinition.SCHEMA_VERSION) {
            throw versionCorrupt();
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static ProfileLifecycleFailure versionCorrupt() {
        return new ProfileLifecycleFailure(Code.PROFILE_VERSION_CORRUPT);
    }

    private static ProfileLifecycleFailure hashMismatch() {
        return new ProfileLifecycleFailure(Code.PROFILE_HASH_MISMATCH);
    }
}
