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
package zeroecho.pki.application;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.math.BigInteger;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

/** Store-backed read-only repository application service. */
final class DefaultPkiRepository implements PkiRepository {
    private static final int MAX_PAGE = 1_000;
    private final PkiStore store;
    private final Runnable requireOpen;

    /* default */ DefaultPkiRepository(PkiStore store, Runnable requireOpen) {
        this.store = Objects.requireNonNull(store, "store");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    @Override public Optional<CaRecord> authority(PkiId authorityId) {
        requireOpen.run();
        return store.getCa(Objects.requireNonNull(authorityId, "authorityId"));
    }

    @Override public List<CaRecord> authorities(Optional<PkiId> afterAuthorityId, int limit) {
        requireOpen.run();
        Objects.requireNonNull(afterAuthorityId, "afterAuthorityId");
        if (limit <= 0 || limit > MAX_PAGE) {
            throw new IllegalArgumentException("limit must be between 1 and " + MAX_PAGE);
        }
        return store.listCasPage(afterAuthorityId, limit);
    }

    @Override public Optional<IssuerGeneration> issuer(PkiId issuerId) {
        requireOpen.run();
        return store.getIssuerGeneration(Objects.requireNonNull(issuerId, "issuerId"));
    }

    @Override public Optional<IssuerChainPath> chainPath(PkiId pathId) {
        requireOpen.run();
        return store.getIssuerChainPath(Objects.requireNonNull(pathId, "pathId"));
    }

    @Override public Optional<Credential> credential(PkiId credentialId) {
        requireOpen.run();
        return store.getCredential(Objects.requireNonNull(credentialId, "credentialId"));
    }

    @Override public Optional<Credential> credential(PkiId issuerId, BigInteger serial) {
        requireOpen.run();
        return store.getCredentialByIssuerAndSerial(Objects.requireNonNull(issuerId, "issuerId"),
                Objects.requireNonNull(serial, "serial"));
    }

    @Override public Optional<StatusObject> statusObject(PkiId statusObjectId) {
        requireOpen.run();
        return store.getStatusObject(Objects.requireNonNull(statusObjectId, "statusObjectId"));
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    @Override public PkiRepositoryContent openCredential(PkiId credentialId) {
        requireOpen.run();
        Credential credential = credential(credentialId).orElseThrow(() -> new PkiException("Credential not found"));
        if (!BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())) {
            throw new PkiException("Credential is not an X.509 repository object");
        }
        try {
            RepeatableContent content = store.stagedContent().openContent(credential.content());
            try {
                validateCertificate(content, credential.content().length(), credential.content().sha256());
            } catch (IOException | RuntimeException failure) {
                closeAfterValidationFailure(content, failure);
                throw failure;
            }
            return new PkiRepositoryContent(credential.credentialId(), credential.issuerRef().caId(),
                    PkiRepositoryContent.Role.CERTIFICATE, credential.content(),
                    content);
        } catch (IOException exception) {
            throw new PkiException("Credential content unavailable", exception);
        }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    @Override public PkiRepositoryContent openStatusObject(PkiId statusObjectId) {
        requireOpen.run();
        StatusObject object = statusObject(statusObjectId).orElseThrow(() -> new PkiException("Status object not found"));
        PkiRepositoryContent.Role role = object.type() == StatusObjectType.CRL
                || object.type() == StatusObjectType.DELTA_CRL ? PkiRepositoryContent.Role.CRL
                        : PkiRepositoryContent.Role.STATUS_OBJECT;
        try {
            RepeatableContent content = store.stagedContent().openContent(object.content());
            try {
                if (role == PkiRepositoryContent.Role.CRL) {
                    validateCrl(content, object.content().length(), object.content().sha256());
                }
            } catch (IOException | RuntimeException failure) {
                closeAfterValidationFailure(content, failure);
                throw failure;
            }
            return new PkiRepositoryContent(object.statusObjectId(), object.issuerCaId(), role, object.content(),
                    content);
        } catch (IOException exception) {
            throw new PkiException("Status object content unavailable", exception);
        }
    }

    private static void validateCertificate(RepeatableContent content, long expectedLength, String expectedDigest)
            throws IOException {
        byte[] bytes;
        try (InputStream input = content.openStream()) {
            bytes = input.readAllBytes();
        }
        try {
            X509Certificate certificate = Pkix.parseCertificate(bytes);
            // The certificate re-encodes to canonical DER; matching the stored length and
            // digest proves the stored bytes are a single canonical object with no trailing data.
            requireCanonical(certificate.getEncoded(), expectedLength, expectedDigest, "certificate");
        } catch (IllegalArgumentException | java.security.cert.CertificateEncodingException failure) {
            throw new IOException("Repository certificate is not canonical DER", failure);
        }
    }

    private static void validateCrl(RepeatableContent content, long expectedLength, String expectedDigest)
            throws IOException {
        byte[] bytes;
        try (InputStream input = content.openStream()) {
            bytes = input.readAllBytes();
        }
        try {
            X509CRL crl = Pkix.parseCrl(bytes);
            requireCanonical(crl.getEncoded(), expectedLength, expectedDigest, "CRL");
        } catch (IllegalArgumentException | java.security.cert.CRLException failure) {
            throw new IOException("Repository CRL is not canonical DER", failure);
        }
    }

    private static void closeAfterValidationFailure(RepeatableContent content, Throwable primary) {
        try {
            content.close();
        } catch (IOException closeFailure) {
            primary.addSuppressed(closeFailure);
        }
    }

    private static void requireCanonical(byte[] canonical, long expectedLength, String expectedDigest, String role)
            throws IOException {
        try {
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical));
            if (canonical.length != expectedLength || !MessageDigest.isEqual(
                    digest.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                    expectedDigest.getBytes(java.nio.charset.StandardCharsets.US_ASCII))) {
                throw new IOException("Repository " + role + " is not canonical DER");
            }
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
