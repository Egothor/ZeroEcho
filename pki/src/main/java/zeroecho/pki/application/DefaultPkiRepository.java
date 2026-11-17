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
package zeroecho.pki.application;

import java.io.ByteArrayOutputStream;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.spi.framework.CredentialFramework;


import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.math.BigInteger;

import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;

import zeroecho.core.io.RepeatableContent;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Store-backed read-only repository application service.
 */
final class DefaultPkiRepository implements PkiRepository {
    private static final String VALUE_ORIGINAL = "original";

    private static final int MAX_PAGE = 1_000;
    private final PkiStore store;
    private final Runnable requireOpen;
    private final java.util.Map<zeroecho.pki.api.FormatId, CredentialFramework> frameworks;
    private static final int MAX_CREDENTIAL_BYTES = 1_024 * 1_024;
    private static final int MAX_EXPORT_BYTES = 2 * MAX_CREDENTIAL_BYTES + 256;

    /**
     * Binds a read-only repository without configured export frameworks.
     *
     * @param store borrowed authoritative repository store
     * @param requireOpen session lifecycle guard
     * @throws NullPointerException if an argument is null
     */
    /* default */ DefaultPkiRepository(PkiStore store, Runnable requireOpen) {
        this(store, requireOpen, List.of());
    }

    /**
     * Binds a read-only repository and indexes explicitly configured export frameworks.
     *
     * @param store borrowed authoritative repository store
     * @param requireOpen session lifecycle guard
     * @param configuredFrameworks borrowed frameworks indexed by exact format identity
     * @throws NullPointerException if an argument or required framework metadata is null
     * @throws IllegalStateException if frameworks advertise duplicate format identities
     */
    /* default */ DefaultPkiRepository(PkiStore store, Runnable requireOpen,
            List<CredentialFramework> configuredFrameworks) {
        this.frameworks = configuredFrameworks.stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                CredentialFramework::formatId, value -> value));
        this.store = Objects.requireNonNull(store, "store");
        this.requireOpen = Objects.requireNonNull(requireOpen, "requireOpen");
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<CaRecord> authority(PkiId authorityId) {
        requireOpen.run();
        return store.getCa(Objects.requireNonNull(authorityId, "authorityId"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public List<CaRecord> authorities(Optional<PkiId> afterAuthorityId, int limit) {
        requireOpen.run();
        Objects.requireNonNull(afterAuthorityId, "afterAuthorityId");
        if (limit <= 0 || limit > MAX_PAGE) {
            throw new IllegalArgumentException("limit must be between 1 and " + MAX_PAGE);
        }
        return store.listCasPage(afterAuthorityId, limit);
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<IssuerGeneration> issuer(PkiId issuerId) {
        requireOpen.run();
        return store.getIssuerGeneration(Objects.requireNonNull(issuerId, "issuerId"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<IssuerChainPath> chainPath(PkiId pathId) {
        requireOpen.run();
        return store.getIssuerChainPath(Objects.requireNonNull(pathId, "pathId"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<Credential> credential(PkiId credentialId) {
        requireOpen.run();
        return store.getCredential(Objects.requireNonNull(credentialId, "credentialId"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<Credential> credential(PkiId issuerId, BigInteger serial) {
        requireOpen.run();
        return store.getCredentialByIssuerAndSerial(Objects.requireNonNull(issuerId, "issuerId"),
                Objects.requireNonNull(serial, "serial"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public Optional<StatusObject> statusObject(PkiId statusObjectId) {
        requireOpen.run();
        return store.getStatusObject(Objects.requireNonNull(statusObjectId, "statusObjectId"));
    }

    /**
     * {@inheritDoc}
     */
    @Override public List<CredentialFramework.CredentialRepresentation> credentialRepresentations(PkiId credentialId) {
        requireOpen.run();
        Credential credential = credential(credentialId).orElseThrow(() -> new PkiException("Credential not found"));
        return representations(credential);
    }

    private List<CredentialFramework.CredentialRepresentation> representations(Credential credential) {
        CredentialFramework framework = frameworks.get(credential.formatId());
        List<CredentialFramework.CredentialRepresentation> values = List.copyOf(framework == null
                ? List.of(CredentialFramework.CredentialRepresentation.original(credential.content().encoding()))
                : framework.credentialRepresentations(credential.content().encoding()));
        if (values.isEmpty() || values.size() > 16 || values.stream().map(CredentialFramework.CredentialRepresentation::id).distinct().count() != values.size()
                || values.stream().noneMatch(value -> VALUE_ORIGINAL.equals(value.id()))) {
            throw new PkiException("Credential representation metadata is invalid");
        }
        return values;
    }

    /**
     * {@inheritDoc}
     */
    @Override public PkiRepositoryContent openCredential(PkiId credentialId, String representation,
            CancellationSignal cancellation) throws IOException {
        requireOpen.run();
        Objects.requireNonNull(representation, "representation");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        Credential credential = credential(credentialId).orElseThrow(() -> new PkiException("Credential not found"));
        CredentialFramework.CredentialRepresentation selected = representations(credential).stream().filter(value -> value.id().equals(representation)).findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("Unsupported credential representation"));
        if (credential.content().length() < 1 || credential.content().length() > MAX_CREDENTIAL_BYTES) {
            throw new IOException("Credential content exceeds export budget");
        }
        ContentTransfer ownership = new ContentTransfer(store.stagedContent().openContent(credential.content()));
        try {
            byte[] originalBytes = ContentChecks.readCredential(ownership.content(), credential, cancellation);
            CredentialFramework framework = frameworks.get(credential.formatId());
            EncodedObject original = new EncodedObject(credential.content().encoding(), originalBytes);
            EncodedObject exported = framework == null ? original : framework.exportCredential(original, representation, cancellation);
            if (exported.encoding() != selected.encoding() || exported.byteLength() > MAX_EXPORT_BYTES) {
                throw new IOException("Credential representation encoding or output budget differs");
            }
            byte[] bytes = exported.bytes();
            cancellation.throwIfCancelled();
            if (VALUE_ORIGINAL.equals(representation)) {
                if (!java.util.Arrays.equals(originalBytes, bytes)) { throw new IOException("Original credential representation changed bytes"); }
                PkiRepositoryContent lease = new PkiRepositoryContent(credentialId, credential.issuerRef().caId(), PkiRepositoryContent.Role.CERTIFICATE,
                        credential.content(), ownership.content());
                ownership.release();
                return lease;
            }
            return new PkiRepositoryContent(credentialId, credential.issuerRef().caId(), PkiRepositoryContent.Role.CERTIFICATE,
                    bytes.length, ContentChecks.digest(bytes), new ExportContent(bytes));
        } finally {
            ownership.closeIfOwned();
        }
    }





    /** Owns the current content until the caller explicitly transfers its lease. */
    private static final class ContentTransfer {
        private RepeatableContent content;
        private boolean released;

        private ContentTransfer(RepeatableContent content) { this.content = content; }
        private RepeatableContent content() { return content; }
        private void replace(RepeatableContent replacement) { content = replacement; }
        private void release() { released = true; }
        private void closeIfOwned() throws IOException {
            if (!released) { content.close(); }
        }
    }

    /** Independent immutable representation bytes with a synchronized lease lifecycle. */
    private static final class ExportContent implements RepeatableContent {
        private final byte[] bytes;
        private boolean closed;
        private final java.util.concurrent.locks.ReentrantLock lock = new java.util.concurrent.locks.ReentrantLock();
        /* default */ ExportContent(byte[] bytes) { this.bytes = bytes; }
        /**
         * {@inheritDoc}
         */
        @Override public InputStream openStream() throws IOException {
            lock.lock();
            try {
                if (closed) { throw new IOException("Credential export lease closed"); }
                return new java.io.ByteArrayInputStream(bytes);
            } finally { lock.unlock(); }
        }
        /**
         * {@inheritDoc}
         */
        @Override public OptionalLong length() { return OptionalLong.of(bytes.length); }
        /**
         * {@inheritDoc}
         */
        @Override public String contentId() { return "credential-export:" + ContentChecks.digest(bytes); }
        /**
         * {@inheritDoc}
         */
        @Override public void close() { lock.lock(); try { closed = true; } finally { lock.unlock(); } }
    }

    /**
     * {@inheritDoc}
     */
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
                ContentChecks.validateCertificate(content, credential.content().length(), credential.content().sha256());
            } catch (IOException | RuntimeException failure) {
                ContentChecks.closeAfterValidationFailure(content, failure);
                throw failure;
            }
            return new PkiRepositoryContent(credential.credentialId(), credential.issuerRef().caId(),
                    PkiRepositoryContent.Role.CERTIFICATE, credential.content(),
                    content);
        } catch (IOException exception) {
            throw new PkiException("Credential content unavailable", exception);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override public List<CredentialFramework.CredentialRepresentation> statusRepresentations(PkiId id) {
        requireOpen.run();StatusObject object=statusObject(id).orElseThrow(() -> new PkiException("Status object not found"));
        CredentialFramework framework=frameworks.get(object.formatId());
        List<CredentialFramework.CredentialRepresentation> values=List.copyOf(framework==null?List.of(CredentialFramework.CredentialRepresentation.original(object.content().encoding()))
                :framework.statusRepresentations(object.type(),object.content().encoding()));
        if(values.isEmpty()||values.size()>16||values.stream().map(CredentialFramework.CredentialRepresentation::id).distinct().count()!=values.size()
                ||values.stream().noneMatch(value -> VALUE_ORIGINAL.equals(value.id()))){ throw new PkiException("Status representation metadata is invalid"); }
        return values;
    }

    /**
     * {@inheritDoc}
     */
    @Override public PkiRepositoryContent openStatusObject(PkiId id,String representation,CancellationSignal cancellation)throws IOException {
        requireOpen.run();Objects.requireNonNull(cancellation,"cancellation").throwIfCancelled();
        StatusObject object=statusObject(id).orElseThrow(() -> new PkiException("Status object not found"));
        CredentialFramework.CredentialRepresentation selected=statusRepresentations(id).stream().filter(value -> value.id().equals(representation)).findFirst()
                .orElseThrow(() -> new UnsupportedOperationException("Status representation unavailable"));
        long nativeLimit=256L*1_024*1_024;
        if(object.content().length()<1||object.content().length()>nativeLimit){ throw new IOException("Status content exceeds download budget"); }
        ContentTransfer ownership = new ContentTransfer(store.stagedContent().openContent(object.content()));
        try {
            String nativeDigest=ContentChecks.inspectStatusStream(ownership.content(),object.content().length(),nativeLimit,cancellation);
            if(!nativeDigest.equals(object.content().sha256())){ throw new IOException("Status source integrity differs"); }
            CredentialFramework framework=frameworks.get(object.formatId());
            if(framework!=null){ ownership.replace(framework.exportStatusContent(object.type(),object.content().encoding(),ownership.content(),representation,cancellation)); }
            else if(!VALUE_ORIGINAL.equals(representation)){ throw new UnsupportedOperationException("Status representation unavailable"); }
            long length=ownership.content().length().orElseThrow(() -> new IOException("Status representation length unavailable"));
            String digest=ContentChecks.inspectStatusStream(ownership.content(),length,368L*1_024*1_024,cancellation);
            if(VALUE_ORIGINAL.equals(selected.id())&&(length!=object.content().length()||!digest.equals(object.content().sha256()))){ throw new IOException("Original status representation changed bytes"); }
            PkiRepositoryContent.Role role=object.type()==StatusObjectType.CRL||object.type()==StatusObjectType.DELTA_CRL?PkiRepositoryContent.Role.CRL:PkiRepositoryContent.Role.STATUS_OBJECT;
            PkiRepositoryContent result=new PkiRepositoryContent(id,object.issuerCaId(),role,length,digest,ownership.content());ownership.release();return result;
        } finally { ownership.closeIfOwned(); }
    }


    /**
     * {@inheritDoc}
     */
    // A validation failure must close the newly opened content before it leaves this boundary.
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
                    ContentChecks.validateCrl(content, object.content().length(), object.content().sha256());
                }
            } catch (IOException | RuntimeException failure) {
                ContentChecks.closeAfterValidationFailure(content, failure);
                throw failure;
            }
            return new PkiRepositoryContent(object.statusObjectId(), object.issuerCaId(), role, object.content(),
                    content);
        } catch (IOException exception) {
            throw new PkiException("Status object content unavailable", exception);
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
    /** Performs bounded immutable content inspection independently of repository selection. */
    private static final class ContentChecks {
    private static byte[] readCredential(RepeatableContent content, Credential credential, CancellationSignal cancellation) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (InputStream input = content.openStream()) {
            byte[] buffer = new byte[16 * 1_024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                cancellation.throwIfCancelled();
                if (read > credential.content().length() - bytes.size()) { throw new IOException("Credential content length differs"); }
                bytes.write(buffer, 0, read);
            }
        }
        byte[] exact = bytes.toByteArray();
        if (exact.length != credential.content().length() || !digest(exact).equals(credential.content().sha256())) {
            throw new IOException("Credential content integrity differs");
        }
        return exact;
    }
    private static String digest(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static String inspectStatusStream(RepeatableContent content,long expected,long maximum,CancellationSignal cancellation)throws IOException {
        if(expected<1||expected>maximum){ throw new IOException("Status representation exceeds download budget"); }
        MessageDigest digest;
        try {digest=MessageDigest.getInstance("SHA-256");}catch(NoSuchAlgorithmException impossible){throw new IllegalStateException("SHA-256 unavailable",impossible);}
        long count=0;byte[] buffer=new byte[16*1_024];
        try(InputStream input=content.openStream()) {
            int read;while((read=input.read(buffer))!=-1){cancellation.throwIfCancelled();if(read>expected-count){ throw new IOException("Status representation length differs"); }count+=read;digest.update(buffer,0,read);}
        }
        cancellation.throwIfCancelled();if(count!=expected){ throw new IOException("Status representation length differs"); }return HexFormat.of().formatHex(digest.digest());
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
        try (RepeatableContent inspection = new RepeatableContent() {
            @Override public InputStream openStream() throws IOException {
                return new BufferedInputStream(content.openStream(), 16 * 1_024);
            }
            @Override public OptionalLong length() { return content.length(); }
            @Override public String contentId() { return content.contentId(); }
            @Override public void close() {
                // Inspection owns its readers; the repository retains source ownership.
            }
        }) {
            new StreamingDerReader().inspectSignedObject(inspection, StreamingDerReader.SignedObjectKind.CRL,
                    CancellationSignal.NONE);
        }
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
        // A separate full pass binds the structurally validated, immutable bytes to
        // the durable reference without relying on a store-specific stream wrapper.
        long length = 0L;
        byte[] buffer = new byte[16 * 1_024];
        try (InputStream input = content.openStream()) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (read > expectedLength - length) {
                    throw new IOException("Repository CRL content length mismatch");
                }
                length += read;
                digest.update(buffer, 0, read);
            }
        }
        if (length != expectedLength || !HexFormat.of().formatHex(digest.digest()).equals(expectedDigest)) {
            throw new IOException("Repository CRL content integrity mismatch");
        }
    }
    private static void closeAfterValidationFailure(RepeatableContent content, Throwable primary) {
        try {
            content.close();
        } catch (IOException closeFailure) {
            primary.addSuppressed(closeFailure);
        }
    }
    }
}
