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
package zeroecho.pki.cli;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationValue;

/** Explicit stable operation-name to typed-request binding registry. */
@SuppressWarnings("PMD.UnusedFormalParameter")
final class PkiOperationRegistry {

    private static final String CREDENTIAL_ID = "credentialId";
    private static final String FORMAT_ID = "formatId";
    private static final String ISSUER_CA_ID = "issuerCaId";
    private static final String LIMIT = "limit";
    private static final String PUBLICATION_ID = "publicationId";
    private static final String PROFILE_FILE = "profileFile";
    private static final String PROFILE_ID = "profileId";
    private static final String PROFILE_VERSION = "profileVersion";
    private static final String REQUEST_ID = "requestId";
    private static final int MAXIMUM_REQUEST_BYTES = 1024 * 1024;

    private final Map<String, Binding> bindings;

    /* default */ PkiOperationRegistry() {
        Map<String, Binding> configured = new LinkedHashMap<>();
        add(configured, PkiOperation.ValidateConfiguration.NAME, this::configuration);
        add(configured, PkiOperation.ValidateProfile.NAME, this::profile);
        add(configured, PkiOperation.RegisterProfile.NAME, this::registerProfile);
        add(configured, PkiOperation.InspectProfile.NAME, this::inspectProfile);
        add(configured, PkiOperation.ListProfileVersions.NAME, this::listProfiles);
        add(configured, PkiOperation.ActivateProfile.NAME, this::activateProfile);
        add(configured, PkiOperation.InspectAuthority.NAME, this::inspectAuthority);
        add(configured, PkiOperation.ListAuthorities.NAME, this::listAuthorities);
        add(configured, PkiOperation.CreateAuthority.NAME, this::createAuthority);
        add(configured, PkiOperation.TransitionAuthority.NAME, this::transitionAuthority);
        add(configured, PkiOperation.InspectRequest.NAME, this::inspectRequest);
        add(configured, PkiOperation.ImportRequest.NAME, this::importRequest);
        add(configured, PkiOperation.VerifyRequest.NAME, this::verifyRequest);
        add(configured, PkiOperation.InspectCredential.NAME, this::credential);
        add(configured, PkiOperation.IssueCredential.NAME, this::issueCredential);
        add(configured, PkiOperation.RevokeCredential.NAME, this::revoke);
        add(configured, PkiOperation.InspectRevocation.NAME, this::inspectRevocation);
        add(configured, PkiOperation.ReadRevocationHistory.NAME, this::history);
        add(configured, PkiOperation.SnapshotRevocations.NAME, this::snapshotRevocations);
        add(configured, PkiOperation.InspectStatus.NAME, this::inspectStatus);
        add(configured, PkiOperation.ListStatus.NAME, this::listStatus);
        add(configured, PkiOperation.GenerateStatus.NAME, this::generateStatus);
        add(configured, PkiOperation.InspectPublication.NAME, this::publication);
        add(configured, PkiOperation.ListPublications.NAME, this::listPublications);
        add(configured, PkiOperation.RegisterPublication.NAME, this::registerPublication);
        add(configured, PkiOperation.ProcessPublication.NAME, this::processPublication);
        add(configured, PkiOperation.RetryPublication.NAME, this::retryPublication);
        add(configured, PkiOperation.ReconcilePublication.NAME, this::reconcilePublication);
        bindings = Map.copyOf(configured);
    }

    /* default */ Set<String> names() {
        return bindings.keySet();
    }

    /* default */ PkiOperation bind(String name, PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        Binding binding = bindings.get(name);
        if (binding == null) {
            throw new IllegalArgumentException("Unknown PKI operation");
        }
        return binding.bind(arguments, baseDirectory);
    }

    private PkiOperation configuration(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of());
        return new PkiOperation.ValidateConfiguration();
    }

    private PkiOperation profile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException {
        requireFields(arguments, Set.of(PROFILE_FILE));
        Path path = resolve(baseDirectory, text(arguments, PROFILE_FILE));
        byte[] document = PkiCliFiles.readRegularFile(path, CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
        return new PkiOperation.ValidateProfile(document);
    }

    private PkiOperation registerProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        requireFields(arguments, Set.of(PROFILE_FILE));
        Path path = resolve(baseDirectory, text(arguments, PROFILE_FILE));
        byte[] document = PkiCliFiles.readRegularFile(path, CertificateProfileDocumentCodec.MAXIMUM_DOCUMENT_BYTES);
        return new PkiOperation.RegisterProfile(document);
    }

    private PkiOperation inspectProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID, PROFILE_VERSION));
        return new PkiOperation.InspectProfile(text(arguments, PROFILE_ID), integer(arguments, PROFILE_VERSION));
    }

    private PkiOperation listProfiles(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID));
        return new PkiOperation.ListProfileVersions(text(arguments, PROFILE_ID));
    }

    private PkiOperation activateProfile(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PROFILE_ID, PROFILE_VERSION));
        return new PkiOperation.ActivateProfile(text(arguments, PROFILE_ID), integer(arguments, PROFILE_VERSION));
    }

    private PkiOperation inspectAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("caId"));
        return new PkiOperation.InspectAuthority(new PkiId(text(arguments, "caId")));
    }

    private PkiOperation listAuthorities(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(LIMIT));
        return new PkiOperation.ListAuthorities(limit(arguments));
    }

    private PkiOperation createAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(FORMAT_ID, "subjectRef", PROFILE_ID, "keyRef"));
        return new PkiOperation.CreateAuthority(new FormatId(text(arguments, FORMAT_ID)),
                new SubjectRef(text(arguments, "subjectRef")), text(arguments, PROFILE_ID),
                new KeyRef(text(arguments, "keyRef")));
    }

    private PkiOperation transitionAuthority(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("caId", "state", "reason"));
        return new PkiOperation.TransitionAuthority(new PkiId(text(arguments, "caId")),
                CaState.valueOf(text(arguments, "state")), text(arguments, "reason"));
    }

    private PkiOperation inspectRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(REQUEST_ID));
        return new PkiOperation.InspectRequest(new PkiId(text(arguments, REQUEST_ID)));
    }

    private PkiOperation importRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory)
            throws IOException {
        requireFields(arguments, Set.of(FORMAT_ID, "encoding", "requestFile"));
        Path path = resolve(baseDirectory, text(arguments, "requestFile"));
        byte[] document = PkiCliFiles.readRegularFile(path, MAXIMUM_REQUEST_BYTES);
        return new PkiOperation.ImportRequest(new FormatId(text(arguments, FORMAT_ID)),
                new EncodedObject(Encoding.valueOf(text(arguments, "encoding")), document));
    }

    private PkiOperation verifyRequest(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(REQUEST_ID));
        return new PkiOperation.VerifyRequest(new PkiId(text(arguments, REQUEST_ID)));
    }

    private PkiOperation credential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.InspectCredential(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiOperation issueCredential(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_CA_ID, REQUEST_ID, PROFILE_ID));
        return new PkiOperation.IssueCredential(new PkiId(text(arguments, ISSUER_CA_ID)),
                new PkiId(text(arguments, REQUEST_ID)), text(arguments, PROFILE_ID));
    }

    private PkiOperation revoke(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, "reason"));
        RevocationReason reason = RevocationReason.valueOf(text(arguments, "reason"));
        return new PkiOperation.RevokeCredential(new PkiId(text(arguments, CREDENTIAL_ID)), reason);
    }

    private PkiOperation history(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID, LIMIT));
        return new PkiOperation.ReadRevocationHistory(new PkiId(text(arguments, CREDENTIAL_ID)), limit(arguments));
    }

    private PkiOperation inspectRevocation(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(CREDENTIAL_ID));
        return new PkiOperation.InspectRevocation(new PkiId(text(arguments, CREDENTIAL_ID)));
    }

    private PkiOperation snapshotRevocations(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(LIMIT));
        return new PkiOperation.SnapshotRevocations(limit(arguments));
    }

    private PkiOperation inspectStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of("statusObjectId"));
        return new PkiOperation.InspectStatus(new PkiId(text(arguments, "statusObjectId")));
    }

    private PkiOperation listStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_CA_ID, LIMIT));
        return new PkiOperation.ListStatus(new PkiId(text(arguments, ISSUER_CA_ID)), limit(arguments));
    }

    private PkiOperation generateStatus(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(ISSUER_CA_ID, "type", FORMAT_ID));
        return new PkiOperation.GenerateStatus(new PkiId(text(arguments, ISSUER_CA_ID)),
                StatusObjectType.valueOf(text(arguments, "type")), new FormatId(text(arguments, FORMAT_ID)));
    }

    private PkiOperation publication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(PUBLICATION_ID));
        return new PkiOperation.InspectPublication(new PkiId(text(arguments, PUBLICATION_ID)));
    }

    private PkiOperation listPublications(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments, Set.of(LIMIT));
        return new PkiOperation.ListPublications(limit(arguments));
    }

    private PkiOperation registerPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        requireFields(arguments,
                Set.of(PUBLICATION_ID, "sourceType", "sourceId", "targetType", "targetId"));
        PublicationTarget target = new PublicationTarget(PublicationTargetType.valueOf(text(arguments, "targetType")),
                text(arguments, "targetId"));
        return new PkiOperation.RegisterPublication(new PkiId(text(arguments, PUBLICATION_ID)),
                PublicationSourceType.valueOf(text(arguments, "sourceType")),
                new PkiId(text(arguments, "sourceId")), target);
    }

    private PkiOperation processPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.ProcessPublication(publicationId(arguments));
    }

    private PkiOperation retryPublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.RetryPublication(publicationId(arguments));
    }

    private PkiOperation reconcilePublication(PkiOperationValue.ObjectValue arguments, Path baseDirectory) {
        return new PkiOperation.ReconcilePublication(publicationId(arguments));
    }

    private static PkiId publicationId(PkiOperationValue.ObjectValue arguments) {
        requireFields(arguments, Set.of(PUBLICATION_ID));
        return new PkiId(text(arguments, PUBLICATION_ID));
    }

    private static void add(Map<String, Binding> target, String name, Binding binding) {
        if (target.putIfAbsent(name, binding) != null) {
            throw new IllegalStateException("Duplicate PKI operation identity");
        }
    }

    private static void requireFields(PkiOperationValue.ObjectValue arguments, Set<String> expected) {
        if (!arguments.fields().keySet().equals(expected)) {
            throw new IllegalArgumentException("PKI operation arguments are invalid");
        }
    }

    private static String text(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.text(PkiCliConfiguration.required(arguments, name));
    }

    private static long integer(PkiOperationValue.ObjectValue arguments, String name) {
        return PkiCliConfiguration.integer(PkiCliConfiguration.required(arguments, name));
    }

    private static int limit(PkiOperationValue.ObjectValue arguments) {
        return Math.toIntExact(integer(arguments, LIMIT));
    }

    private static Path resolve(Path baseDirectory, String value) {
        Path supplied = Path.of(value);
        return (supplied.isAbsolute() ? supplied : baseDirectory.resolve(supplied)).toAbsolutePath().normalize();
    }

    /** One explicit typed binding. */
    @FunctionalInterface
    private interface Binding {
        /** Binds validated structured arguments to one typed operation. */
        PkiOperation bind(PkiOperationValue.ObjectValue arguments, Path baseDirectory) throws IOException;
    }
}
