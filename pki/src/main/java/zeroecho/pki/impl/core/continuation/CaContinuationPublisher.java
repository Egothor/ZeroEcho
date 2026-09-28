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
package zeroecho.pki.impl.core.continuation;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.DomainContinuationStore;

/** Publishes frozen root and intermediate CA continuations. */
final class CaContinuationPublisher {
    private static final String CREATE_ROOT = "CREATE_ROOT";
    private static final String CREATE_INTERMEDIATE = "CREATE_INTERMEDIATE";
    private static final String ROLLOVER_ROOT = "ROLLOVER_ROOT";
    private static final String ROLLOVER_INTERMEDIATE = "ROLLOVER_INTERMEDIATE";
    private final PkiStore store;
    private final DomainContinuationPublisher support;

    /* default */ CaContinuationPublisher(PkiStore store, DomainContinuationPublisher support) {
        this.store = java.util.Objects.requireNonNull(store, "store");
        this.support = java.util.Objects.requireNonNull(support, "support");
    }

    /* default */ void publish(DomainCommandEncoding.Decoded command, EncodedObject result,
            DomainContinuationStore.Record domain) {
        if (CREATE_ROOT.equals(command.operation())) {
            publishRoot(command, result, domain);
        } else if (ROLLOVER_ROOT.equals(command.operation())) {
            publishRootRollover(command, result, domain);
        } else if (CREATE_INTERMEDIATE.equals(command.operation())
                || "ISSUE_INTERMEDIATE".equals(command.operation())
                || ROLLOVER_INTERMEDIATE.equals(command.operation())) {
            publishIntermediate(command, result, domain);
        } else {
            throw new DomainContinuationPublisher.PostconditionFailure("CA_OPERATION_INVALID");
        }
    }

    // A root rollover/rotation re-signs the CA's own subject and advances the existing CA to the new
    // generation. Field 13 retains the existing authority instead of deriving a new one.
    private void publishRootRollover(DomainCommandEncoding.Decoded command, EncodedObject result,
            DomainContinuationStore.Record domain) {
        command.requireFields(14);
        RootCommand frozen = RootCommand.decode(command);
        PkiId authorityId = new PkiId(command.field(13));
        X509Certificate certificate = support.certificate(result);
        validateRoot(certificate, frozen.serial(), frozen.notBefore(), frozen.notAfter());
        byte[] der = result.bytes();
        try {
            String certificateHash = support.sha256(der);
            PkiId credentialId = new PkiId("x509:" + certificateHash);
            PkiId issuerId = IssuerGeneration.idFor(authorityId, credentialId);
            IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(credentialId));
            String profileCommitment = HexFormat.of().formatHex(frozen.profile().canonicalSha256());
            IssuerGeneration generation = new IssuerGeneration(issuerId, authorityId, credentialId, frozen.keyRef(),
                    IssuerGenerationState.ACTIVE, profileCommitment, profileCommitment);
            RootTargets targets = new RootTargets(credentialId, authorityId, issuerId, path.pathId(),
                    support.sha256SubjectPublicKey(certificate));
            requireExactPrefix(credentialId, issuerId, path.pathId(), authorityId, false);
            publishRootCredential(frozen, der, targets, domain);
            putOrRequireGeneration(generation);
            putOrRequirePath(path);
            advanceExistingCa(authorityId, issuerId, path.pathId(), frozen.keyRef());
        } finally {
            java.util.Arrays.fill(der, (byte) 0);
        }
    }

    private void publishRoot(DomainCommandEncoding.Decoded command, EncodedObject result,
            DomainContinuationStore.Record domain) {
        command.requireFields(14);
        RootCommand frozen = RootCommand.decode(command);
        X509Certificate certificate = support.certificate(result);
        validateRoot(certificate, frozen.serial(), frozen.notBefore(), frozen.notAfter());
        byte[] der = result.bytes();
        try {
            publishRootRecords(frozen, new RootPublication(certificate, der), domain);
        } finally {
            java.util.Arrays.fill(der, (byte) 0);
        }
    }

    private static void validateRoot(X509Certificate certificate, BigInteger serial,
            Instant notBefore, Instant notAfter) {
        if (!certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())
                || !certificate.getSerialNumber().equals(serial)
                || !certificate.getNotBefore().toInstant().equals(notBefore)
                || !certificate.getNotAfter().toInstant().equals(notAfter)) {
            throw new DomainContinuationPublisher.PostconditionFailure("ROOT_CERTIFICATE_DIFFERS");
        }
        try {
            certificate.verify(certificate.getPublicKey());
        } catch (java.security.GeneralSecurityException malformed) {
            throw new DomainContinuationPublisher.PostconditionFailure("ROOT_CERTIFICATE_INVALID", malformed);
        }
    }

    private void publishRootRecords(RootCommand frozen, RootPublication publication,
            DomainContinuationStore.Record domain) {
        String certificateHash = support.sha256(publication.der());
        PkiId credentialId = new PkiId("x509:" + certificateHash);
        PkiId authorityId = frozen.authorityId();
        PkiId issuerId = IssuerGeneration.idFor(authorityId, credentialId);
        IssuerChainPath path = IssuerChainPath.create(authorityId, issuerId, List.of(credentialId));
        String publicKeyFingerprint = support.sha256SubjectPublicKey(publication.certificate());
        String profileCommitment = HexFormat.of().formatHex(frozen.profile().canonicalSha256());
        IssuerGeneration generation = new IssuerGeneration(issuerId, authorityId, credentialId, frozen.keyRef(),
                IssuerGenerationState.ACTIVE, profileCommitment, profileCommitment);
        CaRecord authority = new CaRecord(authorityId, CaKind.ROOT, CaState.ACTIVE, frozen.keyRef(), frozen.subject(),
                List.of(issuerId), issuerId, path.pathId());
        RootTargets targets = new RootTargets(credentialId, authorityId, issuerId, path.pathId(),
                publicKeyFingerprint);
        requireExactPrefix(credentialId, issuerId, path.pathId(), authorityId, true);
        publishRootCredential(frozen, publication.der(), targets, domain);
        putOrRequireGeneration(generation);
        putOrRequirePath(path);
        putOrRequireCa(authority);
    }

    private DurableContentReference publishRootCredential(RootCommand frozen, byte[] der, RootTargets targets,
            DomainContinuationStore.Record domain) {
        java.util.Optional<Credential> existing = store.getCredential(targets.credentialId());
        if (existing.isPresent()) {
            Credential expected = rootCredential(frozen, existing.orElseThrow().content(), targets);
            support.requireCredential(existing.orElseThrow(), expected, der);
            store.putCredentialFromSigning(expected, domain.operationId(), domain.commandCommitment());
            return existing.orElseThrow().content();
        }
        DurableContentReference content = support.persist(der);
        boolean published = false;
        try {
            store.putCredentialFromSigning(rootCredential(frozen, content, targets),
                    domain.operationId(), domain.commandCommitment());
            published = true;
            DomainContinuationPublisher.afterDurablePublication(
                    DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL);
            return content;
        } finally {
            support.releaseUnlessPublished(content, published);
        }
    }

    private static Credential rootCredential(RootCommand frozen, DurableContentReference content,
            RootTargets targets) {
        return new Credential(targets.credentialId(), frozen.format(),
                new IssuerRef(targets.authorityId(), targets.issuerId(), targets.pathId()), frozen.subject(),
                new Validity(frozen.notBefore(), frozen.notAfter()), frozen.serial().toString(),
                new PkiId("spki:" + targets.publicKeyFingerprint()),
                new CaProfileBinding(frozen.profile()), CredentialStatus.ISSUED, content,
                SimpleAttributeSet.builder().build());
    }

    private void publishIntermediate(DomainCommandEncoding.Decoded command, EncodedObject result,
            DomainContinuationStore.Record domain) {
        command.requireFields(23);
        IntermediateCommand frozen = IntermediateCommand.decode(command);
        IssuerGeneration parentGeneration = store.getIssuerGeneration(frozen.parentIssuerId())
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure("PARENT_ISSUER_UNAVAILABLE"));
        IssuerChainPath parentPath = store.getIssuerChainPath(frozen.parentPathId())
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure("PARENT_PATH_UNAVAILABLE"));
        DomainContinuationPublisher.requireFrozenIssuer(parentGeneration, parentPath, frozen.issuerCaId(),
                frozen.parentIssuerId(), frozen.parentPathCommitment());
        X509Certificate certificate = support.certificate(result);
        try {
            byte[] tbs = certificate.getTBSCertificate();
            if (tbs.length != ManagedKeyProofCommand.positiveLength(command.field(21), 1_048_576)
                    || !zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment.sha256(tbs).sha256().equals(command.field(22))) {
                throw new DomainContinuationPublisher.PostconditionFailure("INTERMEDIATE_TBS_DIFFERS");
            }
        } catch (java.security.cert.CertificateEncodingException malformed) {
            throw new DomainContinuationPublisher.PostconditionFailure("INTERMEDIATE_TBS_INVALID", malformed);
        }
        DomainContinuationPublisher.requireIssuedMetadata(certificate, frozen.serial(), frozen.notBefore(),
                frozen.notAfter(), frozen.publicKeyFingerprint());
        Credential issuerCredential = store.getCredential(parentGeneration.credentialId())
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure("PARENT_CREDENTIAL_UNAVAILABLE"));
        support.verifyIssuerSignature(certificate, issuerCredential.content());
        byte[] der = result.bytes();
        try {
            publishIntermediateRecords(command.operation(), frozen, parentPath, der, domain);
        } finally {
            java.util.Arrays.fill(der, (byte) 0);
        }
    }

    private void publishIntermediateRecords(String operation, IntermediateCommand frozen,
            IssuerChainPath parentPath, byte[] der, DomainContinuationStore.Record domain) {
        PkiId credentialId = new PkiId("x509:" + support.sha256(der));
        PkiId subjectIssuerId = IssuerGeneration.idFor(frozen.subjectCaId(), credentialId);
        List<PkiId> chain = new ArrayList<>(parentPath.orderedCredentialIds().size() + 1);
        chain.add(credentialId);
        chain.addAll(parentPath.orderedCredentialIds());
        IssuerChainPath subjectPath = IssuerChainPath.create(frozen.subjectCaId(), subjectIssuerId, chain);
        String profileCommitment = HexFormat.of().formatHex(frozen.profile().canonicalSha256());
        IssuerGeneration generation = new IssuerGeneration(subjectIssuerId, frozen.subjectCaId(),
                credentialId, frozen.subjectKeyRef(), IssuerGenerationState.ACTIVE,
                profileCommitment, profileCommitment);
        boolean createAuthority = CREATE_INTERMEDIATE.equals(operation);
        requireExactPrefix(credentialId, subjectIssuerId, subjectPath.pathId(), frozen.subjectCaId(),
                createAuthority);
        publishIntermediateCredential(frozen, der, credentialId, domain);
        putOrRequireGeneration(generation);
        putOrRequirePath(subjectPath);
        publishIntermediateCa(operation, frozen, subjectIssuerId, subjectPath.pathId());
    }

    private void publishIntermediateCredential(IntermediateCommand frozen, byte[] der, PkiId credentialId,
            DomainContinuationStore.Record domain) {
        java.util.Optional<Credential> existing = store.getCredential(credentialId);
        if (existing.isPresent()) {
            Credential expected = intermediateCredential(frozen, existing.orElseThrow().content(), credentialId);
            support.requireCredential(existing.orElseThrow(), expected, der);
            store.putCredentialFromSigning(expected, domain.operationId(), domain.commandCommitment());
            return;
        }
        DurableContentReference content = support.persist(der);
        boolean published = false;
        try {
            store.putCredentialFromSigning(intermediateCredential(frozen, content, credentialId),
                    domain.operationId(), domain.commandCommitment());
            published = true;
            DomainContinuationPublisher.afterDurablePublication(
                    DomainContinuationPublisher.PublicationFaultPoint.AFTER_CREDENTIAL);
        } finally {
            support.releaseUnlessPublished(content, published);
        }
    }

    private static Credential intermediateCredential(IntermediateCommand frozen,
            DurableContentReference content, PkiId credentialId) {
        return new Credential(credentialId, frozen.format(),
                new IssuerRef(frozen.issuerCaId(), frozen.parentIssuerId(), frozen.parentPathId()), frozen.subject(),
                new Validity(frozen.notBefore(), frozen.notAfter()), frozen.serial().toString(),
                new PkiId("spki:" + frozen.publicKeyFingerprint()), new CaProfileBinding(frozen.profile()),
                CredentialStatus.ISSUED, content, SimpleAttributeSet.builder().build());
    }

    private void publishIntermediateCa(String operation, IntermediateCommand frozen,
            PkiId subjectIssuerId, PkiId subjectPathId) {
        if (CREATE_INTERMEDIATE.equals(operation)) {
            putOrRequireCa(new CaRecord(frozen.subjectCaId(), CaKind.INTERMEDIATE, CaState.ACTIVE,
                    frozen.subjectKeyRef(), frozen.subject(), List.of(subjectIssuerId),
                    subjectIssuerId, subjectPathId));
            return;
        }
        if (ROLLOVER_INTERMEDIATE.equals(operation)) {
            advanceExistingCa(frozen.subjectCaId(), subjectIssuerId, subjectPathId, frozen.subjectKeyRef());
            return;
        }
        CaRecord current = store.getCa(frozen.subjectCaId())
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure("SUBJECT_CA_UNAVAILABLE"));
        if (current.kind() != CaKind.INTERMEDIATE) {
            throw new DomainContinuationPublisher.PostconditionFailure("SUBJECT_CA_AUTHORITY_DIFFERS");
        }
        if (current.issuerIds().contains(subjectIssuerId)) {
            return;
        }
        if (current.state() != CaState.ACTIVE || !current.issuerKeyRef().equals(frozen.subjectKeyRef())) {
            throw new DomainContinuationPublisher.PostconditionFailure("SUBJECT_CA_AUTHORITY_DIFFERS");
        }
        List<PkiId> issuerIds = new ArrayList<>(current.issuerIds());
        issuerIds.add(subjectIssuerId);
        if (!store.replaceCa(current, new CaRecord(current.caId(), current.kind(), current.state(),
                current.issuerKeyRef(), current.subjectRef(), issuerIds,
                current.currentIssuanceIssuerId(), current.issuanceChainPathId()))) {
            throw new IllegalStateException("CA publication changed concurrently");
        }
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA);
    }

    private void requireExactPrefix(PkiId credentialId, PkiId issuerId, PkiId pathId,
            PkiId authorityId, boolean createdByContinuation) {
        boolean credential = store.getCredential(credentialId).isPresent();
        boolean generation = store.getIssuerGeneration(issuerId).isPresent();
        boolean path = store.getIssuerChainPath(pathId).isPresent();
        java.util.Optional<CaRecord> authority = store.getCa(authorityId);
        boolean finalAuthorityStep = createdByContinuation
                ? authority.isPresent()
                : authority.filter(value -> value.issuerIds().contains(issuerId)).isPresent();
        if (!credential && (generation || path || finalAuthorityStep)
                || !generation && (path || finalAuthorityStep)
                || !path && finalAuthorityStep) {
            throw new DomainContinuationPublisher.PostconditionFailure("CA_PUBLICATION_PREFIX_INVALID");
        }
    }

    private void putOrRequireGeneration(IssuerGeneration expected) {
        java.util.Optional<IssuerGeneration> existing = store.getIssuerGeneration(expected.issuerId());
        if (existing.isPresent()) {
            if (!existing.orElseThrow().equals(expected)) {
                throw new DomainContinuationPublisher.PostconditionFailure("PUBLISHED_ISSUER_DIFFERS");
            }
            return;
        }
        store.putIssuerGeneration(expected);
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_ISSUER_GENERATION);
    }

    private void putOrRequirePath(IssuerChainPath expected) {
        java.util.Optional<IssuerChainPath> existing = store.getIssuerChainPath(expected.pathId());
        if (existing.isPresent()) {
            if (!existing.orElseThrow().equals(expected)) {
                throw new DomainContinuationPublisher.PostconditionFailure("PUBLISHED_PATH_DIFFERS");
            }
            return;
        }
        store.putIssuerChainPath(expected);
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CHAIN_PATH);
    }

    // Exact credential ownership, generation and path have already been checked. Membership
    // therefore proves this publication step finished even after later administrative changes.
    private void advanceExistingCa(PkiId caId, PkiId issuerId, PkiId pathId, KeyRef keyRef) {
        CaRecord current = store.getCa(caId)
                .orElseThrow(() -> new DomainContinuationPublisher.PostconditionFailure("ROLLOVER_CA_UNAVAILABLE"));
        if (current.issuerIds().contains(issuerId)) {
            return;
        }
        if (current.state() != CaState.ACTIVE) {
            throw new DomainContinuationPublisher.PostconditionFailure("ROLLOVER_CA_NOT_ACTIVE");
        }
        List<PkiId> issuerIds = new ArrayList<>(current.issuerIds());
        issuerIds.add(issuerId);
        if (!store.replaceCa(current, new CaRecord(caId, current.kind(), current.state(), keyRef, current.subjectRef(),
                issuerIds, issuerId, pathId))) {
            throw new IllegalStateException("CA publication changed concurrently");
        }
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA);
    }

    private void putOrRequireCa(CaRecord expected) {
        java.util.Optional<CaRecord> existing = store.getCa(expected.caId());
        if (existing.isPresent()) {
            CaRecord current = existing.orElseThrow();
            if (!current.caId().equals(expected.caId()) || current.kind() != expected.kind()
                    || !current.subjectRef().equals(expected.subjectRef())
                    || !current.issuerIds().getFirst().equals(expected.issuerIds().getFirst())) {
                throw new DomainContinuationPublisher.PostconditionFailure("PUBLISHED_CA_DIFFERS");
            }
            return;
        }
        store.putCa(expected);
        DomainContinuationPublisher.afterDurablePublication(
                DomainContinuationPublisher.PublicationFaultPoint.AFTER_CA);
    }

    /** Root inputs grouped below the method parameter bound. */
    private record RootPublication(X509Certificate certificate, byte[] der) { }

    /** Exact decoded root-publication fields. */
    private record RootCommand(FormatId format, SubjectRef subject, KeyRef keyRef,
            CertificateProfileRef profile, Instant notBefore, Instant notAfter, BigInteger serial,
            PkiId authorityId) {

        private static RootCommand decode(DomainCommandEncoding.Decoded command) {
            return new RootCommand(new FormatId(command.field(0)), new SubjectRef(command.field(1)),
                    new KeyRef(command.field(3)), DomainContinuationPublisher.profile(command, 4),
                    Instant.parse(command.field(7)), Instant.parse(command.field(8)),
                    new BigInteger(command.field(9)), new PkiId(command.field(13)));
        }
    }

    /** Deterministic root identifiers and immutable public-key commitment. */
    private record RootTargets(PkiId credentialId, PkiId authorityId, PkiId issuerId,
            PkiId pathId, String publicKeyFingerprint) { }

    /** Exact decoded intermediate-publication fields. */
    private record IntermediateCommand(FormatId format, PkiId issuerCaId, PkiId subjectCaId,
            PkiId parentIssuerId, PkiId parentPathId, String parentPathCommitment, KeyRef subjectKeyRef,
            CertificateProfileRef profile, SubjectRef subject, Instant notBefore, Instant notAfter,
            BigInteger serial, String publicKeyFingerprint) {

        private static IntermediateCommand decode(DomainCommandEncoding.Decoded command) {
            return new IntermediateCommand(new FormatId(command.field(0)), new PkiId(command.field(1)),
                    new PkiId(command.field(2)), new PkiId(command.field(3)), new PkiId(command.field(4)),
                    command.field(5), new KeyRef(command.field(6)),
                    DomainContinuationPublisher.profile(command, 7),
                    new SubjectRef(command.field(10)), Instant.parse(command.field(11)),
                    Instant.parse(command.field(12)), new BigInteger(command.field(13)), command.field(17));
        }
    }
}
