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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerGenerationState;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.status.FullCrlRequest;
import zeroecho.pki.api.status.DeltaCrlRequest;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.core.continuation.FullCrlSnapshotProvenance;
import zeroecho.pki.impl.framework.x509.StreamingCrlSignatureVerifier;
import zeroecho.pki.impl.framework.x509.StreamingDerWriter;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.Pkix;

/**
 * Read-only full-CRL issuer and policy preparation. Captures one evaluation
 * time and freezes exact construction inputs; owns no revocation snapshot,
 * number reservation, content staging or signing workflow. A constant number
 * of point store calls and bounded certificate/profile parsing accompany O(G)
 * membership work for the selected CA's G generations. New auxiliary memory
 * is O(1) under the existing artifact bounds. The frozen result retains the
 * existing immutable CA record and its O(G) generation list without copying it
 * or constructing another generation index.
 */
final class FullCrlPreparation { // NOPMD - CyclomaticComplexity totals independent cohesive operations; method-level checks remain enabled.
    private final PkiStore store;
    private final EffectiveCredentialStatusResolver status;
    private final X509AuthoritySnapshot authority;
    private final X509AlgorithmBindingRegistry bindings;
    private final AlgorithmIdentity signature;

    /* default */ FullCrlPreparation(PkiStore store, Clock clock, X509AuthoritySnapshot authority,
            X509AlgorithmBindingRegistry bindings, String signatureAlgorithm) {
        this.store = Objects.requireNonNull(store, "store");
        this.status = new StoreBackedEffectiveCredentialStatusResolver(store, clock);
        this.authority = Objects.requireNonNull(authority, "authority");
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        this.signature = authority.resolveIdentity(signatureAlgorithm);
        if (!signature.canonicalForm().equals(signatureAlgorithm)
                || signature.kind() != AlgorithmIdentity.Kind.SIGNATURE) {
            throw new IllegalArgumentException("Configured signing algorithm must be a canonical signature identity");
        }
        X509SecurityFloor.requirePermitted(signature);
    }

    /* default */ Prepared prepare(FullCrlRequest request, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(request, "request");
        return prepare(request.issuerGenerationId(), request.validity(), false, 0, cancellation);
    }

    /* default */ Prepared prepare(DeltaCrlRequest request, long pureEdDsaMaximum, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(request, "request");
        return prepare(request.issuerGenerationId(), request.validity(), true, pureEdDsaMaximum, cancellation);
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private Prepared prepare(PkiId issuerId, Duration validity, boolean delta, long pureEdDsaMaximum,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        IssuerGeneration generation = store.getIssuerGeneration(issuerId)
                .orElseThrow(() -> reject("GENERATION_MISSING"));
        CaRecord ca = store.getCa(generation.authorityId()).orElseThrow(() -> reject("AUTHORITY_MISSING"));
        Credential credential = store.getCredential(generation.credentialId())
                .orElseThrow(() -> reject("CREDENTIAL_MISSING"));
        requireIssuer(issuerId, generation, ca, credential);
        evaluation.requireUsable(credential, CredentialUse.STATUS_OBJECT_ISSUER);
        CertificateProfileRef reference = ((CaProfileBinding) credential.profileBinding()).reference();
        CertificateProfileDefinition profile = profile(reference, generation);
        byte[] der = CredentialContent.materializeForBc(store, credential.content());
        try {
            if (!HexFormat.of().formatHex(sha256(der)).equals(credential.content().sha256())) {
                throw reject("CREDENTIAL_COMMITMENT_MISMATCH");
            }
            new StreamingDerReader().validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate certificate = Pkix.parseCertificate(der);
            requireCertificate(certificate, credential, ca, evaluation.evaluationTime());
            Instant thisUpdate = evaluation.evaluationTime().truncatedTo(ChronoUnit.SECONDS);
            Instant requestedNext = thisUpdate.plus(validity);
            Instant nextUpdate = requestedNext.truncatedTo(ChronoUnit.SECONDS);
            requireTimes(thisUpdate, requestedNext, nextUpdate, certificate);
            byte[] spki = Pkix.subjectPublicKeyInfo(certificate);
            AlgorithmIdentity key = new BcX509AlgorithmAdapter(authority.bindings()).decode(
                    Pkix.subjectPublicKeyAlgorithm(spki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509AlgorithmBinding binding = binding(profile.algorithmBindingPolicy());
            X509ExecutionPlan<SigningProvider> plan = authority.plan(signature, key,
                    AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                    binding.bindingId(), SigningProvider.class);
            authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
            CrlScope scope = CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), spki);
            Optional<DeltaCrlBase> base = delta
                    ? Optional.of(selectBase(ca.caId(), certificate, pureEdDsaMaximum, cancellation)) : Optional.empty();
            cancellation.throwIfCancelled();
            return new Prepared(ca, generation, credential.credentialId(), reference, credential.content(),
                    scope, binding, plan.selection().binding(), evaluation.evaluationTime(), thisUpdate, nextUpdate, der, base);
        } catch (DateTimeException | ArithmeticException invalid) {
            throw reject("TIME_INVALID");
        } catch (IllegalArgumentException invalid) {
            throw reject("CERTIFICATE_OR_BINDING_INVALID");
        }
    }

    private static void requireIssuer(PkiId issuerId, IssuerGeneration generation, CaRecord ca,
            Credential credential) {
        if (!issuerId.equals(generation.issuerId())
                || !generation.issuerId().equals(IssuerGeneration.idFor(generation.authorityId(), generation.credentialId()))
                || !ca.caId().equals(generation.authorityId()) || !ca.issuerIds().contains(generation.issuerId())
                || !credential.credentialId().equals(generation.credentialId())
                || !credential.formatId().equals(BcX509CredentialFramework.FORMAT_ID)
                || !(credential.profileBinding() instanceof CaProfileBinding)) {
            throw reject("ISSUER_BINDING_INCONSISTENT");
        }
        if ((ca.state() != CaState.ACTIVE && ca.state() != CaState.RETIRED)
                || (generation.state() != IssuerGenerationState.ACTIVE
                        && generation.state() != IssuerGenerationState.RETIRED)) {
            throw reject("ISSUER_UNAVAILABLE");
        }
    }

    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    private DeltaCrlBase selectBase(PkiId authorityId, X509Certificate issuer, long maximum,
            CancellationSignal cancellation) throws IOException {
        StatusObject selected = latestBase(authorityId, cancellation);
        DurableContentReference reference = selected.content();
        if (!selected.formatId().equals(BcX509CredentialFramework.FORMAT_ID)
                || reference.encoding() != Encoding.DER
                || reference.lifecycle() != DurableContentReference.Lifecycle.PERSISTED
                || !selected.statusObjectId().value().equals("crl:" + reference.sha256())) {
            throw reject("DELTA_BASE_IDENTITY_INVALID");
        }
        FullCrlSnapshotProvenance provenance = FullCrlSnapshotProvenance.decode(selected.attributes());
        try (RepeatableContent content = store.stagedContent().openContent(reference)) {
            requireBaseCommitment(content, reference, cancellation);
            StreamingDerReader.CrlSemanticLayout semantics = new StreamingDerReader().inspectCrlSemantics(content, cancellation);
            StreamingDerReader.SignedObjectLayout layout = semantics.layout();
            if (semantics.deltaIndicator().isPresent()
                    || !layout.thisUpdate().equals(Optional.of(selected.thisUpdate()))
                    || !layout.nextUpdate().equals(selected.nextUpdate())) {
                throw reject("DELTA_BASE_METADATA_INVALID");
            }
            byte[] algorithm = readSlice(content, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength(), 16_384);
            if (!Arrays.equals(algorithm, readSlice(content, layout.tbsAlgorithmOffset(), layout.tbsAlgorithmLength(), 16_384))
                    || !Arrays.equals(issuer.getSubjectX500Principal().getEncoded(),
                            readSlice(content, layout.issuerOffset(), layout.issuerLength(), 16_384))) {
                throw reject("DELTA_BASE_SCOPE_INVALID");
            }
            X509AlgorithmIdentifier identifier = BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(algorithm));
            AlgorithmIdentity actual = authority.bindings().reverse(identifier, X509AlgorithmRole.SIGNATURE_ALGORITHM);
            FullCrlSigningCommand.requireAdmission(actual.canonicalForm(), layout.tbsLength(), maximum);
            byte[] signatureBytes = readSlice(content, layout.signatureOffset(), layout.signatureLength(), 1024 * 1024);
            try (RepeatableContent tbs = new ContentSlice(content, layout.tbsOffset(), layout.tbsLength())) {
                StreamingCrlSignatureVerifier.verify(tbs, actual.canonicalForm(), issuer, signatureBytes,
                        authority.bindings(), cancellation);
            } finally { Arrays.fill(signatureBytes, (byte) 0); }
            cancellation.throwIfCancelled();
            return new DeltaCrlBase(selected.statusObjectId(), semantics.crlNumber(), provenance);
        } catch (GeneralSecurityException invalid) {
            throw reject("DELTA_BASE_SIGNATURE_INVALID");
        }
    }

    private StatusObject latestBase(PkiId authorityId, CancellationSignal cancellation) throws IOException {
        StatusObject selected = null;
        for (StatusObject candidate : store.listStatusObjects(authorityId)) {
            cancellation.throwIfCancelled();
            if (candidate.type() == StatusObjectType.CRL && candidate.issuerCaId().equals(authorityId)
                    && (selected == null || candidate.thisUpdate().isAfter(selected.thisUpdate()))) {
                selected = candidate;
            }
        }
        if (selected == null) { throw reject("DELTA_BASE_MISSING"); }
        return selected;
    }

    private static void requireBaseCommitment(RepeatableContent content, DurableContentReference reference,
            CancellationSignal cancellation) throws IOException, GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new DigestInputStream(content.openStream(), digest)) {
            long length = StreamingDerWriter.copy(input, OutputStream.nullOutputStream(), cancellation);
            if (length != reference.length() || !HexFormat.of().formatHex(digest.digest()).equals(reference.sha256())) {
                throw reject("DELTA_BASE_COMMITMENT_INVALID");
            }
        }
    }

    private static byte[] readSlice(RepeatableContent content, long offset, long length, int maximum) throws IOException {
        if (length <= 0 || length > maximum) { throw reject("DELTA_BASE_FIELD_INVALID"); }
        try (RepeatableContent slice = new ContentSlice(content, offset, length); InputStream input = slice.openStream()) {
            byte[] value = input.readNBytes((int) length);
            if (value.length != length || input.read() != -1) { throw reject("DELTA_BASE_FIELD_INVALID"); }
            return value;
        }
    }

    private CertificateProfileDefinition profile(CertificateProfileRef expected, IssuerGeneration generation) {
        ImportedCertificateProfileVersion imported = store.getProfileVersion(expected.profileId(), expected.profileVersion())
                .orElseThrow(() -> reject("PROFILE_MISSING"));
        String commitment = HexFormat.of().formatHex(expected.canonicalSha256());
        CertificateProfileDefinition definition = imported.definition();
        if (!expected.equals(imported.reference())
                || !generation.profilePolicyCommitment().equals(commitment)
                || !generation.x509BindingCommitment().equals(commitment)
                || definition.certificateType() == CertificateProfileKind.END_ENTITY
                || !definition.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) {
            throw reject("PROFILE_BINDING_INCONSISTENT");
        }
        byte[] canonical = CertificateProfileDocumentCodec.writeCanonical(definition);
        if (!Arrays.equals(canonical, imported.canonicalJson())
                || !MessageDigest.isEqual(sha256(canonical), expected.canonicalSha256())) {
            throw reject("PROFILE_COMMITMENT_MISMATCH");
        }
        return definition;
    }

    private X509AlgorithmBinding binding(X509AlgorithmBindingPolicy policy) {
        Optional<X509AlgorithmBindingPolicy.BindingReference> reference = policy.crlSignature();
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(signature, X509AlgorithmBinding.Role.CRL_SIGNATURE)
                        .orElseThrow(() -> reject("CRL_BINDING_MISSING")));
        if (selected.role() != X509AlgorithmBinding.Role.CRL_SIGNATURE
                || !selected.algorithmIdentity().equals(signature)
                || reference.isPresent() && selected.origin() == X509AlgorithmBinding.Origin.STANDARD) {
            throw reject("CRL_BINDING_INCONSISTENT");
        }
        return selected;
    }

    private static void requireCertificate(X509Certificate certificate, Credential credential, CaRecord ca, Instant now) {
        boolean[] usages = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0 || usages == null || usages.length <= 6 || !usages[6]
                || !certificate.getSubjectX500Principal().equals(new X500Principal(credential.subjectRef().value()))
                || !certificate.getSubjectX500Principal().equals(new X500Principal(ca.subjectRef().value()))
                || !certificate.getSerialNumber().toString().equals(credential.serialOrUniqueId())
                || !certificate.getNotBefore().toInstant().equals(credential.validity().notBefore())
                || !certificate.getNotAfter().toInstant().equals(credential.validity().notAfter())
                || now.isBefore(certificate.getNotBefore().toInstant()) || !now.isBefore(certificate.getNotAfter().toInstant())) {
            throw reject("CREDENTIAL_UNUSABLE");
        }
    }

    private static void requireTimes(Instant thisUpdate, Instant requestedNext, Instant nextUpdate,
            X509Certificate certificate) {
        // X.509 GeneralizedTime has a four-digit year; overflow is not a duration policy cap.
        int firstYear = thisUpdate.atOffset(ZoneOffset.UTC).getYear();
        int lastYear = nextUpdate.atOffset(ZoneOffset.UTC).getYear();
        if (firstYear < 1 || lastYear > 9999 || !nextUpdate.isAfter(thisUpdate)
                || requestedNext.isAfter(certificate.getNotAfter().toInstant())
                || thisUpdate.isBefore(certificate.getNotBefore().toInstant())) {
            throw reject("TIME_INVALID");
        }
    }

    private static byte[] sha256(byte[] encoded) {
        try { return MessageDigest.getInstance("SHA-256").digest(encoded); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static PkiException reject(String code) {
        return new PkiException("Full CRL preparation rejected: code=" + code);
    }

    /** Frozen provider-free bounded inputs; the authorized process-local execution plan is not retained. */
    /* default */ record Prepared(CaRecord authority, IssuerGeneration generation, PkiId credentialId, CertificateProfileRef profile,
            DurableContentReference issuerContent, CrlScope scope, X509AlgorithmBinding signatureBinding,
            X509AlgorithmIdentifier signatureIdentifier, Instant evaluationTime, Instant thisUpdate,
            Instant nextUpdate, byte[] issuerDer, Optional<DeltaCrlBase> base) {
        Prepared { issuerDer = issuerDer.clone(); Objects.requireNonNull(base, "base"); }
        /* default */ PkiId authorityId() { return authority.caId(); }
        @Override public byte[] issuerDer() { return issuerDer.clone(); }
        @Override public String toString() { return "PreparedFullCrl[redacted]"; }
    }
}
