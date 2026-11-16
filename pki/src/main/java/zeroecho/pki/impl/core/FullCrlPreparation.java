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

    /**
     * Creates a CRL preparer using an authoritative store, clock, and permitted signature binding.
     *
     * @param store borrowed PKI store; must not be null
     * @param clock authoritative session clock; must not be null
     * @param authority frozen X.509 authority snapshot; must not be null
     * @param bindings immutable X.509 algorithm binding registry; must not be null
     * @param signatureAlgorithm canonical permitted signature algorithm identity
     * @throws NullPointerException if a required collaborator is null
     * @throws IllegalArgumentException if the algorithm is noncanonical, not a signature, or disallowed
     */
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

    /**
     * Validates the issuer and CRL policy, freezing bounded inputs for later TBS staging.
     *
     * <p>Preparation does not emit a signature or publish a status object.</p>
     *
     * @param request full or delta CRL request; must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return frozen issuer, scope, signature, validity, and optional delta-base inputs
     * @throws IOException if authoritative content access or cooperative cancellation fails
     * @throws PkiException if issuer selection, profile, CRL scope, or time policy rejects the request
     * @throws NullPointerException if request or cancellation is null
     */
    /* default */ Prepared prepare(FullCrlRequest request, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(request, "request");
        return prepare(request.issuerGenerationId(), request.validity(), false, 0, cancellation);
    }

    /**
     * Validates the issuer and CRL policy, freezing bounded inputs for later TBS staging.
     *
     * <p>Preparation does not emit a signature or publish a status object.</p>
     *
     * @param request full or delta CRL request; must not be null
     * @param pureEdDsaMaximum finite maximum raw-message length in bytes for pure EdDSA
     * @param cancellation cooperative cancellation signal; must not be null
     * @return frozen issuer, scope, signature, validity, and optional delta-base inputs
     * @throws IOException if authoritative content access or cooperative cancellation fails
     * @throws PkiException if issuer selection, profile, CRL scope, or time policy rejects the request
     * @throws NullPointerException if request or cancellation is null
     */
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
        var issuerBinding = store.getIssuerCryptographicBinding(generation.issuerId())
                .orElseThrow(() -> reject("ISSUER_CRYPTOGRAPHIC_BINDING_MISSING"));
        CertificateProfileDefinition profile = profile(reference, generation, issuerBinding);
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
            AlgorithmIdentity selectedSignature = issuerBinding.primary().signatureAlgorithm();
            CrlSigningRoleTuple.validate(issuerBinding.primary(), spki, authority);
            X509AlgorithmBinding binding = binding(profile.algorithmBindingPolicy(), selectedSignature);
            X509ExecutionPlan<SigningProvider> plan = authority.plan(selectedSignature, key,
                    AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                    binding.bindingId(), SigningProvider.class);
            authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
            Optional<PreparedFullCrlTbs.Hybrid> hybrid = Optional.empty();
            boolean hybridProfile = profile.hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature;
            if (hybridProfile != issuerBinding.alternative().isPresent()) throw reject("CRL_HYBRID_ROLE_MISMATCH");
            if (hybridProfile) {
                var alt = issuerBinding.alternative().orElseThrow();
                byte[] alternativeSpki = CrlSigningRoleTuple.alternativeSpki(certificate);
                CrlSigningRoleTuple.validate(alt, alternativeSpki, authority);
                var alternativePlan = authority.plan(alt.signatureAlgorithm(), alt.publicKeyAlgorithm(),
                        AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit", SigningProvider.class);
                authority.authorize(alternativePlan, alternativePlan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
                if (alternativePlan.executor() != plan.executor() || !Arrays.equals(alt.signatureAlgorithmIdentifier().bytes(),
                        Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(alternativePlan.selection().binding()))))
                    throw reject("CRL_ALTERNATIVE_PLAN_DIFFERS");
                String tuple = CrlSigningRoleTuple.commitment(issuerBinding, certificate,
                        Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(plan.selection().binding())),
                        alt.signatureAlgorithmIdentifier().bytes());
                hybrid = Optional.of(new PreparedFullCrlTbs.Hybrid(issuerBinding, alternativePlan.selection().binding(), tuple,
                        store.requireCrlSignerLineage(issuerId), CrlSigningRoleTuple.planCommitment(plan, binding.bindingId(), binding.semanticCommitment()),
                        alternativePlanCommitment(alternativePlan),
                        CrlSigningRoleTuple.maximumSignatureBytes(alt, alternativeSpki, authority),
                        CrlSigningRoleTuple.maximumSignatureBytes(issuerBinding.primary(), spki, authority)));
            }
            CrlScope scope = CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), spki);
            Optional<DeltaCrlBase> base = delta
                    ? Optional.of(hybrid.isPresent() ? selectHybridBase(ca.caId(), hybrid.orElseThrow(), scope, pureEdDsaMaximum, cancellation)
                            : selectBase(ca.caId(), certificate, pureEdDsaMaximum, cancellation)) : Optional.empty();
            cancellation.throwIfCancelled();
            return new Prepared(ca, generation, credential.credentialId(), reference, credential.content(),
                    scope, binding, plan.selection().binding(), evaluation.evaluationTime(), thisUpdate, nextUpdate, der, base, hybrid);
        } catch (GeneralSecurityException invalid) {
            throw reject("CRL_PUBLIC_SIGNATURE_BOUND_INVALID");
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

    private String alternativePlanCommitment(X509ExecutionPlan<SigningProvider> plan) {
        String id = authority.bindings().bindingId(plan.selection().binding(), X509AlgorithmRole.SIGNATURE_ALGORITHM);
        var rule = authority.bindings().rules().stream().filter(value -> value.id().equals(id)).findFirst().orElseThrow();
        return CrlSigningRoleTuple.planCommitment(plan, id, rule.semanticFingerprint());
    }

    private DeltaCrlBase selectHybridBase(PkiId authorityId, PreparedFullCrlTbs.Hybrid requested, CrlScope scope,
            long maximum, CancellationSignal cancellation) throws IOException, GeneralSecurityException {
        StatusObject selected = null;
        java.math.BigInteger selectedNumber = null;
        for (StatusObject candidate : store.listStatusObjects(authorityId)) {
            cancellation.throwIfCancelled();
            if (candidate.type() != StatusObjectType.CRL) continue;
            var evidence = baseEvidence(candidate, authorityId);
            if (!requested.lineageId().equals(evidence.lineage()) || !scope.digest().equals(evidence.scope().digest())) continue;
            if (selected != null && candidate.thisUpdate().isBefore(selected.thisUpdate())) continue;
            java.math.BigInteger number;
            try (RepeatableContent content = store.stagedContent().openContent(candidate.content())) {
                number = new StreamingDerReader().inspectCrlSemantics(content, cancellation).crlNumber();
            }
            if (selected == null || candidate.thisUpdate().isAfter(selected.thisUpdate())
                    || number.compareTo(selectedNumber) > 0
                    || number.equals(selectedNumber) && candidate.statusObjectId().value().compareTo(selected.statusObjectId().value()) > 0) {
                selected = candidate; selectedNumber = number;
            }
        }
        if (selected == null) throw reject("DELTA_BASE_NEW_FULL_REQUIRED");
        var issuerId = new PkiId(text(selected, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ISSUER_GENERATION));
        var binding = store.getIssuerCryptographicBinding(issuerId).orElseThrow();
        var credential = store.getCredential(binding.credentialId()).orElseThrow();
        var certificate = Pkix.parseCertificate(CredentialContent.materializeForBc(store, credential.content()));
        if (!store.requireCrlSignerLineage(issuerId).equals(requested.lineageId())
                || !binding.commitment().equals(text(selected, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ISSUER_BINDING))
                || !requested.tupleCommitment().equals(text(selected, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ROLE_TUPLE))
                || !zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.PROFILE.equals(text(selected,
                        zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.SIGNATURE_PROFILE)))
            throw reject("DELTA_BASE_ROLE_TUPLE_INVALID");
        try (RepeatableContent content = store.stagedContent().openContent(selected.content())) {
            requireBaseCommitment(content, selected.content(), cancellation);
            var alternativeLayout = new StreamingDerReader().inspectAlternativeCrl(content, cancellation);
            var semantic = alternativeLayout.semantic(); var layout = semantic.layout();
            byte[] nativeAlgorithm = readSlice(content, layout.outerAlgorithmOffset(), layout.outerAlgorithmLength(), 16_384);
            if (semantic.deltaIndicator().isPresent() || !layout.thisUpdate().equals(Optional.of(selected.thisUpdate()))
                    || !layout.nextUpdate().equals(selected.nextUpdate())
                    || !requested.tupleCommitment().equals(CrlSigningRoleTuple.commitment(binding, certificate,
                            nativeAlgorithm, alternativeLayout.alternativeAlgorithmDer()))
                    || !Arrays.equals(alternativeLayout.alternativeAlgorithmDer(), binding.alternative().orElseThrow().signatureAlgorithmIdentifier().bytes()))
                throw reject("DELTA_BASE_METADATA_INVALID");
            var nativeIdentity = authority.bindings().reverse(BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(nativeAlgorithm)),
                    X509AlgorithmRole.SIGNATURE_ALGORITHM);
            if (!nativeIdentity.equals(binding.primary().signatureAlgorithm())) throw reject("DELTA_BASE_NATIVE_ALGORITHM_INVALID");
            byte[] primarySpki = Pkix.subjectPublicKeyInfo(certificate);
            byte[] alternativeSpki = CrlSigningRoleTuple.alternativeSpki(certificate);
            CrlSigningRoleTuple.validate(binding.primary(), primarySpki, authority);
            CrlSigningRoleTuple.validate(binding.alternative().orElseThrow(), alternativeSpki, authority);
            FullCrlSigningCommand.requireAdmission(nativeIdentity.canonicalForm(), layout.tbsLength(), maximum);
            try (RepeatableContent tbs = new ContentSlice(content, layout.tbsOffset(), layout.tbsLength());
                    RepeatableContent alternativeTbs = zeroecho.pki.impl.framework.x509.StreamingCrlAlternativeSignature.alternativeTbs(content, cancellation)) {
                StreamingCrlSignatureVerifier.verify(tbs, nativeIdentity.canonicalForm(), primarySpki,
                        readSlice(content, layout.signatureOffset(), layout.signatureLength(), 1_048_576), authority.bindings(), cancellation);
                FullCrlSigningCommand.requireAdmission(binding.alternative().orElseThrow().signatureAlgorithm().canonicalForm(),
                        alternativeTbs.length().orElseThrow(), maximum);
                StreamingCrlSignatureVerifier.verify(alternativeTbs, binding.alternative().orElseThrow().signatureAlgorithm().canonicalForm(),
                        alternativeSpki, alternativeLayout.alternativeSignature(), authority.bindings(), cancellation);
            }
            return new DeltaCrlBase(selected.statusObjectId(), semantic.crlNumber(), FullCrlSnapshotProvenance.decode(selected.attributes()));
        }
    }

    private BaseEvidence baseEvidence(StatusObject candidate, PkiId authorityId) throws IOException {
        var generationId = new PkiId(requiredText(candidate, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ISSUER_GENERATION));
        var generation = store.getIssuerGeneration(generationId).orElseThrow(() -> reject("DELTA_BASE_GENERATION_MISSING"));
        var binding = store.getIssuerCryptographicBinding(generationId).orElseThrow(() -> reject("DELTA_BASE_BINDING_MISSING"));
        var credential = store.getCredential(generation.credentialId()).orElseThrow(() -> reject("DELTA_BASE_CREDENTIAL_MISSING"));
        if (!generation.authorityId().equals(authorityId) || !candidate.issuerCaId().equals(authorityId)
                || !binding.issuerId().equals(generationId) || !binding.credentialId().equals(credential.credentialId())
                || !binding.commitment().equals(requiredText(candidate, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ISSUER_BINDING)))
            throw reject("DELTA_BASE_METADATA_INVALID");
        byte[] der = CredentialContent.materializeForBc(store, credential.content());
        if (!HexFormat.of().formatHex(sha256(der)).equals(binding.certificateSha256())) throw reject("DELTA_BASE_METADATA_INVALID");
        var certificate = Pkix.parseCertificate(der);
        var lineage = store.requireCrlSignerLineage(generationId);
        if (!lineage.value().equals(requiredText(candidate, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.SIGNER_LINEAGE))
                || !zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.PROFILE.equals(requiredText(candidate,
                        zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.SIGNATURE_PROFILE)))
            throw reject("DELTA_BASE_METADATA_INVALID");
        var immutableProfile = profile(((CaProfileBinding) credential.profileBinding()).reference(), generation, binding);
        String tuple = new CrlHybridPublicVerifier(authority).roleTupleCommitment(binding,
                new zeroecho.pki.api.EncodedObject(Encoding.DER, der), immutableProfile);
        if (!tuple.equals(requiredText(candidate, zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand.ROLE_TUPLE)))
            throw reject("DELTA_BASE_METADATA_INVALID");
        return new BaseEvidence(lineage, CrlScope.of(certificate.getSubjectX500Principal().getEncoded(), Pkix.subjectPublicKeyInfo(certificate)));
    }

    private record BaseEvidence(PkiId lineage, CrlScope scope) { }

    private static String requiredText(StatusObject status, zeroecho.pki.api.attr.AttributeId id) {
        String value = text(status, id);
        if (value.isEmpty()) throw reject("DELTA_BASE_METADATA_INVALID");
        return value;
    }

    private static String text(StatusObject status, zeroecho.pki.api.attr.AttributeId id) {
        if (status.attributes().getAll(id).size() != 1) return "";
        return status.attributes().get(id).filter(zeroecho.pki.api.attr.AttributeValue.StringValue.class::isInstance)
                .map(zeroecho.pki.api.attr.AttributeValue.StringValue.class::cast).map(zeroecho.pki.api.attr.AttributeValue.StringValue::value).orElse("");
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

    private CertificateProfileDefinition profile(CertificateProfileRef expected, IssuerGeneration generation,
            zeroecho.pki.api.ca.IssuerCryptographicBinding binding) {
        ImportedCertificateProfileVersion imported = store.getProfileVersion(expected.profileId(), expected.profileVersion())
                .orElseThrow(() -> reject("PROFILE_MISSING"));
        String commitment = HexFormat.of().formatHex(expected.canonicalSha256());
        if (!binding.issuerId().equals(generation.issuerId()) || !binding.authorityId().equals(generation.authorityId())
                || !binding.credentialId().equals(generation.credentialId()) || !binding.profile().equals(expected)
                || !binding.primary().keyRef().equals(generation.signingKeyRef())
                || !generation.x509BindingCommitment().equals(binding.bindingSetCommitment())) {
            throw reject("ISSUER_CRYPTOGRAPHIC_BINDING_INCONSISTENT");
        }
        CertificateProfileDefinition definition = imported.definition();
        if (!expected.equals(imported.reference())
                || !generation.profilePolicyCommitment().equals(commitment)
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

    private X509AlgorithmBinding binding(X509AlgorithmBindingPolicy policy, AlgorithmIdentity selectedSignature) {
        Optional<X509AlgorithmBindingPolicy.BindingReference> reference = policy.crlSignature();
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(selectedSignature, X509AlgorithmBinding.Role.CRL_SIGNATURE)
                        .orElseThrow(() -> reject("CRL_BINDING_MISSING")));
        if (selected.role() != X509AlgorithmBinding.Role.CRL_SIGNATURE
                || !selected.algorithmIdentity().equals(selectedSignature)
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

    /**
     * Frozen provider-free bounded inputs; the authorized process-local execution plan is not retained.
     * @param authority frozen CA record retaining its generation membership
     * @param generation selected issuer generation
     * @param credentialId exact issuer credential identity
     * @param profile selected CA certificate profile reference
     * @param issuerContent durable issuer certificate content reference
     * @param scope frozen CRL scope
     * @param signatureBinding authorized signature binding
     * @param signatureIdentifier canonical X.509 signature AlgorithmIdentifier
     * @param evaluationTime authoritative status evaluation time
     * @param thisUpdate CRL issuance time
     * @param nextUpdate exclusive upper freshness bound
     * @param issuerDer issuer certificate DER, cloned at construction and on access
     * @param base optional full CRL base for delta generation; container must not be null
     * @param hybrid optional frozen hybrid-signature preparation
     */
    /* default */ record Prepared(CaRecord authority, IssuerGeneration generation, PkiId credentialId, CertificateProfileRef profile,
            DurableContentReference issuerContent, CrlScope scope, X509AlgorithmBinding signatureBinding,
            X509AlgorithmIdentifier signatureIdentifier, Instant evaluationTime, Instant thisUpdate,
            Instant nextUpdate, byte[] issuerDer, Optional<DeltaCrlBase> base, Optional<PreparedFullCrlTbs.Hybrid> hybrid) {
        /**
         * Retains frozen CRL inputs, taking a defensive copy of issuer certificate DER.
         *
         * @param authority frozen CA record retaining its generation membership
         * @param generation selected issuer generation
         * @param credentialId exact issuer credential identity
         * @param profile selected CA certificate profile reference
         * @param issuerContent durable issuer certificate content reference
         * @param scope frozen CRL scope
         * @param signatureBinding authorized signature binding
         * @param signatureIdentifier canonical X.509 signature AlgorithmIdentifier
         * @param evaluationTime authoritative status evaluation time
         * @param thisUpdate CRL issuance time
         * @param nextUpdate exclusive upper freshness bound
         * @param issuerDer issuer certificate DER, cloned at construction and on access
         * @param base optional full CRL base for delta generation; container must not be null
         * @throws NullPointerException if issuerDer or the base container is null
         */
        Prepared(CaRecord authority, IssuerGeneration generation, PkiId credentialId, CertificateProfileRef profile,
                DurableContentReference issuerContent, CrlScope scope, X509AlgorithmBinding signatureBinding,
                X509AlgorithmIdentifier signatureIdentifier, Instant evaluationTime, Instant thisUpdate, Instant nextUpdate,
                byte[] issuerDer, Optional<DeltaCrlBase> base) {
            this(authority, generation, credentialId, profile, issuerContent, scope, signatureBinding, signatureIdentifier,
                    evaluationTime, thisUpdate, nextUpdate, issuerDer, base, Optional.empty());
        }
        /**
         * Retains frozen CRL inputs, taking a defensive copy of issuer certificate DER.
         *
         * @param authority frozen CA record retaining its generation membership
         * @param generation selected issuer generation
         * @param credentialId exact issuer credential identity
         * @param profile selected CA certificate profile reference
         * @param issuerContent durable issuer certificate content reference
         * @param scope frozen CRL scope
         * @param signatureBinding authorized signature binding
         * @param signatureIdentifier canonical X.509 signature AlgorithmIdentifier
         * @param evaluationTime authoritative status evaluation time
         * @param thisUpdate CRL issuance time
         * @param nextUpdate exclusive upper freshness bound
         * @param issuerDer issuer certificate DER, cloned at construction and on access
         * @param base optional full CRL base for delta generation; container must not be null
         * @param hybrid optional frozen hybrid-signature preparation
         * @throws NullPointerException if issuerDer or the base container is null
         */
        Prepared { issuerDer = issuerDer.clone(); Objects.requireNonNull(base, "base"); }
        /**
         * Returns the logical authority identity from the frozen CA record.
         *
         * @return frozen CA identity
         */
        /* default */ PkiId authorityId() { return authority.caId(); }
        /**
         * Returns an independent copy of the frozen issuer certificate DER.
         *
         * @return issuer certificate bytes owned by the caller
         */
        @Override public byte[] issuerDer() { return issuerDer.clone(); }
        /**
         * {@inheritDoc}
         */
        @Override public String toString() { return "PreparedFullCrl[redacted]"; }
    }
}
