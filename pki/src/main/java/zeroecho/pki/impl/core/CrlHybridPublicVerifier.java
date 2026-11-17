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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Optional;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainContinuationValidation;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;
import zeroecho.pki.spi.store.DomainContinuationStore;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ContentSlice;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.impl.core.continuation.CrlHybridSigningCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.framework.x509.StreamingCrlAlternativeSignature;
import zeroecho.pki.impl.framework.x509.StreamingCrlSignatureVerifier;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.store.CrlHybridNativeChildVerifier;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pkix.Pkix;

/**
 * Configured public-only authority for exact streamed hybrid CRL child adoption.
 */
public final class CrlHybridPublicVerifier implements CrlHybridNativeChildVerifier {
    private final X509AuthoritySnapshot authority;

    /**
     * Captures immutable configured public rules, including contributed OIDs and parameters.
     * @param authority exact session public verification authority; no private provider
     * @throws NullPointerException if authority is null
     */
    public CrlHybridPublicVerifier(X509AuthoritySnapshot authority) { this.authority = Objects.requireNonNull(authority, "authority"); }

    /**
     * Computes compatibility from an immutable CA profile's actual CRL presentation.
     * @param binding validated immutable outgoing roles
     * @param issuerCertificate bounded exact issuer DER
     * @param profile immutable creation profile
     * @return lowercase SHA-256 actual signer-tuple commitment
     * @throws IOException if public evidence cannot be decoded
     */
    @Override public String roleTupleCommitment(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            CertificateProfileDefinition profile) throws IOException {
        X509Certificate certificate = Pkix.parseCertificate(issuerCertificate.bytes());
        X509AlgorithmIdentifier primary = profile.algorithmBindingPolicy().crlSignature()
                .map(reference -> authority.bindings().resolve(reference.bindingId(), binding.primary().signatureAlgorithm(), X509AlgorithmRole.SIGNATURE_ALGORITHM))
                .orElseGet(() -> authority.bindings().resolve(binding.primary().signatureAlgorithm(), X509AlgorithmRole.SIGNATURE_ALGORITHM));
        return CrlSigningRoleTuple.commitment(binding, certificate,
                Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(primary)),
                binding.alternative().map(value -> value.signatureAlgorithmIdentifier().bytes()).orElse(new byte[0]));
    }

    /**
     * Validates the captured public generation, immutable profile, role presentation and
     * exact public signature-size bounds before alternative dispatch. This authority
     * deliberately does not recompute SIGN implementation-plan hashes: provider/config
     * and typed-preparation execution guards own those frozen commitments.
     * @param binding exact immutable issuer signing roles
     * @param issuerCertificate bounded issuer certificate DER
     * @param profile exact imported creation profile, never today's active profile
     * @param parent proposed alternative-parent acceptance
     * @throws GeneralSecurityException if configured public evidence or bounds cannot be resolved
     * @throws IOException if bounded public DER cannot be decoded
     * @throws IllegalArgumentException if the profile or captured execution coordinates differ
     */
    @Override public void validateAdmission(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            CertificateProfileDefinition profile, SignWorkflowStore.AcceptanceCommand parent)
            throws GeneralSecurityException, IOException {
        SignWorkflowStore.OuterCommand outer = parent.outer().orElseThrow();
        DomainCommandEncoding.Decoded command = DomainContinuationValidation.validate(
                new DomainContinuationTemplate(outer.kind(),
                        Optional.of(outer.correlationId()), outer.command(), outer.commandCommitment()));
        if (outer.kind() != DomainContinuationStore.Kind.STATUS
                || parent.mode() != SignWorkflowStore.Mode.NORMAL || parent.signatureEncoding() != Encoding.BINARY
                || parent.proofStep().isPresent() || parent.alternativeProofStep().isPresent()
                || !parent.fairnessAuthorityId().equals(binding.authorityId())
                || !(profile.hybridMode() instanceof HybridCertificateMode.AltSignature)
                || profile.certificateType() == CertificateProfileKind.END_ENTITY
                || !profile.profileId().equals(binding.profile().profileId()) || profile.profileVersion() != binding.profile().profileVersion()
                || !profile.formatId().value().equals(binding.formatId())
                || !sha256(CertificateProfileDocumentCodec.writeCanonical(profile))
                        .equals(HexFormat.of().formatHex(binding.profile().canonicalSha256())))
            { throw new IllegalArgumentException("Hybrid CRL immutable profile or parent differs"); }
        FullCrlSigningCommand.requireTbs(command, parent.candidate());
        publicRoles(binding, issuerCertificate, command, parent.operationId(), parent.keyRef(), parent.algorithmId());
        if (!roleTupleCommitment(binding, issuerCertificate, profile).equals(CrlHybridSigningCommand.descriptor(command).roleTupleCommitment()))
            { throw new IllegalArgumentException("Hybrid CRL immutable profile presentation differs"); }
        profile.algorithmBindingPolicy().crlSignature().ifPresent(reference -> {
            if (!reference.bindingId().equals(command.field(17)) || !reference.semanticCommitment().equals(command.field(18)))
                { throw new IllegalArgumentException("Hybrid CRL selected profile binding differs"); }
        });
    }

    /**
     * Validates inherited execution authority, actual alternative signature and exact native TBS bytes.
     * @param binding exact frozen generation roles
     * @param issuerCertificate bounded issuer DER
     * @param parent retained successful alternative workflow
     * @param alternativeTranscript borrowed accepted ALT input
     * @param nativeChild exact proposed raw child
     * @param nativeTbs borrowed final native TBS
     * @param cancellation cooperative streamed cancellation
     * @throws GeneralSecurityException if either role or the actual ALT signature is invalid
     * @throws IOException if committed content or exact native reconstruction differs
     * @throws IllegalArgumentException for contradictory execution authority or descriptors
     */
    @Override public void verify(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            SignWorkflowStore.Workflow parent, RepeatableContent alternativeTranscript,
            SignWorkflowStore.AcceptanceCommand nativeChild, RepeatableContent nativeTbs,
            CancellationSignal cancellation) throws GeneralSecurityException, IOException {
        cancellation.throwIfCancelled();
        SignWorkflowStore.AcceptanceEnvelope envelope = parent.envelope();
        SignWorkflowStore.OuterCommand outer = envelope.outer().orElseThrow();
        DomainCommandEncoding.Decoded command = DomainCommandEncoding.decode(outer.command());
        FullCrlSigningCommand.validate(command);
        CrlHybridSigningCommand.Descriptor descriptor = CrlHybridSigningCommand.descriptor(command);
        IssuerKeyBinding alternative = binding.alternative().orElseThrow();
        AuthorityChecks.requireChild(command, binding, issuerCertificate, parent, envelope, descriptor, nativeChild, alternative);
        CrlHybridPublicVerifier.PublicRoles roles = publicRoles(binding, issuerCertificate, command, parent.operationId(), envelope.keyRef(), envelope.algorithmId());
        X509Certificate certificate = roles.certificate();
        byte[] alternativeSpki = roles.alternativeSpki();
        X509AlgorithmIdentifier decodedNative = roles.nativeIdentifier();
        StreamingDerReader.CrlAlternativeTbsLayout layout = new StreamingDerReader().inspectAlternativeCrlTbs(alternativeTranscript, cancellation);
        requireAlternativeHeader(layout, alternative, command);
        try (RepeatableContent issuer = new ContentSlice(alternativeTranscript, layout.issuerOffset(), layout.issuerLength());
                InputStream input = issuer.openStream()) {
            if (!Arrays.equals(input.readAllBytes(), certificate.getSubjectX500Principal().getEncoded()))
                { throw new IOException("Alternative CRL issuer differs"); }
        }
        byte[] signature = parent.result().orElseThrow().bytes();
        if (parent.result().orElseThrow().encoding() != Encoding.BINARY || signature.length == 0
                || signature.length > descriptor.alternativeMaximumSignatureBytes()) { throw new GeneralSecurityException("Invalid alternative CRL result bound"); }
        String transcriptHash = StreamingCrlSignatureVerifier.verify(alternativeTranscript,
                alternative.signatureAlgorithm().canonicalForm(), alternativeSpki, signature, authority.bindings(), cancellation);
        if (!transcriptHash.equals(command.field(28)) || !envelope.candidate().sha256().equals(transcriptHash)
                || envelope.candidate().length() != layout.encodedLength()
                || !Long.toString(layout.encodedLength()).equals(command.field(27))) { throw new IOException("Alternative CRL content commitment differs"); }
        verifyNativeTbs(alternativeTranscript, decodedNative, signature, nativeTbs, nativeChild, cancellation);
    }

    private PublicRoles publicRoles(IssuerCryptographicBinding binding, EncodedObject issuerCertificate,
            DomainCommandEncoding.Decoded command, PkiId parentId,
            KeyRef alternativeKey, String alternativeAlgorithm)
            throws GeneralSecurityException, IOException {
        CrlHybridSigningCommand.Descriptor descriptor = CrlHybridSigningCommand.descriptor(command);
        IssuerKeyBinding alternative = binding.alternative().orElseThrow();
        AuthorityChecks.requirePublicRoles(binding, issuerCertificate, command, descriptor, parentId, alternativeKey, alternativeAlgorithm, alternative);
        X509Certificate certificate = Pkix.parseCertificate(issuerCertificate.bytes());
        byte[] primarySpki = Pkix.subjectPublicKeyInfo(certificate);
        byte[] alternativeSpki = CrlSigningRoleTuple.alternativeSpki(certificate);
        CrlSigningRoleTuple.validate(binding.primary(), primarySpki, authority);
        CrlSigningRoleTuple.validate(alternative, alternativeSpki, authority);
        byte[] nativeAlgorithm = HexFormat.of().parseHex(command.field(9));
        X509AlgorithmIdentifier decodedNative = BcX509AlgorithmAdapter.fromLib(Pkix.parseAlgorithmIdentifier(nativeAlgorithm));
        if (!authority.bindings().reverse(decodedNative, X509AlgorithmRole.SIGNATURE_ALGORITHM).equals(binding.primary().signatureAlgorithm())
                || !binding.primary().signatureAlgorithm().canonicalForm().equals(command.field(8))
                || !Arrays.equals(nativeAlgorithm, Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(
                        authority.bindings().resolve(command.field(17), binding.primary().signatureAlgorithm(), X509AlgorithmRole.SIGNATURE_ALGORITHM))))
                || !descriptor.roleTupleCommitment().equals(CrlSigningRoleTuple.commitment(binding, certificate,
                        nativeAlgorithm, alternative.signatureAlgorithmIdentifier().bytes()))
                || descriptor.primaryMaximumSignatureBytes() != CrlSigningRoleTuple.maximumSignatureBytes(binding.primary(), primarySpki, authority)
                || descriptor.alternativeMaximumSignatureBytes() != CrlSigningRoleTuple.maximumSignatureBytes(alternative, alternativeSpki, authority))
            { throw new IllegalArgumentException("Hybrid CRL role presentation differs"); }
        if (authority.bindings().rules().stream().flatMap(rule -> rule.bindings().stream()).noneMatch(presentation ->
                presentation.bindingId().equals(command.field(17)) && presentation.semanticCommitment().equals(command.field(18))
                        && presentation.role() == X509AlgorithmBinding.Role.CRL_SIGNATURE
                        && presentation.algorithmIdentity().equals(binding.primary().signatureAlgorithm())))
            { throw new IllegalArgumentException("Hybrid CRL presentation commitment differs"); }
        return new PublicRoles(certificate, primarySpki, alternativeSpki, decodedNative);
    }

    private record PublicRoles(X509Certificate certificate, byte[] primarySpki,
            byte[] alternativeSpki, X509AlgorithmIdentifier nativeIdentifier) { }

    private static String sha256(byte[] value) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static void verifyNativeTbs(RepeatableContent alternativeTranscript, X509AlgorithmIdentifier decodedNative,
            byte[] signature, RepeatableContent nativeTbs, SignWorkflowStore.AcceptanceCommand nativeChild,
            CancellationSignal cancellation) throws GeneralSecurityException, IOException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream actual = nativeTbs.openStream()) {
            try (OutputStream comparison = new OutputStream() {
                @Override public void write(int value) throws IOException {
                    cancellation.throwIfCancelled();
                    if (actual.read() != (value & 255)) { throw new IOException("Native CRL reconstruction differs"); }
                    digest.update((byte) value);
                }
                @Override public void write(byte[] bytes, int offset, int count) throws IOException {
                    cancellation.throwIfCancelled();
                    byte[] observed = actual.readNBytes(count);
                    if (observed.length != count || !Arrays.equals(observed, 0, count, bytes, offset, offset + count))
                        { throw new IOException("Native CRL reconstruction differs"); }
                    digest.update(bytes, offset, count);
                }
            }) {
            long written = StreamingCrlAlternativeSignature.completeTbs(alternativeTranscript, decodedNative, signature, comparison, cancellation);
            if (actual.read() != -1 || written != nativeChild.candidate().length()
                    || !HexFormat.of().formatHex(digest.digest()).equals(nativeChild.candidate().sha256()))
                { throw new IOException("Native CRL content commitment differs"); }
        }
        }
    }

    /** Checks the frozen parent and native-child authority before reading streamed content. */
    private static final class AuthorityChecks {
        private static void requireChild(DomainCommandEncoding.Decoded command, IssuerCryptographicBinding binding, EncodedObject issuerCertificate, SignWorkflowStore.Workflow parent, SignWorkflowStore.AcceptanceEnvelope envelope, CrlHybridSigningCommand.Descriptor descriptor, SignWorkflowStore.AcceptanceCommand nativeChild, IssuerKeyBinding alternative) throws GeneralSecurityException {
            requireParentBinding(command, binding, issuerCertificate, parent, envelope, descriptor, alternative);
            requireCapturedChild(binding, parent, envelope, descriptor, nativeChild);
            requireNativeChildShape(binding, nativeChild);
        }

        private static void requirePublicRoles(IssuerCryptographicBinding binding, EncodedObject issuerCertificate, DomainCommandEncoding.Decoded command, CrlHybridSigningCommand.Descriptor descriptor, PkiId parentId, KeyRef alternativeKey, String alternativeAlgorithm, IssuerKeyBinding alternative) throws GeneralSecurityException {
            requirePublicCoordinates(binding, issuerCertificate, command, descriptor);
            requirePublicRoleIdentity(binding, issuerCertificate, command, descriptor, parentId, alternativeKey, alternativeAlgorithm, alternative);
        }

        private static void requireParentBinding(DomainCommandEncoding.Decoded command, IssuerCryptographicBinding binding, EncodedObject issuerCertificate, SignWorkflowStore.Workflow parent, SignWorkflowStore.AcceptanceEnvelope envelope, CrlHybridSigningCommand.Descriptor descriptor, IssuerKeyBinding alternative) throws GeneralSecurityException {
            if (!descriptor.issuerBindingCommitment().equals(binding.commitment())
                    || !binding.issuerId().value().equals(command.field(6)) || !binding.credentialId().value().equals(command.field(7))
                    || issuerCertificate.encoding() != Encoding.DER || !sha256(issuerCertificate.bytes()).equals(binding.certificateSha256())
                    || !sha256(issuerCertificate.bytes()).equals(command.field(26))
                    || !parent.operationId().equals(envelope.operationId())
                    || !descriptor.nativeChildId().equals(CrlHybridSigningCommand.nativeChildId(parent.operationId()))
                    || !envelope.keyRef().equals(alternative.keyRef())
                    || !envelope.algorithmId().equals(alternative.signatureAlgorithm().canonicalForm())) { throw new IllegalArgumentException("Hybrid CRL child authority differs"); }
        }

        private static void requireCapturedChild(IssuerCryptographicBinding binding, SignWorkflowStore.Workflow parent, SignWorkflowStore.AcceptanceEnvelope envelope, CrlHybridSigningCommand.Descriptor descriptor, SignWorkflowStore.AcceptanceCommand nativeChild) throws GeneralSecurityException {
            if (parent.state() != SignWorkflowStore.State.SUCCEEDED
                    || !nativeChild.operationId().equals(descriptor.nativeChildId())
                    || !nativeChild.providerNamespace().equals(envelope.providerNamespace())
                    || !nativeChild.providerConfigurationCommitment().matches(envelope.providerConfigurationCommitment())
                    || !nativeChild.accessContext().equals(envelope.accessContext())
                    || !nativeChild.fairnessAuthorityId().equals(envelope.fairnessAuthorityId())
                    || !nativeChild.createdAt().equals(envelope.createdAt()) || !nativeChild.deadline().equals(envelope.deadline())
                    || !nativeChild.keyRef().equals(binding.primary().keyRef())) { throw new IllegalArgumentException("Hybrid CRL child authority differs"); }
        }

        private static void requireNativeChildShape(IssuerCryptographicBinding binding, SignWorkflowStore.AcceptanceCommand nativeChild) throws GeneralSecurityException {
            if (!nativeChild.algorithmId().equals(binding.primary().signatureAlgorithm().canonicalForm())
                    || nativeChild.outer().isPresent() || nativeChild.proofStep().isPresent() || nativeChild.alternativeProofStep().isPresent()
                    || nativeChild.mode() != SignWorkflowStore.Mode.NORMAL || nativeChild.signatureEncoding() != Encoding.BINARY) { throw new IllegalArgumentException("Hybrid CRL child authority differs"); }
        }

        private static void requirePublicCoordinates(IssuerCryptographicBinding binding, EncodedObject issuerCertificate, DomainCommandEncoding.Decoded command, CrlHybridSigningCommand.Descriptor descriptor) throws GeneralSecurityException {
            if (!descriptor.issuerBindingCommitment().equals(binding.commitment())
                    || !binding.authorityId().value().equals(command.field(0)) || !binding.formatId().equals(command.field(2))
                    || !binding.issuerId().value().equals(command.field(6)) || !binding.credentialId().value().equals(command.field(7))
                    || !binding.profile().profileId().equals(command.field(12))
                    || binding.profile().profileVersion() != Long.parseLong(command.field(13))
                    || !HexFormat.of().formatHex(binding.profile().canonicalSha256()).equals(command.field(14))
                    || !binding.bindingSetCommitment().equals(command.field(16))
                    || issuerCertificate.encoding() != Encoding.DER || issuerCertificate.bytes().length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw new IllegalArgumentException("Hybrid CRL public admission evidence differs"); }
        }

        private static void requirePublicRoleIdentity(IssuerCryptographicBinding binding, EncodedObject issuerCertificate, DomainCommandEncoding.Decoded command, CrlHybridSigningCommand.Descriptor descriptor, PkiId parentId, KeyRef alternativeKey, String alternativeAlgorithm, IssuerKeyBinding alternative) throws GeneralSecurityException {
            if (issuerCertificate.bytes().length != Long.parseLong(command.field(25))
                    || !sha256(issuerCertificate.bytes()).equals(binding.certificateSha256())
                    || !sha256(issuerCertificate.bytes()).equals(command.field(26))
                    || !descriptor.nativeChildId().equals(CrlHybridSigningCommand.nativeChildId(parentId))
                    || !alternative.keyRef().equals(alternativeKey)
                    || !alternative.signatureAlgorithm().canonicalForm().equals(alternativeAlgorithm)) { throw new IllegalArgumentException("Hybrid CRL public admission evidence differs"); }
        }
    }

    private static void requireAlternativeHeader(StreamingDerReader.CrlAlternativeTbsLayout layout,
            IssuerKeyBinding alternative, DomainCommandEncoding.Decoded command) throws IOException {
        if (!Arrays.equals(layout.alternativeAlgorithmDer(), alternative.signatureAlgorithmIdentifier().bytes())
                || !layout.thisUpdate().toString().equals(command.field(3)) || !layout.nextUpdate().toString().equals(command.field(4))
                || !layout.crlNumber().toString().equals(command.field(10))
                || !layout.deltaIndicator().equals(FullCrlSigningCommand.DELTA_OPERATION.equals(command.operation())
                        ? Optional.of(new BigInteger(command.field(32))) : Optional.empty()))
            { throw new IOException("Alternative CRL header differs from frozen command"); }
    }
}
