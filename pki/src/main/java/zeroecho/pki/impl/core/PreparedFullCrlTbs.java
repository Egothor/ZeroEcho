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
import java.util.Objects;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pkix.Pkix;

import java.math.BigInteger;
import java.time.Instant;
import java.util.OptionalLong;
import java.util.Optional;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.framework.x509.X509AlgorithmIdentifier;

/**
 * Provider-free, resource-free evidence for one fully staged full CRL TBS.
 * Contains only immutable identifiers, commitments, scalar provenance and
 * content references; it grants no signing authorization or workflow custody.
 * The number is already durably consumed even if the content is later retired.
 * Public visibility bridges unexported implementation packages only.
 *
 * @param authorityId logical issuer authority
 * @param issuerGenerationId selected immutable issuer generation
 * @param issuerCredentialId exact issuer credential
 * @param profile selected versioned profile
 * @param issuerContent exact bounded issuer certificate content
 * @param scopeDigest canonical CRL numbering scope digest
 * @param profilePolicyCommitment frozen issuer policy commitment
 * @param x509BindingCommitment frozen issuer binding commitment
 * @param signingKeyRef selected managed signing key
 * @param signatureAlgorithm canonical semantic signature identity
 * @param signatureBinding exact selected signature binding descriptor
 * @param signatureIdentifier exact inner and outer AlgorithmIdentifier
 * @param crlNumber irreversibly reserved CRL number
 * @param evaluationTime precise preparation evaluation time
 * @param thisUpdate normalized current update time
 * @param nextUpdate normalized next update time
 * @param snapshotId stable revocation snapshot identity
 * @param snapshotSourceStoreId source identity captured by that same snapshot
 * @param snapshotRevision frozen snapshot revision
 * @param base frozen validated full CRL base, empty for a full CRL
 * @param snapshotBoundary frozen snapshot journal boundary
 * @param snapshotCommitment immutable snapshot commitment
 * @param rawEntryCount optional raw snapshot row count
 * @param emittedEntryCount exact emitted revocation count
 * @param hybrid optional captured two-role alternative-transcript preparation
 * @param tbsContent completed operation-owned DER TBSCertList
 */
public record PreparedFullCrlTbs(PkiId authorityId, PkiId issuerGenerationId, PkiId issuerCredentialId,
        CertificateProfileRef profile, DurableContentReference issuerContent, String scopeDigest,
        String profilePolicyCommitment, String x509BindingCommitment, KeyRef signingKeyRef,
        String signatureAlgorithm, X509AlgorithmBinding signatureBinding, X509AlgorithmIdentifier signatureIdentifier, BigInteger crlNumber,
        Instant evaluationTime, Instant thisUpdate, Instant nextUpdate, String snapshotId,
        MetadataStoreId snapshotSourceStoreId, long snapshotRevision, long snapshotBoundary, String snapshotCommitment,
        OptionalLong rawEntryCount,
        long emittedEntryCount, DurableContentReference tbsContent, Optional<DeltaCrlBase> base, Optional<Hybrid> hybrid) {
    /**
     * Checks hybrid carrier consistency against its actual selected CRL binding.
     * Native-only carrier behavior is preserved. Cryptographic authority remains
     * with configured preparation and the adoption verifier, not this constructor.
     * @throws NullPointerException if a hybrid structural coordinate is null
     * @throws IllegalArgumentException if captured roles or selected presentation disagree
     * @param authorityId logical issuer authority
     * @param issuerGenerationId selected immutable issuer generation
     * @param issuerCredentialId exact issuer credential
     * @param profile selected versioned profile
     * @param issuerContent exact bounded issuer certificate content
     * @param scopeDigest canonical CRL numbering scope digest
     * @param profilePolicyCommitment frozen issuer policy commitment
     * @param x509BindingCommitment frozen issuer binding commitment
     * @param signingKeyRef selected managed signing key
     * @param signatureAlgorithm canonical semantic signature identity
     * @param signatureBinding exact selected signature binding descriptor
     * @param signatureIdentifier exact inner and outer AlgorithmIdentifier
     * @param crlNumber irreversibly reserved CRL number
     * @param evaluationTime precise preparation evaluation time
     * @param thisUpdate normalized current update time
     * @param nextUpdate normalized next update time
     * @param snapshotId stable revocation snapshot identity
     * @param snapshotSourceStoreId source identity captured by that same snapshot
     * @param snapshotRevision frozen snapshot revision
     * @param snapshotBoundary frozen snapshot journal boundary
     * @param snapshotCommitment immutable snapshot commitment
     * @param rawEntryCount optional raw snapshot row count
     * @param emittedEntryCount exact emitted revocation count
     * @param tbsContent completed operation-owned DER TBSCertList
     * @param base frozen validated full CRL base, empty for a full CRL
     * @param hybrid optional captured two-role alternative-transcript preparation
     */
    public PreparedFullCrlTbs {
        Objects.requireNonNull(hybrid, "hybrid");
        if (hybrid.isPresent()) {
            Hybrid selected = hybrid.orElseThrow();
            IssuerKeyBinding primary = selected.binding().primary();
            if (!selected.binding().issuerId().equals(issuerGenerationId)
                    || !selected.binding().authorityId().equals(authorityId)
                    || !selected.binding().credentialId().equals(issuerCredentialId)
                    || !selected.binding().profile().equals(profile)
                    || !selected.binding().bindingSetCommitment().equals(x509BindingCommitment)
                    || !primary.keyRef().equals(signingKeyRef)
                    || !primary.signatureAlgorithm().canonicalForm().equals(signatureAlgorithm)
                    || !signatureBinding.algorithmIdentity().equals(primary.signatureAlgorithm())
                    || signatureBinding.role() != X509AlgorithmBinding.Role.CRL_SIGNATURE
                    || !signatureBinding.oid().equals(signatureIdentifier.oid())
                    || !switch (signatureBinding.parameterRule()) {
                        case ABSENT -> signatureIdentifier.parameterForm() == X509AlgorithmIdentifier.ParameterForm.ABSENT;
                        case DER_NULL -> signatureIdentifier.parameterForm() == X509AlgorithmIdentifier.ParameterForm.DER_NULL;
                        case STRUCTURED_DER -> signatureIdentifier.parameterForm() == X509AlgorithmIdentifier.ParameterForm.EXACT_DER;
                    }) {
                throw new IllegalArgumentException("Hybrid CRL selected native role differs");
            }
            requireAlgorithm(signatureIdentifier);
            Objects.requireNonNull(tbsContent, "tbsContent");
            if (tbsContent.encoding() != Encoding.DER
                    || tbsContent.lifecycle() != DurableContentReference.Lifecycle.OPERATION || tbsContent.length() <= 0) {
                throw new IllegalArgumentException("Hybrid CRL transcript content is invalid");
            }
        }
    }

    private static void requireAlgorithm(X509AlgorithmIdentifier identifier) {
        byte[] der = Pkix.encodeAlgorithmIdentifier(
                BcX509AlgorithmAdapter.toLib(identifier));
        try {
            new StreamingDerReader().validate(der, 16_384);
        } catch (IOException invalid) {
            throw new IllegalArgumentException("Invalid CRL AlgorithmIdentifier", invalid);
        }
    }

    /**
     * Creates a native-only prepared carrier without alternative-transcript evidence.
     *
     * <p>This overload retains the supplied immutable preparation coordinates and
     * uses an empty hybrid optional. Preparation and adoption remain responsible for
     * validating those coordinates; construction does not reserve a CRL number,
     * resolve content or acquire signing custody.
     *
     * @param authorityId logical issuer authority
     * @param issuerGenerationId selected immutable issuer generation
     * @param issuerCredentialId exact issuer credential
     * @param profile selected versioned profile
     * @param issuerContent bounded issuer certificate content reference
     * @param scopeDigest canonical CRL numbering-scope digest
     * @param profilePolicyCommitment frozen issuer policy commitment
     * @param x509BindingCommitment frozen issuer binding commitment
     * @param signingKeyRef selected managed primary signing key
     * @param signatureAlgorithm canonical semantic signature identity
     * @param signatureBinding selected native CRL signature binding
     * @param signatureIdentifier inner and outer native AlgorithmIdentifier
     * @param crlNumber already durably reserved CRL number
     * @param evaluationTime precise preparation evaluation time
     * @param thisUpdate normalized current update time
     * @param nextUpdate normalized next update time
     * @param snapshotId retained revocation-snapshot identity
     * @param snapshotSourceStoreId source identity captured by that snapshot
     * @param snapshotRevision frozen snapshot revision
     * @param snapshotBoundary frozen snapshot journal boundary
     * @param snapshotCommitment immutable snapshot commitment
     * @param rawEntryCount optional raw snapshot row count
     * @param emittedEntryCount exact emitted revocation count
     * @param tbsContent completed operation-owned DER TBSCertList reference
     * @param base validated full CRL base, or an empty optional for a full CRL
     */
    // Retain the established public compatibility constructor.
    @SuppressWarnings("PMD.ExcessiveParameterList")
    public PreparedFullCrlTbs(PkiId authorityId, PkiId issuerGenerationId, PkiId issuerCredentialId,
            CertificateProfileRef profile, DurableContentReference issuerContent, String scopeDigest,
            String profilePolicyCommitment, String x509BindingCommitment, KeyRef signingKeyRef,
            String signatureAlgorithm, X509AlgorithmBinding signatureBinding, X509AlgorithmIdentifier signatureIdentifier,
            BigInteger crlNumber, Instant evaluationTime, Instant thisUpdate, Instant nextUpdate, String snapshotId,
            MetadataStoreId snapshotSourceStoreId, long snapshotRevision, long snapshotBoundary, String snapshotCommitment,
            OptionalLong rawEntryCount, long emittedEntryCount, DurableContentReference tbsContent, Optional<DeltaCrlBase> base) {
        this(authorityId, issuerGenerationId, issuerCredentialId, profile, issuerContent, scopeDigest,
                profilePolicyCommitment, x509BindingCommitment, signingKeyRef, signatureAlgorithm, signatureBinding,
                signatureIdentifier, crlNumber, evaluationTime, thisUpdate, nextUpdate, snapshotId, snapshotSourceStoreId,
                snapshotRevision, snapshotBoundary, snapshotCommitment, rawEntryCount, emittedEntryCount, tbsContent, base, Optional.empty());
    }

    /**
     * Captures the public role plans used to prepare a hybrid CRL transcript.
     *
     * <p>The carrier holds no private keys or runtime executor tokens. Its commitments
     * identify the compatible signer tuple and both implementation plans; configured
     * adoption and cryptographic verification are still required before signing.
     *
     * @param binding immutable issuer binding with an alternative signer role
     * @param alternativeIdentifier canonical alternative CRL AlgorithmIdentifier
     * @param tupleCommitment compatible signer-tuple digest as 64 lowercase hexadecimal characters
     * @param lineageId immutable signer-lineage identity; must not be {@code null}
     * @param primaryPlanCommitment primary plan digest as 64 lowercase hexadecimal characters
     * @param alternativePlanCommitment alternative plan digest as 64 lowercase hexadecimal characters
     * @param alternativeMaximumSignatureBytes alternative signature bound, between 1 and 1,048,576 bytes
     * @param primaryMaximumSignatureBytes primary signature bound, between 1 and 1,048,576 bytes
     */
    // Component names are retained public accessors used by existing callers.
    @SuppressWarnings("PMD.LongVariable")
    public record Hybrid(IssuerCryptographicBinding binding,
            X509AlgorithmIdentifier alternativeIdentifier, String tupleCommitment, PkiId lineageId,
            String primaryPlanCommitment, String alternativePlanCommitment,
            int alternativeMaximumSignatureBytes, int primaryMaximumSignatureBytes) {
        /**
         * Checks bounded immutable structure; configured decoding and cryptographic checks remain mandatory.
         * @throws NullPointerException if a structural coordinate is null
         * @throws IllegalArgumentException for absent alternative role, invalid digest, DER or signature bound
         * @param binding immutable issuer binding with an alternative signer role
         * @param alternativeIdentifier canonical alternative CRL AlgorithmIdentifier
         * @param tupleCommitment compatible signer-tuple digest as 64 lowercase hexadecimal characters
         * @param lineageId immutable signer-lineage identity; must not be {@code null}
         * @param primaryPlanCommitment primary plan digest as 64 lowercase hexadecimal characters
         * @param alternativePlanCommitment alternative plan digest as 64 lowercase hexadecimal characters
         * @param alternativeMaximumSignatureBytes alternative signature bound, between 1 and 1,048,576 bytes
         * @param primaryMaximumSignatureBytes primary signature bound, between 1 and 1,048,576 bytes
         */
        public Hybrid {
            Objects.requireNonNull(binding, "binding");
            Objects.requireNonNull(alternativeIdentifier, "alternativeIdentifier");
            Objects.requireNonNull(lineageId, "lineageId");
            if (binding.alternative().isEmpty() || alternativeMaximumSignatureBytes < 1 || alternativeMaximumSignatureBytes > 1_048_576
                    || primaryMaximumSignatureBytes < 1 || primaryMaximumSignatureBytes > 1_048_576) {
                throw new IllegalArgumentException("Invalid hybrid CRL role or bound");
            }
            for (String digest : new String[] {tupleCommitment, primaryPlanCommitment, alternativePlanCommitment}) {
                if (digest == null || !digest.matches("[0-9a-f]{64}")) {
                    throw new IllegalArgumentException("Invalid hybrid CRL plan commitment");
                }
            }
            requireAlgorithm(alternativeIdentifier);
        }
    }

    /**
     * Returns a diagnostic label without exposing issuer, snapshot or content coordinates.
     *
     * @return the fixed redacted prepared-CRL label
     */
    @Override
    public String toString() {
        return "PreparedFullCrlTbs[redacted]";
    }
}
