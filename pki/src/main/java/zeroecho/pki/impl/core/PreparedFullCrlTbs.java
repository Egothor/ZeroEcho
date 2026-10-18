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
 * @param tbsContent completed operation-owned DER TBSCertList
 */
public record PreparedFullCrlTbs(PkiId authorityId, PkiId issuerGenerationId, PkiId issuerCredentialId,
        CertificateProfileRef profile, DurableContentReference issuerContent, String scopeDigest,
        String profilePolicyCommitment, String x509BindingCommitment, KeyRef signingKeyRef,
        String signatureAlgorithm, X509AlgorithmBinding signatureBinding, X509AlgorithmIdentifier signatureIdentifier, BigInteger crlNumber,
        Instant evaluationTime, Instant thisUpdate, Instant nextUpdate, String snapshotId,
        MetadataStoreId snapshotSourceStoreId, long snapshotRevision, long snapshotBoundary, String snapshotCommitment, OptionalLong rawEntryCount,
        long emittedEntryCount, DurableContentReference tbsContent, Optional<DeltaCrlBase> base) {
    @Override public String toString() { return "PreparedFullCrlTbs[redacted]"; }
}
