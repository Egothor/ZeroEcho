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
package zeroecho.pki.server.cmp;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cmp.CmpPbmPolicy;
import zeroecho.pkix.cmp.CmpProtectedMessage;

/** One authenticated wire call; owns and erases its binary PBM secret copy. */
final class CmpAuthentication implements AutoCloseable {
    private final CmpProtectedMessage.Verified verified;
    private final EnrollmentTransaction.Requester requester;
    private final X509Certificate certificate;
    private final List<X509Certificate> trustedChain;
    private final CmpPbmPolicy pbmPolicy;
    private final byte[] secret;

    private CmpAuthentication(CmpProtectedMessage.Verified verified, EnrollmentTransaction.Requester requester,
            X509Certificate certificate, List<X509Certificate> trustedChain, CmpPbmPolicy pbmPolicy, byte[] secret) {
        this.verified = verified; this.requester = requester; this.certificate = certificate;
        this.pbmPolicy = pbmPolicy; this.secret = secret;
        this.trustedChain = List.copyOf(trustedChain);
    }

    /* default */ static CmpAuthentication verify(CmpProtectedMessage request, boolean expectedPbm, EnrollmentRuntime.CredentialLease lease,
            RealmId realm, X500Principal serverName, Instant now, CancellationSignal cancellation) {
        if (request.isPbm() != expectedPbm || !request.recipient().equals(serverName)) {
            throw invalid();
        }
        if (expectedPbm) {
            return verifyPbm(request, lease, realm, cancellation);
        }
        X509Certificate responseSigner = lease.responseChain().getFirst();
        if (request.recipientKid().filter(value -> !MessageDigest.isEqual(value, CmpProtectedMessage.certificateKeyId(responseSigner))).isPresent()) {
            throw invalid();
        }
        List<X509Certificate> candidates = new ArrayList<>();
        for (byte[] der : request.extraCertificates()) {
            candidates.add(parseCandidate(der));
        }
        CmpAuthentication result = null;
        for (X509Certificate candidate : candidates) {
            if (!request.sender().equals(candidate.getSubjectX500Principal())) {
                continue;
            }
            CmpAuthentication authenticated; // NOPMD CloseResource - Signature-only proof owns no secret; the unique returned result is closed by the caller.
            try {
                authenticated = authenticateSigner(request, candidate, candidates, lease, realm, now);
            } catch (GeneralSecurityException | IllegalArgumentException failure) { continue; }
            if (result != null) {
                throw invalid();
            }
            result = authenticated;
        }
        if (result == null) {
            throw invalid();
        }
        return result;
    }

    private static X509Certificate parseCandidate(byte[] der) {
        X509Certificate candidate = Pkix.parseCertificate(der);
        try {
            if (!Arrays.equals(der, candidate.getEncoded())) {
                throw invalid();
            }
        } catch (GeneralSecurityException failure) {
            throw invalid(); // NOPMD PreserveStackTrace - Provider encoding diagnostics may disclose sensitive request material.
        }
        return candidate;
    }

    private static CmpAuthentication authenticateSigner(CmpProtectedMessage request, X509Certificate candidate,
            List<X509Certificate> candidates, EnrollmentRuntime.CredentialLease lease, RealmId realm, Instant now)
            throws GeneralSecurityException {
        CmpProtectedMessage.Verified verified = request.verifySignature(candidate);
        List<X509Certificate> path = requireTrust(candidate, candidates, lease.requestTrustAnchors(), now);
        CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(realm, candidate);
        EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.CMP_SIGNER,
                evidence.certificateSha256(), IssuanceExecutionEvidence.Authentication.CMP_SIGNATURE, Optional.of(evidence),
                Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(),
                new EnrollmentIdentityAliases.Snapshot(realm, Set.of()));
        return new CmpAuthentication(verified, requester, candidate, path, null, null);
    }

    private static CmpAuthentication verifyPbm(CmpProtectedMessage request, EnrollmentRuntime.CredentialLease lease,
            RealmId realm, CancellationSignal cancellation) {
        String kid = HexFormat.of().formatHex(request.senderKid().orElseThrow(CmpAuthentication::invalid));
        EnrollmentRuntimeConfiguration.Pbm configured = lease.configuration().pbm().orElseThrow(CmpAuthentication::invalid);
        EnrollmentRuntimeConfiguration.PbmIdentity identity = configured.identities().stream()
                .filter(value -> value.senderKid().equals(kid)).findFirst().orElseThrow(CmpAuthentication::invalid);
        if (request.recipientKid().filter(value -> !MessageDigest.isEqual(value, HexFormat.of().parseHex(kid))).isPresent()) {
            throw invalid();
        }
        CmpPbmPolicy policy = policy(configured);
        byte[] owned = lease.pbmSecret(kid).getEncoded();
        if (owned == null) {
            throw invalid();
        }
        try {
            CmpProtectedMessage.Verified verified = request.verifyPbm(policy, owned, cancellation);
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.CMP_PBM,
                    identity.identityId(), IssuanceExecutionEvidence.Authentication.CMP_PBM, Optional.empty(), Optional.empty(), Set.of(),
                    new EnrollmentIdentityAliases.Snapshot(realm, Set.copyOf(identity.ownerAliases())));
            return new CmpAuthentication(verified, requester, null, List.of(), policy, owned);
        } catch (RuntimeException failure) { Arrays.fill(owned, (byte) 0); throw invalid(); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private static List<X509Certificate> requireTrust(X509Certificate signer, List<X509Certificate> candidates, List<X509Certificate> anchors, Instant now)
            throws GeneralSecurityException {
        signer.checkValidity(Date.from(now));
        boolean[] usage = signer.getKeyUsage();
        if (usage == null || usage.length == 0 || !usage[0]) {
            throw invalid();
        }
        Set<TrustAnchor> trusted = new HashSet<>();
        for (X509Certificate anchor : anchors) {
            anchor.checkValidity(Date.from(now));
            trusted.add(new TrustAnchor(anchor, null));
        }
        if (trusted.isEmpty()) {
            throw invalid();
        }
        X509CertSelector selector = new X509CertSelector(); selector.setCertificate(signer);
        PKIXBuilderParameters parameters = new PKIXBuilderParameters(trusted, selector);
        parameters.setDate(Date.from(now)); parameters.setRevocationEnabled(false);
        parameters.setMaxPathLength(CmpProtectedMessage.MAXIMUM_EXTRA_CERTIFICATES - 1);
        parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(candidates)));
        PKIXCertPathBuilderResult built = (PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(parameters);
        List<X509Certificate> path = new ArrayList<>();
        for (java.security.cert.Certificate value : built.getCertPath().getCertificates()) {
            path.add((X509Certificate) value);
        }
        path.add(built.getTrustAnchor().getTrustedCert());
        return List.copyOf(path);
    }

    /* default */ CmpProtectedMessage.Verified verified() { return verified; }
    /* default */ EnrollmentTransaction.Requester requester() { return requester; }
    /* default */ Optional<X509Certificate> certificate() { return Optional.ofNullable(certificate); }
    /* default */ List<X509Certificate> trustedChain() { return trustedChain; }
    /* default */ CmpPbmPolicy pbmPolicy() { if (pbmPolicy == null) {
        throw invalid();
    } return pbmPolicy; }

    /* default */ byte[] protect(CmpProtectedMessage.Response response, EnrollmentRuntime.CredentialLease lease, X500Principal serverName,
            byte[] salt, byte[] nonce, Instant time, CancellationSignal cancellation) {
        if (secret != null) {
            return verified.protectPbm(response, serverName, pbmPolicy, secret, salt, nonce, time, cancellation);
        }
        List<byte[]> chain = new ArrayList<>();
        try { for (X509Certificate value : lease.responseChain()) {
            chain.add(value.getEncoded());
        } }
        catch (GeneralSecurityException failure) { throw invalid(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        return verified.sign(response, lease.responseChain().getFirst(), lease.privateKey(), chain, nonce, time);
    }

    private static CmpPbmPolicy policy(EnrollmentRuntimeConfiguration.Pbm value) {
        Set<String> digests = new HashSet<>();
        for (EnrollmentRuntimeConfiguration.PbmDigest digest : value.digests()) {
            digests.add(switch (digest) {
            case SHA256 -> "2.16.840.1.101.3.4.2.1"; case SHA384 -> "2.16.840.1.101.3.4.2.2"; case SHA512 -> "2.16.840.1.101.3.4.2.3";
        });
        }
        Set<String> macs = new HashSet<>();
        for (EnrollmentRuntimeConfiguration.PbmMac mac : value.macs()) {
            macs.add(switch (mac) {
            case HMAC_SHA256 -> "1.2.840.113549.2.9"; case HMAC_SHA384 -> "1.2.840.113549.2.10"; case HMAC_SHA512 -> "1.2.840.113549.2.11";
        });
        }
        return new CmpPbmPolicy(value.minimumIterations(), value.maximumIterations(), value.minimumSaltBytes(), value.maximumSaltBytes(), digests, macs);
    }

    @Override public void close() { if (secret != null) {
        Arrays.fill(secret, (byte) 0);
    } }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("CMP authentication failed"); }
}
