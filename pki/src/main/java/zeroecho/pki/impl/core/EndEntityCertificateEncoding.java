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

import java.security.GeneralSecurityException;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest;
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
import zeroecho.pki.spi.crypto.AltSigningCapability;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Optional;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.hybrid.sdk.SdkIssuancePreview;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.sign.ContentVerifier;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.Set;
import zeroecho.pki.api.profile.ExtendedKeyUsageId;
import zeroecho.pki.api.profile.LeafKeyUsage;
import zeroecho.pki.api.request.SubjectAlternativeName;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.ExtendedKeyUsage;
import zeroecho.pkix.GeneralName;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

/**
 * Builds end-entity certificate encodings from validated issuance inputs.
 *
 * <p>Builds certificate fields from the validated issuance preparation, including hybrid
 * signature extensions when requested.
 */
final class EndEntityCertificateEncoding {
    private EndEntityCertificateEncoding() { }
    /* default */ static byte[] tbs(EndEntityIssuancePreparation.Prepared approved) {
        return leafBuilder(approved).buildTbs(approved.signatureBinding());
    }

    /* default */ static CertificateBuilder leafBuilder(EndEntityIssuancePreparation.Prepared approved) {
        ValidatedCertificateRequest request = approved.request();
        CertificateBuilder builder = Pkix.certificateBuilder().serialNumber(approved.serial())
                .issuer(Pkix.parseCertificate(approved.issuerDer()).getSubjectX500Principal())
                .subject(BcX509ProfileSupport.subject(request.subjectRdns()))
                .validity(request.validity().notBefore(), request.validity().notAfter())
                .publicKeyInfo(request.exactPublicKey().bytes())
                .basicConstraints(BasicConstraints.endEntity(), request.basicConstraintsCritical());
        if (!request.keyUsages().isEmpty()) {
            builder.keyUsage(keyUsages(request.keyUsages()), request.keyUsageCritical());
        }
        if (!request.extendedKeyUsages().isEmpty()) {
            builder.extendedKeyUsage(new ExtendedKeyUsage(request.extendedKeyUsages().stream()
                    .map(ExtendedKeyUsageId::oid).sorted().toList()), request.extendedKeyUsageCritical());
        }
        if (!request.subjectAlternativeNames().isEmpty()) {
            builder.subjectAlternativeNames(request.subjectAlternativeNames().stream()
                    .map(EndEntityCertificateEncoding::generalName).toList(), request.subjectAlternativeNameCritical());
        }
        return builder;
    }

    /* default */ static Set<KeyUsage> keyUsages(Set<LeafKeyUsage> source) {
        Set<KeyUsage> result = EnumSet.noneOf(KeyUsage.class);
        for (LeafKeyUsage usage : source) {
            result.add(switch (usage) {
                case DIGITAL_SIGNATURE -> KeyUsage.DIGITAL_SIGNATURE;
                case CONTENT_COMMITMENT -> KeyUsage.NON_REPUDIATION;
                case KEY_ENCIPHERMENT -> KeyUsage.KEY_ENCIPHERMENT;
                case DATA_ENCIPHERMENT -> KeyUsage.DATA_ENCIPHERMENT;
                case KEY_AGREEMENT -> KeyUsage.KEY_AGREEMENT;
                case ENCIPHER_ONLY -> KeyUsage.ENCIPHER_ONLY;
                case DECIPHER_ONLY -> KeyUsage.DECIPHER_ONLY;
            });
        }
        return result;
    }

    /* default */ static GeneralName generalName(SubjectAlternativeName name) {
        return switch (name) {
            case SubjectAlternativeName.DnsName dns -> new GeneralName.DnsName(dns.value());
            case SubjectAlternativeName.Rfc822Name email -> new GeneralName.Rfc822Name(email.value());
            case SubjectAlternativeName.UriName uri -> new GeneralName.UniformResourceIdentifier(uri.value());
            case SubjectAlternativeName.IpAddress ip -> new GeneralName.IpAddress(ipLiteral(ip.bytes()));
        };
    }

    /* default */ static String ipLiteral(byte[] octets) {
        try {
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (UnknownHostException impossible) {
            throw new IllegalArgumentException("Invalid validated IP address length", impossible);
        }
    }

    /* default */ static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    /* default */ static byte[] buildHybridTbs(EndEntityIssuancePreparation.Prepared approved,
            ParsedHybridSdkRequest parsed, SdkIssuancePreview preview, EndEntityIssuancePreparation validation) throws IOException {
        CertificateBuilder builder = leafBuilder(approved);
        IssuerKeyBinding issuerAlternative = approved.issuerBinding().alternative()
                .orElseThrow(() -> new PkiException("SDK_ISSUER_NOT_HYBRID"));
        AlgorithmIdentifier altAlgorithm = Pkix.parseAlgorithmIdentifier(issuerAlternative.signatureAlgorithmIdentifier().bytes());
        builder.addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(
                        parsed.alternativeSubjectPublicKeyInfo().bytes()))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgorithm));
        byte[] transcript = builder.buildAlternativeSignatureTbs(approved.signatureBinding());
        X509AuthoritySnapshot authority = validation.authority();
        X509ExecutionPlan<SigningProvider> plan = authority.plan(issuerAlternative.signatureAlgorithm(), issuerAlternative.publicKeyAlgorithm(),
                AlgorithmExecutionCapability.Direction.SIGN, Optional.empty(), "explicit",
                SigningProvider.class);
        authority.authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        if (!(plan.executor() instanceof AltSigningCapability signer)) {
            throw new PkiException("ALT_SIGNING_CAPABILITY_UNAVAILABLE");
        }
        byte[] signature;
        try {
            signature = signer.sign(issuerAlternative.keyRef(), issuerAlternative.signatureAlgorithm().canonicalForm(), transcript);
        } catch (GeneralSecurityException failure) {
            throw new PkiException("ALT_SIGNING_FAILED", failure);
        }
        ContentVerifier verifier = Pkix.verifier(preview.issuerAlternativeSpki().orElseThrow().bytes(), altAlgorithm);
        try (OutputStream output = verifier.contentStream()) {
            output.write(transcript);
        }
        if (!verifier.verify(signature)) {
            throw new PkiException("ALT_SIGNATURE_INVALID");
        }
        byte[] completeTbs = builder.addExtension(AltSignatureExtensions.altSignatureValue(signature))
                .buildTbs(approved.signatureBinding());
        return completeTbs;
    }
}
