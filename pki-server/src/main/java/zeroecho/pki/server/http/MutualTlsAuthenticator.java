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
package zeroecho.pki.server.http;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.PkiServerConfiguration.ClientCertificateMapping;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/**
 * Production mutual-TLS authenticator using immutable cryptographic certificate
 * commitments rather than mutable subject or SAN strings.
 *
 * <p>The HTTPS handshake has already validated the chain through the configured
 * JSSE trust manager. This authenticator additionally validates validity time,
 * canonical single-certificate encoding, mapping uniqueness, and the enabled
 * state of the persisted principal.</p>
 */
@SuppressWarnings("PMD")
public final class MutualTlsAuthenticator implements PkiServerAuthenticator {
    private final List<ClientCertificateMapping> mappings;
    private final Function<String, SecurityPrincipal> principalResolver;
    private final Clock clock;

    /**
     * Creates one immutable principal mapper.
     *
     * @param mappings exact cryptographic mappings
     * @param principalResolver persisted principal resolver
     * @param clock injected validity clock
     */
    public MutualTlsAuthenticator(List<ClientCertificateMapping> mappings,
            Function<String, SecurityPrincipal> principalResolver, Clock clock) {
        this.mappings = List.copyOf(Objects.requireNonNull(mappings, "mappings"));
        this.principalResolver = Objects.requireNonNull(principalResolver, "principalResolver");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public PkiServerAuthenticationResult authenticate(PkiServerAuthenticationContext context) {
        Objects.requireNonNull(context, "context");
        try {
            for (X509Certificate certificate : context.peerCertificates()) {
                certificate.checkValidity(Date.from(clock.instant()));
                requireCanonical(certificate);
            }
            X509Certificate leaf = context.peerCertificates().getFirst();
            Commitments commitments = commitments(leaf);
            List<ClientCertificateMapping> matches = new ArrayList<>();
            for (ClientCertificateMapping mapping : mappings) {
                if (matches(mapping, commitments)) matches.add(mapping);
            }
            if (matches.isEmpty()) {
                return new PkiServerAuthenticationResult.Rejected(
                        PkiServerAuthenticationResult.Code.MAPPING_UNAVAILABLE);
            }
            if (matches.size() != 1) {
                return new PkiServerAuthenticationResult.Rejected(
                        PkiServerAuthenticationResult.Code.MAPPING_AMBIGUOUS);
            }
            SecurityPrincipal principal = principalResolver.apply(matches.getFirst().principalId());
            if (!principal.enabled()) {
                return new PkiServerAuthenticationResult.Rejected(
                        AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(),
                        Optional.of(principal.principalId()),
                        PkiServerAuthenticationResult.Code.PRINCIPAL_DISABLED);
            }
            Optional<CertificateIdentityEvidence> evidence;
            try {
                evidence = Optional.of(CertificateIdentityEvidence.fromCertificate(context.realmId(), leaf));
            } catch (IllegalArgumentException unsupportedIdentity) {
                // Authentication retains existing mapping semantics; enrollment requires this evidence separately.
                evidence = Optional.empty();
            }
            return new PkiServerAuthenticationResult.Authenticated(AdministrativeAuthenticationMode.DIRECT_MTLS,
                    Optional.empty(), principal.principalId(), evidence);
        } catch (java.security.cert.CertificateException | IllegalArgumentException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    PkiServerAuthenticationResult.Code.CERTIFICATE_INVALID);
        } catch (RuntimeException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
    }

    private static boolean matches(ClientCertificateMapping mapping, Commitments commitments) {
        return mapping.certificateSha256().map(commitments.certificate()::equals).orElse(true)
                && mapping.subjectPublicKeyInfoSha256().map(commitments.spki()::equals).orElse(true)
                && mapping.issuerSerialSha256().map(commitments.issuerSerial()::equals).orElse(true);
    }

    private static Commitments commitments(X509Certificate certificate)
            throws java.security.cert.CertificateEncodingException {
        BigInteger serial = certificate.getSerialNumber();
        if (serial.signum() <= 0) throw new IllegalArgumentException("Certificate serial is invalid");
        MessageDigest issuerSerial = sha256();
        issuerSerial.update(certificate.getIssuerX500Principal().getEncoded());
        issuerSerial.update((byte) 0);
        issuerSerial.update(serial.toByteArray());
        return new Commitments(digest(certificate.getEncoded()), digest(certificate.getPublicKey().getEncoded()),
                HexFormat.of().formatHex(issuerSerial.digest()));
    }

    private static void requireCanonical(X509Certificate certificate)
            throws java.security.cert.CertificateException {
        byte[] encoded = certificate.getEncoded();
        ByteArrayInputStream input = new ByteArrayInputStream(encoded);
        X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(input);
        if (input.available() != 0 || !Arrays.equals(encoded, parsed.getEncoded())) {
            throw new java.security.cert.CertificateException("Certificate encoding is not canonical");
        }
    }

    private static String digest(byte[] value) {
        return HexFormat.of().formatHex(sha256().digest(value));
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private record Commitments(String certificate, String spki, String issuerSerial) { }
}
