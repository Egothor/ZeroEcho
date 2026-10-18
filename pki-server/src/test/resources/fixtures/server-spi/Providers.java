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

package external.spi;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.server.spi.v2.AcmeChallengeProvider;
import zeroecho.pki.server.spi.v2.AcmeExternalAccountBindingProvider;
import zeroecho.pki.server.spi.v2.PkiServerTlsProvider;
import zeroecho.pki.server.spi.v2.PkiServerClientTrustProvider;
import zeroecho.pki.server.ct.CtLogClient;
import zeroecho.pki.server.ct.CtSubmissionException;
import zeroecho.pkix.ct.SignedCertificateTimestamp;

public final class Providers {
    public static final class Challenge implements AcmeChallengeProvider {
        public String id() { return "external-challenge"; }
        public Set<ChallengeType> challengeTypes() { return Set.of(ChallengeType.DNS_01); }
        public Result validate(Context context, ProviderConfig configuration, CancellationSignal cancellation) {
            if (!context.identifier().presentation().equals("*.example.test") || context.attempt() != 3
                    || !context.deadline().equals(context.validationTime().plusSeconds(60))
                    || !context.directoryId().equals("directory") || !context.authorizationId().equals("authorization")
                    || context.identifier().type() != IdentifierType.DNS || context.challengeType() != ChallengeType.DNS_01
                    || !context.token().equals("t".repeat(43))
                    || !context.expectedKeyAuthorization().equals("sensitive-key-authorization")
                    || !context.validationTime().equals(Instant.parse("2026-10-05T12:00:00Z"))
                    || !configuration.backendId().equals(id()) || !configuration.properties().equals(Map.of("input", "exact"))
                    || cancellation.isCancelled()) {
                throw new AssertionError("Challenge context binding changed");
            }
            return new Result(true, "VERIFIED", context.validationTime(), context.deadline());
        }
    }
    public static final class Eab implements AcmeExternalAccountBindingProvider {
        public String id() { return "external-eab"; }
        public Binding verify(Request request, ProviderConfig configuration) {
            if (!request.directoryId().equals("directory") || !request.authorityId().equals(new PkiId("authority"))
                    || !request.profileId().equals("profile") || !request.accountKeyThumbprint().equals("a".repeat(64))
                    || !request.now().equals(Instant.parse("2026-10-05T12:00:00Z"))
                    || !configuration.backendId().equals(id()) || !configuration.properties().equals(Map.of("input", "exact"))
                    || !java.util.Arrays.equals(request.nestedJws(), new byte[] {1, 2})) {
                throw new AssertionError("EAB request binding changed");
            }
            byte[] copy = request.nestedJws();
            copy[0] = 0;
            if (request.nestedJws()[0] != 1) throw new AssertionError("Mutable EAB request");
            return new Binding("key", "b".repeat(64), Set.of("example.test"), request.now().plusSeconds(60), true);
        }
    }
    public static final class Tls implements PkiServerTlsProvider {
        public String id() { return "external-tls"; }
        public SSLContext create(ProviderConfig configuration) throws Exception {
            if (configuration.get("fail").isPresent()) throw new IllegalStateException("Controlled provider failure");
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            return context;
        }
    }
    public static final class Trust implements PkiServerClientTrustProvider {
        public String id() { return "external-trust"; }
        public X509TrustManager create(ProviderConfig configuration) {
            return new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                    throw new java.security.cert.CertificateException("Fixture rejects all clients");
                }
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws java.security.cert.CertificateException {
                    throw new java.security.cert.CertificateException("Fixture rejects all servers");
                }
            };
        }
    }
    public static final class Ct implements CtLogClient {
        public String logId() { return "c".repeat(64); }
        public SignedCertificateTimestamp submit(byte[] preCert, List<byte[]> chain, Instant deadline)
                throws CtSubmissionException {
            throw new CtSubmissionException("Offline fixture", logId());
        }
        public void close() { }
    }
    public static void main(String[] arguments) throws Exception {
        Instant now = Instant.parse("2026-10-05T12:00:00Z");
        AcmeChallengeProvider challenge = ServiceLoader.load(AcmeChallengeProvider.class).findFirst().orElseThrow();
        AcmeChallengeProvider.Context context = new AcmeChallengeProvider.Context("directory", "authorization",
                new AcmeChallengeProvider.Identifier(AcmeChallengeProvider.IdentifierType.DNS, "example.test", true),
                AcmeChallengeProvider.ChallengeType.DNS_01, "t".repeat(43), "sensitive-key-authorization", 3,
                now, now.plusSeconds(60));
        if (context.toString().contains("sensitive") || context.toString().contains("t".repeat(43))) {
            throw new AssertionError("Credential diagnostic disclosure");
        }
        if (!challenge.validate(context, new ProviderConfig(challenge.id(), Map.of("input", "exact")), CancellationSignal.NONE).valid()) {
            throw new AssertionError("Challenge failed");
        }
        AcmeExternalAccountBindingProvider eab = ServiceLoader.load(AcmeExternalAccountBindingProvider.class)
                .findFirst().orElseThrow();
        byte[] payload = new byte[] {1, 2};
        AcmeExternalAccountBindingProvider.Request request = new AcmeExternalAccountBindingProvider.Request(
                "directory", new PkiId("authority"), "profile", "a".repeat(64), payload, now);
        payload[0] = 0;
        if (!eab.verify(request, new ProviderConfig(eab.id(), Map.of("input", "exact"))).consumed()) throw new AssertionError();
        PkiServerTlsProvider tls = ServiceLoader.load(PkiServerTlsProvider.class).findFirst().orElseThrow();
        if (tls.create(new ProviderConfig(tls.id(), Map.of())) == null) throw new AssertionError();
        PkiServerClientTrustProvider trust = ServiceLoader.load(PkiServerClientTrustProvider.class).findFirst().orElseThrow();
        if (trust.create(new ProviderConfig(trust.id(), Map.of())).getAcceptedIssuers().length != 0) throw new AssertionError();
        try (CtLogClient ct = new Ct()) {
            try { ct.submit(new byte[0], List.of(), now); throw new AssertionError(); }
            catch (CtSubmissionException expected) {
                if (!expected.logId().equals(ct.logId())) throw new AssertionError();
            }
        }
    }
}
