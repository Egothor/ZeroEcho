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

package zeroecho.pki.impl.core.signing;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.issuance.CorrelatedEndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.IssuanceIntent;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.core.CorrelatedIssuanceIdentity;

final class CorrelatedIssuanceIdentityTest {
    private static final String DIGEST = "1".repeat(64);
    private static final Instant NOW = Instant.parse("2026-01-02T03:04:05Z");

    @Test
    void stableKeyIsNamespacedAndIndependentOfEffectiveCommitment() {
        CorrelatedEndEntityIssuanceRequest request = request("authority", "order", DIGEST, "profile", 1,
                DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty());
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(request);
        assertEquals(identity, CorrelatedIssuanceIdentity.derive(request));
        assertEquals("issuance.a134bb5c6fc1283746d3e7f9f15b4ada31074c8dfd7e982dd5d887b589b5c9db", identity.correlationId());
        assertEquals("19d0d54661bda7b6eaad03f8292fd050f093c77f47f1be381af6be8ce207efd3", identity.effectiveCommitment());
        CorrelatedEndEntityIssuanceRequest crmf = new CorrelatedEndEntityIssuanceRequest(
                new EndEntityIssuanceRequest(request.request().issuerCaId(), new zeroecho.pki.api.request.X509EnrollmentPayload(
                        zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, request.request().csrDer()),
                        request.request().profileId(), request.request().validityOverride()), request.intent());
        assertEquals(identity.correlationId(), CorrelatedIssuanceIdentity.derive(crmf).correlationId());
        assertNotEquals(identity.effectiveCommitment(), CorrelatedIssuanceIdentity.derive(crmf).effectiveCommitment());
        assertEquals(identity.correlationId(), CorrelatedIssuanceIdentity.correlationId(
                request.request().issuerCaId(), request.intent().issuanceId()));
        assertTrue(identity.correlationId().startsWith("issuance."));
        assertTrue(identity.correlationId().matches("[a-z0-9][a-z0-9._:-]{0,127}"));
        CorrelatedIssuanceIdentity different = CorrelatedIssuanceIdentity.derive(request("authority", "order",
                "2".repeat(64), "profile", 1, DIGEST, "issuer", "path", DIGEST,
                new byte[] { 1 }, Optional.empty()));
        assertEquals(identity.correlationId(), different.correlationId());
        assertNotEquals(identity.effectiveCommitment(), different.effectiveCommitment());
    }

    @Test
    void renewalCommitmentBindsEveryPredecessorCoordinateAndRejectsMalformedInput() {
        CorrelatedEndEntityIssuanceRequest issue = request("authority", "order", DIGEST, "profile", 1,
                DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty());
        zeroecho.pki.api.issuance.EndEntityRenewalRequest predecessor = new zeroecho.pki.api.issuance.EndEntityRenewalRequest(
                new PkiId("x509:" + DIGEST), Optional.empty());
        zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest renewal = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                issue.request().issuerCaId(), predecessor, DIGEST, issue.intent());
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(renewal);
        zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest original = new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                renewal.issuerCaId(), renewal.request(), renewal.predecessorSha256(), renewal.intent(), Optional.of(
                        new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, new byte[] {1})));
        CorrelatedIssuanceIdentity withOriginal = CorrelatedIssuanceIdentity.derive(original);
        assertEquals(identity.correlationId(), withOriginal.correlationId());
        assertNotEquals(identity.effectiveCommitment(), withOriginal.effectiveCommitment());
        for (zeroecho.pki.api.request.X509EnrollmentPayload payload : java.util.List.of(
                new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10, new byte[] {2}),
                new zeroecho.pki.api.request.X509EnrollmentPayload(zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF, new byte[] {1}))) {
            CorrelatedIssuanceIdentity changed = CorrelatedIssuanceIdentity.derive(new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                    renewal.issuerCaId(), renewal.request(), renewal.predecessorSha256(), renewal.intent(), Optional.of(payload)));
            assertEquals(identity.correlationId(), changed.correlationId());
            assertNotEquals(withOriginal.effectiveCommitment(), changed.effectiveCommitment());
        }
        assertEquals(CorrelatedIssuanceIdentity.derive(issue).correlationId(), identity.correlationId());
        assertNotEquals(CorrelatedIssuanceIdentity.derive(issue).effectiveCommitment(), identity.effectiveCommitment());
        for (int field = 0; field < 3; field++) {
            zeroecho.pki.api.issuance.EndEntityRenewalRequest changed = new zeroecho.pki.api.issuance.EndEntityRenewalRequest(
                    field == 0 ? new PkiId("x509:" + "2".repeat(64)) : predecessor.existingCredentialId(),
                    field == 2 ? Optional.of(new Validity(NOW, NOW.plusSeconds(30))) : Optional.empty());
            assertNotEquals(identity.effectiveCommitment(), CorrelatedIssuanceIdentity.derive(
                    new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(renewal.issuerCaId(), changed,
                            field == 1 ? "2".repeat(64) : DIGEST, renewal.intent())).effectiveCommitment());
        }
        assertThrows(IllegalArgumentException.class, () -> new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                renewal.issuerCaId(), predecessor, "not-a-digest", renewal.intent()));
        assertThrows(IllegalArgumentException.class, () -> new zeroecho.pki.api.issuance.CorrelatedEndEntityRenewalRequest(
                renewal.issuerCaId(), new zeroecho.pki.api.issuance.EndEntityRenewalRequest(new PkiId("x".repeat(4097)), Optional.empty()),
                DIGEST, renewal.intent()));
    }

    @Test
    void everyFrozenInputChangesEffectiveCommitment() {
        CorrelatedIssuanceIdentity original = CorrelatedIssuanceIdentity.derive(request("authority", "order",
                DIGEST, "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty()));
        for (int field = 0; field < 12; field++) {
            CorrelatedEndEntityIssuanceRequest changed = request(field == 0 ? "other" : "authority",
                    field == 1 ? "other" : "order", field == 2 ? "2".repeat(64) : DIGEST,
                    field == 3 ? "other" : "profile", field == 4 ? 2 : 1,
                    field == 5 ? "2".repeat(64) : DIGEST, field == 6 ? "other" : "issuer",
                    field == 7 ? "other" : "path", field == 8 ? "2".repeat(64) : DIGEST,
                    field == 9 ? new byte[] { 1, 0 } : new byte[] { 1 },
                    field >= 10 ? Optional.of(new Validity(NOW.plusNanos(field == 11 ? 1 : 0),
                            NOW.plusSeconds(30))) : Optional.empty());
            CorrelatedIssuanceIdentity derived = CorrelatedIssuanceIdentity.derive(changed);
            assertNotEquals(original.effectiveCommitment(), derived.effectiveCommitment(), "field " + field);
            if (field > 1) {
                assertEquals(original.correlationId(), derived.correlationId());
            }
        }
        CorrelatedIssuanceIdentity nanos = CorrelatedIssuanceIdentity.derive(request("authority", "order",
                DIGEST, "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 },
                Optional.of(new Validity(NOW, NOW.plusSeconds(30)))));
        assertNotEquals(nanos, CorrelatedIssuanceIdentity.derive(request("authority", "order", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 },
                Optional.of(new Validity(NOW, NOW.plusSeconds(30).plusNanos(1))))));
        assertNotEquals(nanos, CorrelatedIssuanceIdentity.derive(request("authority", "order", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 },
                Optional.of(new Validity(NOW.plusNanos(1), NOW.plusSeconds(30))))));
    }

    @Test
    void replacementBindsPayloadKindBytesPredecessorAndFrozenSelectionInSeparateDomain() {
        CorrelatedEndEntityIssuanceRequest issue = request("authority", "order", DIGEST, "profile", 1,
                DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty());
        zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest original = new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(
                issue.request().issuerCaId(), new zeroecho.pki.api.issuance.EndEntityReplacementRequest(
                        new PkiId("predecessor"), new byte[] { 1 }, "profile"), DIGEST, issue.intent());
        CorrelatedIssuanceIdentity identity = CorrelatedIssuanceIdentity.derive(original);
        assertEquals(CorrelatedIssuanceIdentity.derive(issue).correlationId(), identity.correlationId());
        assertNotEquals(CorrelatedIssuanceIdentity.derive(issue).effectiveCommitment(), identity.effectiveCommitment());
        for (int change = 0; change < 9; change++) {
            zeroecho.pki.api.request.X509EnrollmentPayload payload = new zeroecho.pki.api.request.X509EnrollmentPayload(
                    change == 0 ? zeroecho.pki.api.request.X509EnrollmentPayload.Kind.CRMF : zeroecho.pki.api.request.X509EnrollmentPayload.Kind.PKCS10,
                    new byte[] { (byte) (change == 1 ? 2 : 1) });
            IssuanceIntent intent = new IssuanceIntent("order", change == 4 ? "2".repeat(64) : DIGEST,
                    change == 5 ? new CertificateProfileRef("profile", 2, HexFormat.of().parseHex(DIGEST)) : issue.intent().expectedProfile(),
                    new PkiId(change == 6 ? "other-issuer" : "issuer"), new PkiId(change == 7 ? "other-path" : "path"),
                    change == 8 ? "2".repeat(64) : DIGEST);
            zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest changed = new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(
                    original.issuerCaId(), new zeroecho.pki.api.issuance.EndEntityReplacementRequest(
                            new PkiId(change == 2 ? "other-predecessor" : "predecessor"), payload, "profile"),
                    change == 3 ? "2".repeat(64) : DIGEST, intent);
            assertEquals(identity.correlationId(), CorrelatedIssuanceIdentity.derive(changed).correlationId());
            assertNotEquals(identity.effectiveCommitment(), CorrelatedIssuanceIdentity.derive(changed).effectiveCommitment());
            if (change == 0) assertThrows(IllegalStateException.class, () -> changed.request().csrDer());
        }
        assertThrows(IllegalArgumentException.class, () -> new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(
                original.issuerCaId(), original.request(), "invalid", original.intent()));
        assertThrows(IllegalArgumentException.class, () -> new zeroecho.pki.api.issuance.CorrelatedEndEntityReplacementRequest(
                original.issuerCaId(), new zeroecho.pki.api.issuance.EndEntityReplacementRequest(new PkiId("predecessor"), new byte[] {1}, "other"),
                DIGEST, original.intent()));
    }

    @Test
    void framingPreventsAmbiguousConcatenation() {
        CorrelatedIssuanceIdentity first = CorrelatedIssuanceIdentity.derive(request("ab", "c", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty()));
        CorrelatedIssuanceIdentity second = CorrelatedIssuanceIdentity.derive(request("a", "bc", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, new byte[] { 1 }, Optional.empty()));
        assertNotEquals(first.correlationId(), second.correlationId());
        assertNotEquals(first.effectiveCommitment(), second.effectiveCommitment());
    }

    @Test
    void requestBoundsCoordinatesAndKeepsDefensiveCsrOwnership() {
        byte[] csr = { 1, 2 };
        CorrelatedEndEntityIssuanceRequest request = request("authority", "order", DIGEST, "profile", 1,
                DIGEST, "issuer", "path", DIGEST, csr, Optional.empty());
        csr[0] = 7;
        request.request().csrDer()[0] = 9;
        assertArrayEquals(new byte[] { 1, 2 }, request.request().csrDer());
        assertEquals("CorrelatedEndEntityIssuanceRequest[redacted]", request.toString());
        assertThrows(IllegalArgumentException.class, () -> request("x".repeat(4097), "order", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, csr, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> request("authority", "order", DIGEST,
                "\ud800", 1, DIGEST, "issuer", "path", DIGEST, csr, Optional.empty()));
        assertEquals("é".repeat(2048), request("é".repeat(2048), "order", DIGEST, "profile", 1,
                DIGEST, "issuer", "path", DIGEST, csr, Optional.empty()).request().issuerCaId().value());
        assertThrows(IllegalArgumentException.class, () -> request("é".repeat(2049), "order", DIGEST,
                "profile", 1, DIGEST, "issuer", "path", DIGEST, csr, Optional.empty()));
        assertThrows(IllegalArgumentException.class, () -> new CorrelatedEndEntityIssuanceRequest(
                new EndEntityIssuanceRequest(new PkiId("authority"), csr, "different", Optional.empty()),
                request.intent()));
        assertThrows(IllegalArgumentException.class, () -> new CorrelatedEndEntityIssuanceRequest(null, request.intent()));
        assertThrows(IllegalArgumentException.class, () -> new CorrelatedEndEntityIssuanceRequest(request.request(), null));
    }

    @Test
    void retainedBindingUsesTheSameStrictBoundsAndRedactsCoordinates() {
        CertificateProfileRef profile = new CertificateProfileRef("profile", 1, new byte[32]);
        RetainedIssuanceBinding binding = new RetainedIssuanceBinding(new PkiId("é".repeat(2048)), "order",
                profile, new PkiId("issuer"), new PkiId("path"), DIGEST, DIGEST);
        assertEquals("RetainedIssuanceBinding[redacted]", binding.toString());
        for (String invalid : new String[] { "x".repeat(4097), "é".repeat(2049), "\ud800" }) {
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId(invalid),
                    "order", profile, new PkiId("issuer"), new PkiId("path"), DIGEST, DIGEST));
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    "order", new CertificateProfileRef(invalid, 1, new byte[32]),
                    new PkiId("issuer"), new PkiId("path"), DIGEST, DIGEST));
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    "order", profile, new PkiId(invalid), new PkiId("path"), DIGEST, DIGEST));
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    "order", profile, new PkiId("issuer"), new PkiId(invalid), DIGEST, DIGEST));
        }
        for (String invalid : new String[] { "", "UPPERCASE", "x".repeat(129), "white space" }) {
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    invalid, profile, new PkiId("issuer"), new PkiId("path"), DIGEST, DIGEST));
        }
        for (String invalid : new String[] { "", "A".repeat(64), "1".repeat(63), "g".repeat(64) }) {
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    "order", profile, new PkiId("issuer"), new PkiId("path"), invalid, DIGEST));
            assertThrows(IllegalArgumentException.class, () -> new RetainedIssuanceBinding(new PkiId("authority"),
                    "order", profile, new PkiId("issuer"), new PkiId("path"), DIGEST, invalid));
        }
        assertThrows(NullPointerException.class, () -> new RetainedIssuanceBinding(null, "order", profile,
                new PkiId("issuer"), new PkiId("path"), DIGEST, DIGEST));
    }

    static CorrelatedEndEntityIssuanceRequest request(String authority, String issuanceId, String command,
            String profile, long version, String profileDigest, String issuer, String path, String pathDigest,
            byte[] csr, Optional<Validity> validity) {
        return new CorrelatedEndEntityIssuanceRequest(new EndEntityIssuanceRequest(new PkiId(authority), csr,
                profile, validity), new IssuanceIntent(issuanceId, command,
                        new CertificateProfileRef(profile, version, HexFormat.of().parseHex(profileDigest)),
                        new PkiId(issuer), new PkiId(path), pathDigest));
    }
}
