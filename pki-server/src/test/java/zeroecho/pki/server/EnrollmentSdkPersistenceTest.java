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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.hybrid.sdk.*;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.enrollment.*;

/** Real control-store atomic rejection at the SDK target/receipt trust boundary. */
class EnrollmentSdkPersistenceTest {
    @Test void changedIssuerCannotConsumeIntentOrCreateEnrollment(@TempDir Path directory) throws Exception {
        try (var opened = ServerTestSupport.open(directory)) {
            var control = opened.store(); var realm = ServerTestSupport.REALM;
            Instant issued = Instant.parse("2026-11-15T12:00:00Z"); Instant accepted = issued.plusSeconds(1);
            String digest = "1".repeat(64), transaction = "2".repeat(64), id = "3".repeat(64);
            var evidence = new CertificateIdentityEvidence(realm, digest, digest, Set.of(digest), digest);
            var requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT, "client",
                    IssuanceExecutionEvidence.Authentication.EST_MTLS, Optional.of(evidence), Optional.of(digest), Set.of(digest),
                    new EnrollmentIdentityAliases.Snapshot(realm, Set.of()));
            var authFields = new TreeMap<Integer, byte[]>();
            authFields.put(1, text("client")); authFields.put(2, text("est-mtls-v1")); authFields.put(3, HybridSdkFrame.hash(text("sha256:" + digest)));
            authFields.put(4, text("est-v1"));
            authFields.put(5, HybridSdkValue.object(Map.ofEntries(
                    Map.entry("endpointId", HybridSdkValue.text("est")), Map.entry("endpointCommitment", HybridSdkValue.text(digest)),
                    Map.entry("certificateSha256", HybridSdkValue.text(digest)), Map.entry("canonicalKeySha256", HybridSdkValue.text(digest)),
                    Map.entry("issuerSerialSha256", HybridSdkValue.text(digest)), Map.entry("operation", HybridSdkValue.text("simpleenroll")),
                    Map.entry("predecessorId", HybridSdkValue.text("")), Map.entry("requestKind", HybridSdkValue.text("PKCS10")))).encode());
            var auth = new HybridSdkFrame(6, authFields);
            String authHash = "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(auth.encode()));
            var target = new SdkEnrollmentTarget(1, "EST", "est", 1, digest, "enroll", 1, digest, "ISSUE", X509EnrollmentPayload.Kind.PKCS10, transaction, authHash);
            var key = new HybridSdkFrame(8, Map.of(1, text("fixture:key.prv"), 2, text(BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY.canonicalForm()),
                    3, text(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()), 4, HybridSdkFrame.primaryAlgorithm(), 5, new byte[64]));
            var fields = new TreeMap<Integer, byte[]>(); fields.put(1, text("credential.issue")); fields.put(2, HybridSdkValue.object(Map.of()).encode()); fields.put(3, text("client"));
            fields.put(4, text("ca")); fields.put(5, text("issuer")); fields.put(6, text("path")); fields.put(7, text("sha512:" + "0".repeat(128))); fields.put(8, key.encode()); fields.put(9, new byte[0]);
            fields.put(10, text("leaf")); fields.put(11, time(1)); fields.put(12, text("sha256:" + digest)); fields.put(13, text("sha512:" + "0".repeat(128)));
            fields.put(14, text("sha256:" + ApprovalService.digest("")));
            var validity = new Validity(issued, issued.plusSeconds(3600));
            fields.put(15, HybridSdkValue.object(Map.of("notBefore", HybridSdkValue.text(validity.notBefore().toString()), "notAfter", HybridSdkValue.text(validity.notAfter().toString()))).encode());
            var bindingInputs = HybridSdkValue.object(Map.of("issuerBinding", HybridSdkValue.text(digest), "provider", HybridSdkValue.text("configured-public-provider"), "path", HybridSdkValue.text(digest)));
            fields.put(13, text("sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(bindingInputs.encode()))));
            fields.put(16, HybridSdkValue.object(Map.of()).encode()); fields.put(17, HybridSdkValue.object(Map.of("version", HybridSdkValue.integer(1), "enrollment", target.value(), "lifecycle", HybridSdkValue.object(Map.of()), "bindingSetInputs", bindingInputs)).encode());
            var frame = new HybridSdkFrame(7, fields); var payload = new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, new byte[] {0x30, 0});
            var primaryFields = new TreeMap<Integer, byte[]>(); primaryFields.put(1, text("zeroecho-hybrid-sdk-v1")); primaryFields.put(2, text(realm.value())); primaryFields.put(3, HexFormat.of().parseHex(id));
            primaryFields.put(4, new byte[32]); primaryFields.put(5, new byte[32]); primaryFields.put(6, new byte[32]); primaryFields.put(7, time(issued.getEpochSecond())); primaryFields.put(8, time(issued.plusSeconds(300).getEpochSecond()));
            primaryFields.put(9, text("https://example.invalid:443")); primaryFields.put(10, text("est-v1")); primaryFields.put(11, HybridSdkFrame.hash(payload.der())); primaryFields.put(12, HybridSdkFrame.hash(auth.encode()));
            primaryFields.put(13, new byte[64]); primaryFields.put(14, new byte[64]); primaryFields.put(15, HybridSdkFrame.primaryAlgorithm()); primaryFields.put(16, HybridSdkFrame.alternativeAlgorithm()); primaryFields.put(17, HybridSdkFrame.hash(frame.encode()));
            var primary = new HybridSdkFrame(1, primaryFields);
            var nativeAdmission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, "est", requester, transaction, EnrollmentTransaction.Operation.ISSUE, payload, Optional.empty(), Optional.empty());
            var admission = new EnrollmentSdkAdmission(nativeAdmission, digest, "https://example.invalid:443", auth, target, Optional.empty());
            var open = new EnrollmentSdkIntent(id, 1, realm, admission, payload, Optional.empty(), primary, auth, frame, issued, issued.plusSeconds(300), EnrollmentSdkIntent.State.OPEN, 0,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            control.mutateProtocol(List.of(new ServerControlStore.ProtocolMutation(EnrollmentSdkIntentCodec.record(open), Optional.empty())));
            String proofHash = "sha512:" + "4".repeat(128), targetHash = "sha512:" + HexFormat.of().formatHex(HybridSdkFrame.hash(frame.encode()));
            var consumed = new EnrollmentSdkIntent(id, 1, realm, admission, payload, Optional.empty(), primary, auth, frame, issued, issued.plusSeconds(300), EnrollmentSdkIntent.State.CONSUMED, 1,
                    Optional.of("sdk-request"), Optional.of(new byte[104]), Optional.of(new byte[4627]), Optional.of(proofHash), Optional.of(accepted), Optional.of("enrollment-test"));
            var source = new EnrollmentTransaction.Source(EnrollmentTransaction.Protocol.EST, "est", "est", 1, digest, "enroll", digest, Optional.empty());
            var intent = new EnrollmentTransaction.Intent(realm, source, requester, transaction, EnrollmentTransaction.Operation.ISSUE, new PkiId("request"), payload.kind(), sha256(payload.der()), payload.der().length,
                    new PkiId("ca"), new CertificateProfileRef("leaf", 1, HexFormat.of().parseHex(digest)), new PkiId("changed-issuer"), new PkiId("path"), digest, Optional.of(validity), Optional.empty(), Optional.empty(),
                    OperationSecurityDescriptors.ApprovalCategory.NONE, Optional.empty(), Optional.empty(), accepted, accepted.plusSeconds(600),
                    Optional.of(new EnrollmentTransaction.SdkProofReference(id, proofHash, authHash, targetHash, accepted)));
            var proposed = new EnrollmentTransaction("enrollment-test", 1, intent, EnrollmentTransaction.State.APPROVED, List.of(), Optional.empty(), Optional.empty());
            assertThrows(IllegalArgumentException.class, () -> control.mutateSdkEnrollment(open, consumed, proposed, Optional.empty(), Optional.empty()));
            assertEquals(EnrollmentSdkIntent.State.OPEN, EnrollmentSdkIntentCodec.decode(control.protocolRecord(ServerControlStore.HYBRID_SDK_INTENT, id).orElseThrow()).state());
            assertTrue(control.protocolRecord(ServerControlStore.ENROLLMENT_REQUEST, proposed.id()).isEmpty());
            assertTrue(control.approvals(0, 10).values().isEmpty());
        }
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] time(long value) { return ByteBuffer.allocate(8).putLong(value).array(); }
    private static String sha256(byte[] value) throws Exception { return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value)); }
}
