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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;

final class ManagedKeyProofChallengeTest {
    private static final PkiId OPERATION = new PkiId("zsign:v1:store.provider:0:" + "0".repeat(32));
    private static final byte[] SPKI = HexFormat.of().parseHex("302a300506032b6570032100" + "00".repeat(32));
    private static final String GOLDEN =
            "5a45524f4543484f2d4d414e414745442d4b45592d50524f4f4600000000020000003a7a7369676e3a76313a73746f72652e70726f7669646572"
            + "3a303a3030303030303030303030303030303030303030303030303030303030303030000000000000003c000000000000010203040506070809"
            + "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000e43415f5355424a4543545f4b455900000009617574686f726974790000000000"
            + "00000770726f66696c6500000000000000036b65790000000e73746f72652e70726f766964657211111111111111111111111111111111111111"
            + "11111111111111111111111111000000417a65616c673a323a393a7369676e6174757265383a7a65726f6563686f373a6564323535313931363a"
            + "7a65726f6563686f2e6275696c74696e363a626d39755a5100000007300506032b65700000002c302a300506032b657003210000000000000000"
            + "00000000000000000000000000000000000000000000000000";

    @Test void bindsParentDeadlineAndIntentAndRejectsVersionOne() {
        java.time.Instant deadline = java.time.Instant.ofEpochSecond(60);
        PkiId parent = new PkiId("zsign:v1:store.provider:0:" + "1".repeat(32));
        ManagedKeyProofChallenge.CaContext context = new ManagedKeyProofChallenge.CaContext(parent,
                "ca-intent:v1:" + "2".repeat(64));
        byte[] encoded = ManagedKeyProofChallenge.encode(OPERATION, deadline, Optional.of(context), metadata(), new byte[32], SPKI);
        ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(encoded);
        assertEquals(deadline, decoded.deadline());
        assertEquals(Optional.of(context), decoded.context());
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.encode(OPERATION,
                java.time.Instant.EPOCH, Optional.of(context), metadata(), new byte[32], SPKI));
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.encode(OPERATION,
                deadline, Optional.of(new ManagedKeyProofChallenge.CaContext(OPERATION, context.intentCommitment())),
                metadata(), new byte[32], SPKI));
        byte[] old = encoded.clone();
        ByteBuffer.wrap(old).putInt("ZEROECHO-MANAGED-KEY-PROOF\0".getBytes(StandardCharsets.US_ASCII).length, 1);
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.decode(old));
    }

    @Test void goldenFramingAndReconstructedCommitmentsAreStable() {
        byte[] nonce = new byte[32];
        for (int index = 0; index < nonce.length; index++) { nonce[index] = (byte) index; }
        byte[] encoded = ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), nonce, SPKI);
        assertEquals(GOLDEN, HexFormat.of().formatHex(encoded));
        assertEquals(373, encoded.length);
        assertEquals("0f0a1fe39fab0e25c7bfdcf84ae8c16c3089f0c08a02f16d851d0d560f1d27f2",
                ContentCommitment.sha256(encoded).sha256());
        ManagedKeyProofChallenge.Decoded decoded = ManagedKeyProofChallenge.decode(encoded);
        assertEquals(OPERATION, decoded.operationId());
        assertArrayEquals(nonce, decoded.nonce());
        assertArrayEquals(SPKI, decoded.spki());
        assertEquals(metadata(), decoded.command().fields().subList(0, 10));
        assertEquals("44", decoded.command().field(10));
        assertEquals(ContentCommitment.sha256(SPKI).sha256(), decoded.command().field(11));
        assertEquals("373", decoded.command().field(12));
        assertEquals(ContentCommitment.sha256(encoded).sha256(), decoded.command().field(13));
        decoded.nonce()[0] = 99;
        decoded.spki()[0] = 99;
        assertArrayEquals(nonce, decoded.nonce());
        assertArrayEquals(SPKI, decoded.spki());
        assertEquals("ManagedKeyProofChallenge.Decoded[redacted]", decoded.toString());
        ManagedKeyProofCommand.validateComplete(decoded.command());
        DomainContinuationTemplate template = DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                ManagedKeyProofCommand.OPERATION, decoded.command().fields().toArray(String[]::new));
        assertEquals(decoded.command(), DomainContinuationValidation.validate(template));
    }

    @Test void rejectsEveryTruncationBadHeaderFramingUtf8AndTrailingData() {
        byte[] golden = HexFormat.of().parseHex(GOLDEN);
        for (int length = 0; length < golden.length; length++) {
            byte[] truncated = Arrays.copyOf(golden, length);
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.decode(truncated));
        }
        assertThrows(IllegalArgumentException.class,
                () -> ManagedKeyProofChallenge.decode(Arrays.copyOf(golden, golden.length + 1)));
        int headerLength = "ZEROECHO-MANAGED-KEY-PROOF\0".getBytes(StandardCharsets.US_ASCII).length;
        for (int offset : new int[] {0, headerLength - 1, headerLength + 3, headerLength + 8}) {
            byte[] malformed = golden.clone();
            malformed[offset] = (byte) 0xff;
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.decode(malformed));
        }
        for (int length : new int[] {-1, Integer.MAX_VALUE, 4097}) {
            byte[] malformed = golden.clone();
            ByteBuffer.wrap(malformed).putInt(headerLength + 4, length);
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.decode(malformed));
        }
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.decode(
                new byte[ManagedKeyProofCommand.MAX_CHALLENGE_BYTES + 1]));
    }

    @Test void rejectsInvalidNonceCoordinatesDerAndAggregateSizeBeforeEncoding() throws Exception {
        for (int length : new int[] {0, 31, 33}) {
            assertThrows(IllegalArgumentException.class,
                    () -> ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), new byte[length], SPKI));
        }
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.encode(
                new PkiId("zsign:v1:other:0:" + "0".repeat(32)), zeroecho.pki.api.orch.SigningSubmissionId.parse(
                new PkiId("zsign:v1:other:0:" + "0".repeat(32))).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), new byte[32], SPKI));
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofChallenge.encode(
                new PkiId("zsign:v1:store.provider:00:" + "0".repeat(32)), zeroecho.pki.api.orch.SigningSubmissionId.parse(
                new PkiId("zsign:v1:store.provider:00:" + "0".repeat(32))).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), new byte[32], SPKI));
        for (byte[] spki : List.of(new byte[0], new byte[] {0x30, 0}, Arrays.copyOf(SPKI, SPKI.length + 1),
                new byte[ManagedKeyProofCommand.MAX_SPKI_BYTES + 1])) {
            assertThrows(IllegalArgumentException.class,
                    () -> ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), new byte[32], spki));
        }
        for (String algorithm : List.of("300506032B6570", "30810506032b6570", "0500", "30000600", "00")) {
            List<String> fields = metadata();
            fields.set(9, algorithm);
            assertThrows(IllegalArgumentException.class,
                    () -> ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), fields, new byte[32], SPKI));
        }
        List<String> malformedUtf8 = metadata();
        malformedUtf8.set(8, "algorithm\ud800");
        assertThrows(IllegalArgumentException.class,
                () -> ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), malformedUtf8, new byte[32], SPKI));
        List<String> excessiveCommand = metadata();
        excessiveCommand.set(5, "k".repeat(ManagedKeyProofCommand.MAX_COMMAND_BYTES));
        assertThrows(IllegalArgumentException.class,
                () -> ManagedKeyProofChallenge.encode(OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), excessiveCommand, new byte[32], SPKI));
        byte[] maximumSpki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.101.112")),
                new byte[ManagedKeyProofCommand.MAX_SPKI_BYTES - 18]).getEncoded("DER");
        assertEquals(ManagedKeyProofCommand.MAX_SPKI_BYTES, maximumSpki.length);
        assertArrayEquals(maximumSpki, ManagedKeyProofChallenge.decode(ManagedKeyProofChallenge.encode(
                OPERATION, zeroecho.pki.api.orch.SigningSubmissionId.parse(
                OPERATION).createdAt().plusSeconds(60), java.util.Optional.empty(), metadata(), new byte[32], maximumSpki)).spki());
    }

    @Test void completeSchemaRejectsMalformedValuesAndSeparatesInstalledAlgorithmSemantics() {
        DomainCommandEncoding.Decoded valid = ManagedKeyProofChallenge.decode(HexFormat.of().parseHex(GOLDEN)).command();
        for (int count = 0; count < 14; count++) {
            DomainCommandEncoding.Decoded shortCommand = new DomainCommandEncoding.Decoded(
                    ManagedKeyProofCommand.OPERATION, valid.fields().subList(0, count));
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateComplete(shortCommand));
        }
        List<String> extra = new ArrayList<>(valid.fields());
        extra.add("extra");
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateComplete(
                new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, extra)));
        for (int index : new int[] {6, 7, 8, 9, 10, 11, 12, 13}) {
            List<String> bad = new ArrayList<>(valid.fields());
            bad.set(index, " ");
            assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateComplete(
                    new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, bad)));
        }
        for (int index : new int[] {10, 12}) {
            for (String value : List.of("0", "-1", "+1", "01", "2147483648", "999999999999999999999")) {
                List<String> bad = new ArrayList<>(valid.fields());
                bad.set(index, value);
                assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateComplete(
                        new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, bad)));
            }
        }
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(), (suite, direction) -> true);
        assertEquals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE,
                ManagedKeyProofCommand.validateAlgorithm(valid, authority));
        List<String> installedOnly = new ArrayList<>(valid.fields());
        installedOnly.set(8, "opaque-installed-extension-identity");
        DomainCommandEncoding.Decoded structural = new DomainCommandEncoding.Decoded(
                ManagedKeyProofCommand.OPERATION, installedOnly);
        ManagedKeyProofCommand.validateComplete(structural);
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateAlgorithm(structural, authority));
        installedOnly.set(8, "Ed25519");
        assertThrows(IllegalArgumentException.class, () -> ManagedKeyProofCommand.validateAlgorithm(
                new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, installedOnly), authority));
    }

    private static List<String> metadata() {
        List<String> fields = new ArrayList<>(ManagedKeyProofCommand.prefix(new ManagedKeyProofRequest.CaSubject(
                new PkiId("authority"), Optional.empty(), "profile", new KeyRef("key"))));
        fields.add("store.provider");
        fields.add("11".repeat(32));
        fields.add(BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm());
        fields.add("300506032b6570");
        return fields;
    }
}
