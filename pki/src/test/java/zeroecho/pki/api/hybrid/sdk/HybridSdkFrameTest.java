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
package zeroecho.pki.api.hybrid.sdk;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Contract and regression tests for hybrid SDK frame.
 */
class HybridSdkFrameTest {
    /** Preserves the finite frame failure when the neutral DER checker rejects a scalar. */
    @Test void invalidPrimaryProofKeepsTheFrameFailureCode() {
        byte[] zeroScalar = HexFormat.of().parseHex("3006020100020101");
        var fields = java.util.Map.of(1, new byte[64], 2, new byte[64], 3, zeroScalar,
                4, new byte[4_627], 5, new byte[64]);
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new HybridSdkFrame(3, fields));
        assertEquals("SDK_FRAME_INVALID", failure.getMessage());
    }

    /**
     * Pins algorithm identifiers and canonical origins.
     */
    @Test void pinsAlgorithmIdentifiersAndCanonicalOrigins() {
        assertEquals("300a06082a8648ce3d040303", HexFormat.of().formatHex(HybridSdkFrame.primaryAlgorithm()));
        assertEquals("300b0609608648016503040313", HexFormat.of().formatHex(HybridSdkFrame.alternativeAlgorithm()));
        for (String origin : java.util.List.of("https://example.invalid:443", "https://127.0.0.1:8443", "https://[::1]:8443")) HybridSdkFrame.requireOrigin(origin);
        for (String origin : java.util.List.of("https://EXAMPLE.invalid:443", "https://example.invalid", "https://127.000.0.1:8443", "https://[0:0:0:0:0:0:0:1]:8443", "https://example.invalid:0443", "https://example.invalid:443/path")) {
            assertThrows(IllegalArgumentException.class, () -> HybridSdkFrame.requireOrigin(origin));
        }
    }
    /**
     * Matches independent python framing vectors and separates proof roles.
     */
    @Test void matchesIndependentPythonFramingVectorsAndSeparatesProofRoles() {
        var primary = vector();
        assertEquals(687, primary.encode().length);
        assertEquals("1a3c47a2aad699a64c5ebe6ed7ee0d6f427e9b55df2e3018f04fd7225ac0aab99d733b63320370a8f283b24c7b7edb8de55957983632d7d79a161da67ed20bee",
                HexFormat.of().formatHex(HybridSdkFrame.hash(primary.encode())));
        var alternative = new HybridSdkFrame(2, primary.fields());
        assertEquals("3bb9def1a0d696b483ae76b7f262a9f9a85a86bbd04270a469bfffc2a08723acaa20e948cf550e7ab48f98c50781032f79b1c83879b5393cbf8376d5fe77a950",
                HexFormat.of().formatHex(HybridSdkFrame.hash(alternative.encode())));
        assertEquals(1, HybridSdkFrame.decode(primary.encode()).kind());
        assertArrayEquals(primary.field(3), HybridSdkFrame.decode(primary.encode()).field(3));
        byte[] changed = primary.field(3); changed[0] ^= 1;
        assertNotEquals(changed[0], primary.field(3)[0]);
    }

    /**
     * Rejects unknown kinds missing fields trailing data and length overflow.
     */
    @Test void rejectsUnknownKindsMissingFieldsTrailingDataAndLengthOverflow() {
        var frame = vector();
        assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(4, frame.fields()));
        var fields = new TreeMap<>(frame.fields()); fields.remove(17);
        assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(1, fields));
        byte[] trailing = java.util.Arrays.copyOf(frame.encode(), frame.encode().length + 1);
        assertThrows(IllegalArgumentException.class, () -> HybridSdkFrame.decode(trailing));
        byte[] oversized = frame.encode();
        int fieldLengthOffset = "ZeroEcho-Hybrid-SDK".length() + 1 + 6 + 2;
        java.util.Arrays.fill(oversized, fieldLengthOffset, fieldLengthOffset + 4, (byte) 0xff);
        assertThrows(IllegalArgumentException.class, () -> HybridSdkFrame.decode(oversized));
    }

    /**
     * Native authentication contexts are closed and carrier bound.
     */
    @Test void nativeAuthenticationContextsAreClosedAndCarrierBound() {
        var context = new java.util.TreeMap<String, HybridSdkValue>();
        for (String key : new String[]{"endpointId", "endpointCommitment", "certificateSha256", "canonicalKeySha256", "issuerSerialSha256"}) {
            context.put(key, HybridSdkValue.text(key.endsWith("Sha256") ? "0".repeat(64) : "endpoint"));
        }
        context.put("operation", HybridSdkValue.text("simpleenroll"));
        context.put("predecessorId", HybridSdkValue.text(""));
        context.put("requestKind", HybridSdkValue.text("PKCS10"));
        var fields = new TreeMap<Integer, byte[]>(); fields.put(1, text("native-actor"));
        fields.put(2, text("est-mtls-v1")); fields.put(3, new byte[64]); fields.put(4, text("est-v1"));
        fields.put(5, HybridSdkValue.object(context).encode());
        assertArrayEquals(fields.get(5), HybridSdkFrame.decode(new HybridSdkFrame(6, fields).encode()).field(5));
        var wrongCarrier = new TreeMap<>(fields); wrongCarrier.put(4, text("cmp-v1"));
        assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(6, wrongCarrier));
        context.put("callerSaysAuthenticated", HybridSdkValue.bool(true));
        fields.put(5, HybridSdkValue.object(context).encode());
        assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(6, fields));
    }

    /**
     * CMP request id preserves the native unsigned64 boundary.
     */
    @Test void cmpRequestIdPreservesTheNativeUnsigned64Boundary() {
        var context = new java.util.TreeMap<String, HybridSdkValue>();
        for (String key : new String[]{"endpointId", "endpointCommitment", "authenticationPolicyCommitment", "manifestCommitment",
                "transactionIdSha256", "originalWireSha512", "senderNonceSha256", "authenticationCredentialId"}) {
            String value = key.endsWith("Sha256") ? "0".repeat(64)
                    : key.endsWith("Sha512") ? "sha512:" + "0".repeat(128) : "native";
            context.put(key, HybridSdkValue.text(value));
        }
        context.put("bodyType", HybridSdkValue.text("ir"));
        context.put("recipientNonceSha256", HybridSdkValue.text(""));
        context.put("authenticationCredentialRevision", HybridSdkValue.integer(1));
        context.put("requestKind", HybridSdkValue.text("CRMF"));
        var fields = new TreeMap<Integer, byte[]>(); fields.put(1, text("native-actor"));
        fields.put(2, text("cmp-signature-v1")); fields.put(3, new byte[64]); fields.put(4, text("cmp-v1"));
        for (String id : new String[]{"0", "9223372036854775808", "18446744073709551615"}) {
            context.put("certReqId", HybridSdkValue.text(id)); fields.put(5, HybridSdkValue.object(context).encode());
            assertArrayEquals(fields.get(5), HybridSdkFrame.decode(new HybridSdkFrame(6, fields).encode()).field(5));
        }
        for (String id : new String[]{"18446744073709551616", "-1", "00", "01"}) {
            context.put("certReqId", HybridSdkValue.text(id)); fields.put(5, HybridSdkValue.object(context).encode());
            assertThrows(IllegalArgumentException.class, () -> new HybridSdkFrame(6, fields));
        }
    }

    /**
     * Constructs the fixed canonical SDK frame used by the encoding vectors.
     *
     * @return fixed SDK frame for exact byte/digest assertions
     */
    static HybridSdkFrame vector() {
        var fields = new TreeMap<Integer, byte[]>();
        fields.put(1, text("zeroecho-hybrid-sdk-v1")); fields.put(2, text("example-realm"));
        for (int tag = 3; tag <= 6; tag++) fields.put(tag, repeated(tag - 2, 32));
        fields.put(7, ByteBuffer.allocate(8).putLong(1700000000).array());
        fields.put(8, ByteBuffer.allocate(8).putLong(1700000300).array());
        fields.put(9, text("https://127.0.0.1:8443")); fields.put(10, text("admin-http-v1"));
        for (int tag = 11; tag <= 14; tag++) fields.put(tag, repeated((tag - 10) * 0x11, 64));
        fields.put(15, HexFormat.of().parseHex("300a06082a8648ce3d040303"));
        fields.put(16, HexFormat.of().parseHex("300b0609608648016503040313"));
        fields.put(17, repeated(0x55, 64)); return new HybridSdkFrame(1, fields);
    }
    private static byte[] text(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static byte[] repeated(int value, int size) { byte[] bytes = new byte[size]; java.util.Arrays.fill(bytes, (byte) value); return bytes; }
}
