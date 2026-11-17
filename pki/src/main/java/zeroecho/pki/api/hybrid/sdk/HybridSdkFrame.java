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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Represents a canonical frame from the F1 through F9 registry of {@code zeroecho-hybrid-sdk-v1}.
 *
 * <p>The immutable frame snapshots its field bytes and enforces the closed kind/tag
 * registry, canonical framing and kind-specific value syntax. Each field is limited
 * to 262,144 bytes and the complete frame to 1,048,576 bytes. No signature is created
 * or verified, caller authenticated, or current-time freshness established merely by
 * constructing or decoding a frame; those checks belong to the protocol verifier.
 * Kinds F4 and F5 describe the separate SDK OCSP evidence profile, not a standard
 * alternative-signature {@code BasicOCSPResponse}.
 */
public final class HybridSdkFrame {
    private static final byte[] DOMAIN = "ZeroEcho-Hybrid-SDK".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRIMARY_ALGORITHM =
            HexFormat.of().parseHex("300a06082a8648ce3d040303");
    private static final byte[] ALTERNATIVE_ALGORITHM =
            HexFormat.of().parseHex("300b0609608648016503040313");
    private static final int MAX_BYTES = 1_048_576;
    private static final int MAX_FIELD = 262_144;
    private final int kind;
    private final Map<Integer, byte[]> fields;

    /**
     * Creates one validated canonical frame.
     *
     * <p>Tags must be contiguous from one through the registered field count, with
     * no missing or extra tag. Every byte array is copied before kind-specific
     * structural validation. Caller mutations after construction do not change the frame.
     *
     * @param kind registered frame kind (1 through 9)
     * @param fields exact contiguous tag registry with borrowed values
     * @throws IllegalArgumentException for malformed values or exceeded bounds
     * @throws NullPointerException if the field map is null
     */
    public HybridSdkFrame(int kind, Map<Integer, byte[]> fields) {
        int count = count(kind);
        Objects.requireNonNull(fields, "fields");
        if (fields.size() != count) {
            throw invalid();
        }
        Map<Integer, byte[]> copy = new TreeMap<>();
        long length = DOMAIN.length + 7L;
        for (int tag = 1; tag <= count; tag++) {
            byte[] value = fields.get(tag);
            if (value == null) {
                throw invalid();
            }
            if (value.length > MAX_FIELD) {
                throw invalid();
            }
            length += 6L + value.length;
            if (length > MAX_BYTES) {
                throw invalid();
            }
            copy.put(tag, value.clone());
        }
        this.kind = kind;
        this.fields = java.util.Collections.unmodifiableMap(copy);
        new HybridSdkFrameValues(this).validate();
    }

    /**
     * Returns the registered kind included in the frame's domain-separated encoding.
     *
     * @return the exact kind, from 1 through 9
     */
    public int kind() {
        return kind;
    }

    /**
     * Returns a copy of one registered field without exposing the retained byte array.
     *
     * @param tag required field tag for this frame kind
     * @return independently owned field bytes
     * @throws IllegalArgumentException if the tag does not exist in this frame
     */
    public byte[] field(int tag) {
        byte[] value = fields.get(tag);
        if (value == null) {
            throw invalid();
        }
        return value.clone();
    }

    /**
     * Returns an independent mutable field map in ascending tag order.
     *
     * <p>Each field array is copied. Modifying the map or any returned array cannot
     * alter the immutable frame; callers can use the copy to construct another frame.
     *
     * @return a new map with independently owned field arrays
     */
    public Map<Integer, byte[]> fields() {
        Map<Integer, byte[]> copy = new TreeMap<>();
        fields.forEach((tag, bytes) -> copy.put(tag, bytes.clone()));
        return copy;
    }

    /**
     * Encodes the complete canonical frame used by the SDK's commitment and signature rules.
     *
     * <p>The encoding includes the fixed domain, version, kind, field count and
     * ordered length-framed fields. Encoding does not generate a signature or make
     * an existing proof valid.
     *
     * @return independently owned canonical frame bytes
     * @throws IllegalStateException if in-memory canonical encoding unexpectedly fails
     */
    public byte[] encode() {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write(DOMAIN);
            out.writeByte(0);
            out.writeShort(1);
            out.writeShort(kind);
            out.writeShort(fields.size());
            for (Map.Entry<Integer, byte[]> entry : fields.entrySet()) {
                out.writeShort(entry.getKey());
                out.writeInt(entry.getValue().length);
                out.write(entry.getValue());
            }
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * Decodes a complete frame and validates its closed registry and field syntax.
     *
     * <p>Input is copied before parsing. Unsupported versions or kinds, out-of-order
     * tags, invalid lengths, missing bytes and trailing bytes are rejected. Successful
     * decoding is structural validation, not cryptographic proof or a freshness check.
     *
     * @param bytes complete frame bytes, borrowed for this call
     * @return an independently owned immutable validated frame
     * @throws NullPointerException if the input is null
     * @throws IllegalArgumentException if framing, registered field syntax or size bounds are invalid
     */
    // Untrusted parser/crypto exceptions are normalized to the existing finite safe failure.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public static HybridSdkFrame decode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length > MAX_BYTES) {
            throw invalid();
        }
        byte[] snapshot = bytes.clone();
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(snapshot))) {
            if (!Arrays.equals(DOMAIN, input.readNBytes(DOMAIN.length))
                    || input.readUnsignedByte() != 0
                    || input.readUnsignedShort() != 1) {
                throw invalid();
            }
            int kind = input.readUnsignedShort();
            int count = input.readUnsignedShort();
            if (count != count(kind)) {
                throw invalid();
            }
            Map<Integer, byte[]> fields = new TreeMap<>();
            for (int expected = 1; expected <= count; expected++) {
                fields.put(expected, readFieldValue(input, expected));
            }
            if (input.available() != 0) {
                throw invalid();
            }
            return new HybridSdkFrame(kind, fields);
        } catch (IOException malformed) {
            throw invalid();
        }
    }

    /**
     * Computes SHA-512 over the exact supplied public bytes.
     *
     * <p>This function adds no domain prefix or framing. The caller must supply
     * the exact canonical frame or DER representation required by its commitment rule.
     *
     * @param value public framed or DER bytes, borrowed for this call
     * @return a new 64-byte SHA-512 digest
     * @throws NullPointerException if the input is null
     * @throws IllegalStateException if the required SHA-512 implementation is unavailable
     */
    public static byte[] hash(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(Objects.requireNonNull(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    /**
     * Returns the primary signature AlgorithmIdentifier fixed by the SDK profile.
     *
     * @return a defensive copy of ECDSA-with-SHA384 DER with absent parameters
     */
    public static byte[] primaryAlgorithm() {
        return PRIMARY_ALGORITHM.clone();
    }

    /**
     * Returns the alternative signature AlgorithmIdentifier fixed by the SDK profile.
     *
     * @return a defensive copy of pure ML-DSA-87 DER with absent parameters
     */
    public static byte[] alternativeAlgorithm() {
        return ALTERNATIVE_ALGORITHM.clone();
    }

    /**
     * Requires the SDK's exact canonical HTTPS origin representation.
     *
     * <p>The ASCII origin is limited to 256 characters and includes an explicit
     * port from 1 through 65,535. Hosts use lowercase DNS labels, canonical IPv4,
     * or bracketed canonical IPv6. The value is checked as supplied, not normalized;
     * acceptance does not establish DNS ownership, TLS identity or origin authorization.
     *
     * @param value canonical HTTPS origin with an explicit port
     * @throws IllegalArgumentException if the value is null, noncanonical or outside its bounds
     */
    public static void requireOrigin(String value) {
        HybridSdkOrigin.requireOrigin(value);
    }

    /**
     * Checks an OCSP role's exact field set, algorithm kinds and public encoding consistency.
     *
     * @param value SDK object containing the role's SPKI and algorithm evidence
     * @param algorithm exact signature AlgorithmIdentifier DER expected for the role
     * @throws NullPointerException if a required reference is null
     * @throws IllegalArgumentException if the role shape, algorithm identity or encoded public evidence is invalid
     */
    /* default */ static void requireOcspRole(HybridSdkValue value, byte[] algorithm) {
        HybridSdkOcspValues.requireOcspRole(value, algorithm);
    }

    /**
     * Checks canonical DER syntax and scalar bounds for a P-384 ECDSA proof signature.
     *
     * <p>This syntax check does not authenticate a signature or establish possession of a private key.</p>
     *
     * @param bytes complete DER signature sequence, bounded to eight through 104 bytes
     * @throws NullPointerException if the signature is null
     * @throws IllegalArgumentException if the length, DER representation, sequence shape or scalar range is invalid
     */
    /* default */ static void requirePrimaryProofSyntax(byte[] bytes) {
        HybridSdkProofSyntax.requirePrimaryProofSyntax(bytes);
    }

    private static byte[] readFieldValue(DataInputStream input, int expected) throws IOException {
                int tag = input.readUnsignedShort();
                int length = input.readInt();
                if (tag != expected
                        || length < 0
                        || length > MAX_FIELD
                        || length > input.available()) {
                    throw invalid();
                }
                return input.readNBytes(length);
    }

    private static int count(int kind) {
        return switch (kind) {
            case 1, 2, 7 -> 17;
            case 4, 5 -> 21;
            case 3, 6, 8, 9 -> 5;
            default -> throw invalid();
        };
    }



    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("SDK_FRAME_INVALID");
    }
}
