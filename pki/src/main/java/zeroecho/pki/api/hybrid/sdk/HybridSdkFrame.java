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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Strict immutable F1/F2/F3/F4/F5/F6/F7/F8/F9 registry of zeroecho-hybrid-sdk-v1. */
public final class HybridSdkFrame {
    private static final byte[] DOMAIN = "ZeroEcho-Hybrid-SDK".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRIMARY_ALGORITHM = HexFormat.of().parseHex("300a06082a8648ce3d040303");
    private static final byte[] ALTERNATIVE_ALGORITHM = HexFormat.of().parseHex("300b0609608648016503040313");
    private static final int MAX_BYTES = 1048576;
    private static final int MAX_FIELD = 262144;
    private final int kind;
    private final Map<Integer, byte[]> fields;

    /**
     * Creates one validated canonical frame.
     * @param kind registered frame kind (1 through 9)
     * @param fields exact contiguous tag registry with borrowed values
     * @throws IllegalArgumentException for malformed values or exceeded bounds
     */
    public HybridSdkFrame(int kind, Map<Integer, byte[]> fields) {
        int count = count(kind); Objects.requireNonNull(fields, "fields");
        if (fields.size() != count) throw invalid();
        var copy = new TreeMap<Integer, byte[]>(); long length = DOMAIN.length + 7L;
        for (int tag = 1; tag <= count; tag++) {
            byte[] value = fields.get(tag); if (value == null) throw invalid();
            if (value.length > MAX_FIELD) throw invalid();
            length += 6L + value.length; if (length > MAX_BYTES) throw invalid();
            copy.put(tag, value.clone());
        }
        this.kind = kind; this.fields = java.util.Collections.unmodifiableMap(copy); validate();
    }

    /** @return registered domain-separation kind */
    public int kind() { return kind; }
    /** @param tag required registry tag @return independent field bytes @throws IllegalArgumentException if the tag does not exist */
    public byte[] field(int tag) {
        byte[] value = fields.get(tag); if (value == null) throw invalid(); return value.clone();
    }
    /** @return independent field map and field bytes */
    public Map<Integer, byte[]> fields() {
        var copy = new TreeMap<Integer, byte[]>(); fields.forEach((tag, bytes) -> copy.put(tag, bytes.clone())); return copy;
    }
    /** @return complete exact canonical signed bytes */
    public byte[] encode() {
        try {
            var bytes = new ByteArrayOutputStream(); var out = new DataOutputStream(bytes);
            out.write(DOMAIN); out.writeByte(0); out.writeShort(1); out.writeShort(kind); out.writeShort(fields.size());
            for (var entry : fields.entrySet()) { out.writeShort(entry.getKey()); out.writeInt(entry.getValue().length); out.write(entry.getValue()); }
            return bytes.toByteArray();
        } catch (IOException impossible) { throw new IllegalStateException(impossible); }
    }
    /** @param bytes borrowed complete frame @return validated independent frame @throws IllegalArgumentException for unsupported or malformed input */
    public static HybridSdkFrame decode(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes"); if (bytes.length > MAX_BYTES) throw invalid(); bytes = bytes.clone();
        try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (!Arrays.equals(DOMAIN, input.readNBytes(DOMAIN.length)) || input.readUnsignedByte() != 0 || input.readUnsignedShort() != 1) throw invalid();
            int kind = input.readUnsignedShort(); int count = input.readUnsignedShort();
            if (count != count(kind)) throw invalid(); var fields = new TreeMap<Integer, byte[]>();
            for (int expected = 1; expected <= count; expected++) {
                int tag = input.readUnsignedShort(); int length = input.readInt();
                if (tag != expected || length < 0 || length > MAX_FIELD || length > input.available()) throw invalid();
                fields.put(tag, input.readNBytes(length));
            }
            if (input.available() != 0) throw invalid(); return new HybridSdkFrame(kind, fields);
        } catch (IOException malformed) { throw invalid(); }
    }
    /** @param value borrowed public framed or DER bytes @return SHA-512 commitment bytes */
    public static byte[] hash(byte[] value) {
        try { return MessageDigest.getInstance("SHA-512").digest(Objects.requireNonNull(value)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    /** @return exact absent-parameters ECDSA-with-SHA384 AlgorithmIdentifier DER */
    public static byte[] primaryAlgorithm() { return PRIMARY_ALGORITHM.clone(); }
    /** @return exact absent-parameters pure ML-DSA-87 AlgorithmIdentifier DER */
    public static byte[] alternativeAlgorithm() { return ALTERNATIVE_ALGORITHM.clone(); }
    /** @param value canonical origin with explicit port @throws IllegalArgumentException for a noncanonical origin */
    public static void requireOrigin(String value) {
        if (value == null || value.length() > 256 || !value.startsWith("https://") || !value.chars().allMatch(c -> c < 128)) throw invalid();
        String authority = value.substring(8); int colon = authority.lastIndexOf(':');
        if (colon < 1) throw invalid(); String host = authority.substring(0, colon); String port = authority.substring(colon + 1);
        if (!port.matches("[1-9][0-9]{0,4}") || Integer.parseInt(port) > 65535) throw invalid();
        if (host.startsWith("[")) {
            if (!host.endsWith("]") || !host.substring(1, host.length() - 1).matches("[0-9a-f:.]+")) throw invalid();
            if (!canonicalIpv6(host.substring(1, host.length() - 1)).equals(host.substring(1, host.length() - 1))) throw invalid();
        } else if (host.matches("[0-9.]+")) {
            String[] parts = host.split("\\.", -1); if (parts.length != 4) throw invalid();
            for (String part : parts) if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) throw invalid();
        } else {
            if (host.length() > 253 || !host.equals(host.toLowerCase(java.util.Locale.ROOT))) throw invalid();
            for (String label : host.split("\\.", -1)) if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) throw invalid();
        }
    }
    private static String canonicalIpv6(String literal) {
        try {
            if (literal.indexOf(':') < 0) throw invalid();
            byte[] address = java.net.InetAddress.getByName(literal).getAddress();
            if (address.length == 4) {
                return "::ffff:" + (address[0] & 255) + "." + (address[1] & 255) + "." + (address[2] & 255) + "." + (address[3] & 255);
            }
            int[] groups = new int[8]; int best = -1, bestLength = 1;
            for (int i = 0; i < 8; i++) groups[i] = (address[2 * i] & 255) * 256 + (address[2 * i + 1] & 255);
            for (int i = 0; i < 8;) {
                if (groups[i] != 0) { i++; continue; } int end = i;
                while (end < 8 && groups[end] == 0) end++;
                if (end - i > bestLength) { best = i; bestLength = end - i; } i = end;
            }
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < 8;) {
                if (i == best) { result.append("::"); i += bestLength; }
                else { if (!result.isEmpty() && result.charAt(result.length() - 1) != ':') result.append(':'); result.append(Integer.toHexString(groups[i++])); }
            }
            return result.toString();
        } catch (java.net.UnknownHostException malformed) { throw invalid(); }
    }
    private void validate() {
        switch (kind) {
            case 1, 2 -> {
                if (!text(1).equals("zeroecho-hybrid-sdk-v1")) throw invalid(); identifier(2);
                for (int tag = 3; tag <= 6; tag++) length(tag, 32);
                long issued = time(7), expires = time(8); if (issued > Long.MAX_VALUE - 300 || expires != issued + 300) throw invalid();
                requireOrigin(text(9));
                if (!java.util.Set.of("admin-http-v1", "acme-v1", "est-v1", "scep-v1", "cmp-v1").contains(text(10))) throw invalid();
                for (int tag = 11; tag <= 14; tag++) length(tag, 64); length(17, 64);
                if (!Arrays.equals(field(15), PRIMARY_ALGORITHM) || !Arrays.equals(field(16), ALTERNATIVE_ALGORITHM)) throw invalid();
            }
            case 4, 5 -> requireOcspEvidenceValues();
            case 3 -> { length(1, 64); length(2, 64); length(5, 64); requirePrimaryProofSyntax(field(3)); length(4, 4627); }
            case 6 -> {
                identifier(1); length(3, 64);
                if (java.util.Set.of("direct-mtls-v1", "trusted-proxy-mtls-v1").contains(text(2))) {
                    if (!text(4).equals("admin-http-v1")) throw invalid();
                    requireAuthenticationValues();
                } else requireEnrollmentAuthenticationValues();
            }
            case 7 -> {
                for (int tag : new int[] {1, 3, 4, 5, 6, 10}) identifier(tag);
                for (int tag : new int[] {2, 15, 16, 17}) {
                    byte[] value = HybridSdkValue.decode(field(tag)).encode(); if (value[0] != 6) throw invalid();
                }
                if (!text(7).matches("sha512:[0-9a-f]{128}") || unsignedLong(11) == 0) throw invalid();
                requireNested(8, 8); if (field(9).length != 0) requireNested(9, 9);
                for (int tag = 12; tag <= 14; tag++) if (!text(tag).matches("sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128}")) throw invalid();
            }
            case 8, 9 -> {
                new zeroecho.pki.api.KeyRef(text(1));
                if (zeroecho.core.spec.AlgorithmIdentity.parse(text(2), java.util.List.of()).kind() != zeroecho.core.spec.AlgorithmIdentity.Kind.PUBLIC_KEY
                        || zeroecho.core.spec.AlgorithmIdentity.parse(text(3), java.util.List.of()).kind() != zeroecho.core.spec.AlgorithmIdentity.Kind.SIGNATURE) throw invalid();
                try {
                    new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(field(4), 1024);
                    var algorithm = org.bouncycastle.asn1.x509.AlgorithmIdentifier.getInstance(field(4));
                    if (!Arrays.equals(algorithm.getEncoded("DER"), field(4))) throw invalid();
                } catch (IOException malformed) { throw invalid(); }
                length(5, 64);
            }
            default -> throw invalid();
        }
    }
    private void requireOcspEvidenceValues() {
        if (!text(1).equals("zeroecho-hybrid-sdk-v1")) throw invalid(); identifier(2); requireOrigin(text(3)); length(4, 32);
        for (int tag = 5; tag <= 8; tag++) length(tag, 64);
        for (int tag = 9; tag <= 11; tag++) identifier(tag);
        if (!text(12).matches("(?:sha256:)?[0-9a-f]{64}") || !text(13).matches("[0-9a-f]{64}")) throw invalid();
        var roles = HybridSdkValue.decode(field(14)).objectFields();
        if (!roles.keySet().equals(java.util.Set.of("primary", "alternative"))) throw invalid();
        requireOcspRole(roles.get("primary"), PRIMARY_ALGORITHM); requireOcspRole(roles.get("alternative"), ALTERNATIVE_ALGORITHM);
        long produced = time(15), update = time(16), next = time(17), issued = time(18), expires = time(19);
        if (update > produced || next <= update || issued < produced || expires <= issued || expires > next
                || issued > Long.MAX_VALUE - 120 || expires > issued + 120) throw invalid();
        var nonce = HybridSdkValue.decode(field(20)).objectFields();
        if (!nonce.keySet().equals(java.util.Set.of("present", "value"))) throw invalid();
        byte[] present = nonce.get("present").encode(), value = nonce.get("value").encode();
        if ((!Arrays.equals(present, HybridSdkValue.bool(true).encode()) && !Arrays.equals(present, HybridSdkValue.bool(false).encode()))
                || value[0] != 4 || Arrays.equals(present, HybridSdkValue.bool(false).encode()) && value.length != 5) throw invalid();
        var statuses = HybridSdkValue.decode(field(21)).listValues();
        if (statuses.isEmpty() || statuses.size() > 819) throw invalid();
        var ids = new java.util.HashSet<String>();
        for (var status : statuses) {
            var entry = status.objectFields();
            if (!entry.keySet().equals(java.util.Set.of("certIdDer", "status", "revocationTime", "reason"))) throw invalid();
            byte[] cert = entry.get("certIdDer").encode(); if (cert[0] != 4 || cert.length <= 5 || !ids.add(ocspCertIdIdentity(Arrays.copyOfRange(cert, 5, cert.length)))) throw invalid();
            String state = entry.get("status").textValue(), revoked = entry.get("revocationTime").textValue(); long reason = entry.get("reason").integerValue();
            if (!java.util.Set.of("GOOD", "REVOKED", "UNKNOWN").contains(state)) throw invalid();
            if (state.equals("REVOKED")) {
                var instant = java.time.Instant.parse(revoked);
                if (!instant.toString().equals(revoked) || instant.getNano() != 0 || reason < -1 || reason > 10 || reason == 7) throw invalid();
            } else if (!revoked.isEmpty() || reason != -1) throw invalid();
        }
    }
    private static String ocspCertIdIdentity(byte[] bytes) {
        try {
            var id = org.bouncycastle.asn1.ocsp.CertID.getInstance(bytes);
            if (!Arrays.equals(bytes, id.getEncoded("DER")) || bytes.length > 108) throw invalid();
            var algorithm = id.getHashAlgorithm();
            int length = switch (algorithm.getAlgorithm().getId()) { case "1.3.14.3.2.26" -> 20; case "2.16.840.1.101.3.4.2.1" -> 32; default -> throw invalid(); };
            if (algorithm.getParameters() != null && !(algorithm.getParameters() instanceof org.bouncycastle.asn1.ASN1Null)
                    || id.getIssuerNameHash().getOctets().length != length || id.getIssuerKeyHash().getOctets().length != length
                    || id.getSerialNumber().getValue().signum() <= 0 || id.getSerialNumber().getValue().bitLength() > 160) throw invalid();
            return algorithm.getAlgorithm().getId() + ":" + HexFormat.of().formatHex(id.getIssuerNameHash().getOctets())
                    + ":" + HexFormat.of().formatHex(id.getIssuerKeyHash().getOctets()) + ":" + id.getSerialNumber().getValue();
        } catch (IOException malformed) { throw invalid(); }
    }
    static void requireOcspRole(HybridSdkValue value, byte[] algorithm) {
        var role = value.objectFields();
        if (!role.keySet().equals(java.util.Set.of("spki", "publicKeyAlgorithm", "signatureAlgorithm", "algorithmIdentifier"))) throw invalid();
        if (zeroecho.core.spec.AlgorithmIdentity.parse(role.get("publicKeyAlgorithm").textValue(), java.util.List.of()).kind() != zeroecho.core.spec.AlgorithmIdentity.Kind.PUBLIC_KEY
                || zeroecho.core.spec.AlgorithmIdentity.parse(role.get("signatureAlgorithm").textValue(), java.util.List.of()).kind() != zeroecho.core.spec.AlgorithmIdentity.Kind.SIGNATURE) throw invalid();
        if (!Arrays.equals(role.get("algorithmIdentifier").encode(), HybridSdkValue.bytes(algorithm).encode())) throw invalid();
        byte[] spki = role.get("spki").encode(); if (spki[0] != 4 || spki.length <= 5) throw invalid();
    }
    private void requireEnrollmentAuthenticationValues() {
        String[] keys;
        String carrier;
        switch (text(2)) {
            case "acme-account-jws-v1" -> {
                carrier = "acme-v1";
                keys = new String[]{"endpointId", "endpointCommitment", "accountId", "accountKeySha256", "orderId", "orderCommitment", "authorizationCommitment", "identifiers", "requestKind"};
            }
            case "est-mtls-v1" -> {
                carrier = "est-v1";
                keys = new String[]{"endpointId", "endpointCommitment", "certificateSha256", "canonicalKeySha256", "issuerSerialSha256", "operation", "predecessorId", "requestKind"};
            }
            case "scep-cms-v1" -> {
                carrier = "scep-v1";
                keys = new String[]{"endpointId", "endpointCommitment", "signerCertificateSha256", "transactionIdSha256", "senderNonceSha256", "nativeMessageSha512", "challengePolicyCommitment", "challengeAuthenticated", "messageType", "requestKind"};
            }
            case "cmp-signature-v1", "cmp-pbm-v1" -> {
                carrier = "cmp-v1";
                keys = new String[]{"endpointId", "endpointCommitment", "authenticationPolicyCommitment", "manifestCommitment", "transactionIdSha256", "certReqId", "bodyType", "originalWireSha512", "senderNonceSha256", "recipientNonceSha256", "authenticationCredentialId", "authenticationCredentialRevision", "requestKind"};
            }
            default -> throw invalid();
        }
        if (!text(4).equals(carrier)) throw invalid();
        var values = HybridSdkValue.decode(field(5)).objectFields();
        if (!values.keySet().equals(java.util.Set.of(keys))) throw invalid();
        for (String key : keys) {
            var value = values.get(key);
            if (key.equals("identifiers")) { requireAcmeIdentifiers(value); continue; }
            if (key.equals("challengeAuthenticated")) {
                if (!Arrays.equals(value.encode(), HybridSdkValue.bool(true).encode())) throw invalid();
                continue;
            }
            if (key.equals("authenticationCredentialRevision")) {
                if (value.integerValue() < 0) throw invalid(); continue;
            }
            String text = value.textValue();
            boolean empty = key.equals("recipientNonceSha256") || key.equals("predecessorId");
            if ((!empty && text.isEmpty()) || text.length() > 8192) throw invalid();
            if (key.endsWith("Sha256") && !(empty && text.isEmpty()) && !text.matches("[0-9a-f]{64}")) throw invalid();
            if (key.endsWith("Sha512") && !text.matches("sha512:[0-9a-f]{128}")) throw invalid();
            if (key.equals("certReqId") && (!text.matches("0|[1-9][0-9]{0,19}")
                    || new java.math.BigInteger(text).bitLength() > 64)) throw invalid();
            if (key.equals("requestKind") && !text.equals(carrier.equals("cmp-v1") ? "CRMF" : "PKCS10")) throw invalid();
            if (key.equals("operation") && !java.util.Set.of("simpleenroll", "simplereenroll").contains(text)) throw invalid();
            if (key.equals("authenticationCredentialId") && (!text.matches("[\\x21-\\x7e]{1,128}"))) throw invalid();
        }
        if (carrier.equals("est-v1")) {
            boolean enroll = values.get("operation").textValue().equals("simpleenroll");
            if (enroll != values.get("predecessorId").textValue().isEmpty()) throw invalid();
        }
    }

    private static void requireAcmeIdentifiers(HybridSdkValue value) {
        var identifiers = value.listValues();
        if (identifiers.isEmpty()) throw invalid();
        String previous = null;
        for (var identifier : identifiers) {
            var item = identifier.objectFields();
            if (!item.keySet().equals(java.util.Set.of("type", "value", "wildcard"))
                    || !item.get("type").textValue().equals("dns")) throw invalid();
            String dns = item.get("value").textValue();
            if (dns.length() > 253 || !dns.matches("[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) throw invalid();
            for (String label : dns.split("\\.", -1)) {
                if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) throw invalid();
            }
            byte[] wildcard = item.get("wildcard").encode();
            if (!Arrays.equals(wildcard, HybridSdkValue.bool(false).encode())
                    && !Arrays.equals(wildcard, HybridSdkValue.bool(true).encode())) throw invalid();
            String coordinate = dns + "\u0000" + (wildcard[1] == 0 ? "0" : "1");
            if (previous != null && previous.compareTo(coordinate) >= 0) throw invalid();
            previous = coordinate;
        }
    }

    private void requireAuthenticationValues() {
        byte[] encoded = HybridSdkValue.decode(field(5)).encode();
        try (var input = new DataInputStream(new ByteArrayInputStream(encoded))) {
            if (input.readUnsignedByte() != 6 || input.readInt() != 3) throw invalid();
            for (String expected : new String[] {"canonicalKeySha256", "issuerSerialSha256", "transportPrincipalId"}) {
                int length = input.readUnsignedShort();
                if (length > 128 || !expected.equals(HybridSdkValue.text(input.readNBytes(length))) || input.readUnsignedByte() != 1) throw invalid();
                int bytes = input.readInt(); if (bytes < 0 || bytes > 128 || bytes > input.available()) throw invalid();
                String value = HybridSdkValue.text(input.readNBytes(bytes));
                if (expected.equals("transportPrincipalId")) {
                    if (text(2).equals("direct-mtls-v1")) { if (!value.isEmpty()) throw invalid(); }
                    else HybridSdkValue.requireIdentifier(value);
                } else if (!value.matches("[0-9a-f]{64}")) throw invalid();
            }
            if (input.available() != 0) throw invalid();
        } catch (IOException malformed) { throw invalid(); }
    }
    static void requirePrimaryProofSyntax(byte[] bytes) {
        if (bytes.length < 8 || bytes.length > 104) throw invalid();
        try {
            new zeroecho.pki.impl.framework.x509.StreamingDerReader().validate(bytes, 104);
            var sequence = org.bouncycastle.asn1.ASN1Sequence.getInstance(org.bouncycastle.asn1.ASN1Primitive.fromByteArray(bytes));
            if (sequence.size() != 2 || !Arrays.equals(bytes, sequence.getEncoded("DER"))) throw invalid();
            var order = org.bouncycastle.asn1.sec.SECNamedCurves.getByName("secp384r1").getN();
            for (int i = 0; i < 2; i++) {
                var scalar = org.bouncycastle.asn1.ASN1Integer.getInstance(sequence.getObjectAt(i)).getValue();
                if (scalar.signum() <= 0 || scalar.compareTo(order) >= 0) throw invalid();
            }
        } catch (IOException malformed) { throw invalid(); }
    }
    private void requireNested(int tag, int expectedKind) {
        byte[] value = field(tag); int offset = DOMAIN.length + 3;
        if (value.length < offset + 2 || Short.toUnsignedInt(ByteBuffer.wrap(value, offset, 2).getShort()) != expectedKind) throw invalid();
        if (decode(value).kind() != expectedKind) throw invalid();
    }
    private long time(int tag) {
        long value = unsignedLong(tag);
        try { java.time.Instant.ofEpochSecond(value); } catch (java.time.DateTimeException unsupported) { throw invalid(); }
        return value;
    }
    private long unsignedLong(int tag) { length(tag, 8); long value = ByteBuffer.wrap(field(tag)).getLong(); if (value < 0) throw invalid(); return value; }
    private void identifier(int tag) { HybridSdkValue.requireIdentifier(text(tag)); }
    private String text(int tag) { return HybridSdkValue.text(field(tag)); }
    private void length(int tag, int required) { if (field(tag).length != required) throw invalid(); }
    private static int count(int kind) { return switch (kind) { case 1, 2, 7 -> 17; case 4, 5 -> 21; case 3, 6, 8, 9 -> 5; default -> throw invalid(); }; }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK_FRAME_INVALID"); }
}
