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

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.application.PkiOperationValue;

/** Strict shared SDK HTTP byte grammar; decoded values establish no caller authority. */
public final class HybridSdkHttpCodec {
    /** Exact SDK JSON media type. */
    public static final String MEDIA_TYPE = "application/vnd.zeroecho.hybrid-sdk+json";
    /** Fixed profile advertised only by explicitly configured listeners. */
    public static final String PROFILE = "zeroecho-hybrid-sdk-v1";
    private HybridSdkHttpCodec() { }
    /**
     * Reads one closed SDK action document without protocol authentication.
     * @param document bounded JSON @param maximumBytes existing listener bound
     * @param acceptance whether this is acceptance rather than challenge
     * @param adapterFields exact adapter-specific required members
     * @return immutable decoded fields @throws IllegalArgumentException for invalid framing
     */
    public static Map<String, PkiOperationValue> parse(byte[] document, int maximumBytes,
            boolean acceptance, Set<String> adapterFields) {
        if (!(StrictJson.parse(document, maximumBytes) instanceof PkiOperationValue.ObjectValue object)) throw invalid();
        var expected = new java.util.HashSet<>(adapterFields);
        expected.addAll(Set.of("version", "profile"));
        expected.addAll(acceptance ? Set.of("intentId", "sdkRequestId", "primaryProof", "alternativeProof") : Set.of("clientNonce"));
        var fields = object.fields();
        if (!fields.keySet().equals(expected) || !(fields.get("version") instanceof PkiOperationValue.IntegerValue version)
                || version.value() != 1 || !text(fields, "profile").equals(PROFILE)) throw invalid();
        if (acceptance) {
            if (!text(fields, "intentId").matches("[0-9a-f]{64}")) throw invalid();
            if (!text(fields, "sdkRequestId").matches("[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")) throw invalid();
            bytes(fields, "primaryProof", 1, 104); bytes(fields, "alternativeProof", 4627, 4627);
        } else bytes(fields, "clientNonce", 32, 32);
        return Map.copyOf(fields);
    }
    /**
     * Reads canonical unpadded base64url with decoded bounds.
     * @param fields decoded closed document @param name member @param minimumBytes inclusive lower bound
     * @param maximumBytes inclusive upper bound @return independently owned bytes
     * @throws IllegalArgumentException for malformed or oversized bytes
     */
    public static byte[] bytes(Map<String, PkiOperationValue> fields, String name, int minimumBytes, int maximumBytes) {
        String value = text(fields, name);
        if (value.length() > ((long) maximumBytes * 4 + 2) / 3 || !value.matches("[A-Za-z0-9_-]+")) throw invalid();
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        if (decoded.length < minimumBytes || decoded.length > maximumBytes
                || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) throw invalid();
        return decoded;
    }
    /** @param fields decoded document @param name member @return exact text @throws IllegalArgumentException for another type */
    public static String text(Map<String, PkiOperationValue> fields, String name) {
        if (!(fields.get(name) instanceof PkiOperationValue.Text text)) throw invalid();
        return text.value();
    }
    /**
     * Encodes the closed retained challenge response.
     * @param intentId retained identity @param primary exact F1 @param target exact F7
     * @return SDK JSON bytes
     */
    public static byte[] challenge(String intentId, HybridSdkFrame primary, HybridSdkFrame target) {
        return StrictJson.encode(new PkiOperationValue.ObjectValue(Map.of(
                "version", new PkiOperationValue.IntegerValue(1), "profile", new PkiOperationValue.Text(PROFILE),
                "intentId", new PkiOperationValue.Text(intentId), "primaryFrame", encoded(primary.encode()),
                "alternativeFrame", encoded(new HybridSdkFrame(2, primary.fields()).encode()), "targetFrame", encoded(target.encode()),
                "expiresAt", new PkiOperationValue.Text(Instant.ofEpochSecond(ByteBuffer.wrap(primary.field(8)).getLong()).toString()))));
    }
    /**
     * Encodes configured capability metadata without inferring an origin.
     * @param basePath exact SDK route @param operations allowed native operations
     * @param canonicalOrigin exact configured HTTPS origin
     * @param maximumBodyBytes listener body bound @return closed capability JSON
     */
    public static byte[] capability(String basePath, java.util.List<String> operations, String canonicalOrigin, int maximumBodyBytes) {
        var fields = new LinkedHashMap<String, PkiOperationValue>();
        zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.requireOrigin(canonicalOrigin);
        fields.put("canonicalOrigin", new PkiOperationValue.Text(canonicalOrigin));
        fields.put("maximumRequestDerBytes", new PkiOperationValue.IntegerValue(1_048_576));
        fields.put("maximumDurableAdmissionBytes", new PkiOperationValue.IntegerValue(524_288));
        fields.put("version", new PkiOperationValue.IntegerValue(1)); fields.put("profile", new PkiOperationValue.Text(PROFILE));
        fields.put("challenge", new PkiOperationValue.Text(basePath + "/challenge"));
        fields.put("accept", new PkiOperationValue.Text(basePath + "/accept"));
        fields.put("operations", new PkiOperationValue.ListValue(operations.stream().map(value -> (PkiOperationValue) new PkiOperationValue.Text(value)).toList()));
        fields.put("maximumBodyBytes", new PkiOperationValue.IntegerValue(maximumBodyBytes));
        fields.put("maximumPrimaryProofBytes", new PkiOperationValue.IntegerValue(104));
        fields.put("alternativeProofBytes", new PkiOperationValue.IntegerValue(4627));
        return StrictJson.encode(new PkiOperationValue.ObjectValue(fields));
    }
    private static PkiOperationValue encoded(byte[] bytes) { return new PkiOperationValue.Text(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("SDK_HTTP_REQUEST_INVALID"); }
}
