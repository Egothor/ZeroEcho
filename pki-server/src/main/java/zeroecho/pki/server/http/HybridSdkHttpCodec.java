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

/**
 * Strict shared SDK HTTP byte grammar; decoded values establish no caller authority.
 */
public final class HybridSdkHttpCodec {
    /**
     * Exact SDK JSON media type.
     */
    public static final String MEDIA_TYPE = "application/vnd.zeroecho.hybrid-sdk+json";
    /**
     * Fixed profile advertised only by explicitly configured listeners.
     */
    public static final String PROFILE = "zeroecho-hybrid-sdk-v1";
    private HybridSdkHttpCodec() { }
    /**
     * Parses one closed SDK action document without verifying native authentication or client signatures.
     *
     * @param document complete bounded JSON bytes, borrowed for parsing
     * @param maximumBytes listener body ceiling, positive and no greater than StrictJson maximum
     * @param acceptance true for acceptance fields, false for a challenge nonce
     * @param adapterFields exact additional required adapter-member names
     * @return immutable field-map copy containing immutable typed values
     * @throws NullPointerException if the adapter-member set is null
     * @throws IllegalArgumentException if JSON/bounds/closed fields, version/profile, identities or encoded
     *     proof/nonce shape is invalid
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
     * Decodes exact unpadded base64url after applying encoded and decoded size checks.
     *
     * @param fields decoded typed field map
     * @param name required binary member name
     * @param minimumBytes inclusive decoded lower bound selected by the caller
     * @param maximumBytes inclusive decoded upper bound selected by the caller
     * @return new independently owned decoded bytes
     * @throws NullPointerException if the field map is null or rejects a null key
     * @throws IllegalArgumentException if text/type/alphabet/canonical re-encoding or decoded bounds fail
     */
    public static byte[] bytes(Map<String, PkiOperationValue> fields, String name, int minimumBytes, int maximumBytes) {
        String value = text(fields, name);
        if (value.length() > ((long) maximumBytes * 4 + 2) / 3 || !value.matches("[A-Za-z0-9_-]+")) throw invalid();
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        if (decoded.length < minimumBytes || decoded.length > maximumBytes
                || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) throw invalid();
        return decoded;
    }
    /**
     * Reads required typed text without trimming, normalization or interpreting it as authentication.
     *
     * @param fields decoded typed field map
     * @param name required text member
     * @return exact supplied text
     * @throws NullPointerException if the map is null or rejects a null key
     * @throws IllegalArgumentException if the member is absent or has another type
     */
    public static String text(Map<String, PkiOperationValue> fields, String name) {
        if (!(fields.get(name) instanceof PkiOperationValue.Text text)) throw invalid();
        return text.value();
    }
    /**
     * Encodes retained challenge fields and derives F2 by changing the supplied primary-frame kind.
     *
     * @param intentId retained intent identity, encoded without identity/frame correspondence checks
     * @param primary retained F1 fields including tag-eight expiry
     * @param target retained target frame encoded without a kind check here
     * @return new JSON bytes with F1/F2/target and expiry derived from the primary frame
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the derived frame or JSON representation violates its encoding bounds
     */
    public static byte[] challenge(String intentId, HybridSdkFrame primary, HybridSdkFrame target) {
        return StrictJson.encode(new PkiOperationValue.ObjectValue(Map.of(
                "version", new PkiOperationValue.IntegerValue(1), "profile", new PkiOperationValue.Text(PROFILE),
                "intentId", new PkiOperationValue.Text(intentId), "primaryFrame", encoded(primary.encode()),
                "alternativeFrame", encoded(new HybridSdkFrame(2, primary.fields()).encode()), "targetFrame", encoded(target.encode()),
                "expiresAt", new PkiOperationValue.Text(Instant.ofEpochSecond(ByteBuffer.wrap(primary.field(8)).getLong()).toString()))));
    }
    /**
     * Encodes configured listener capability metadata without creating or enabling a listener.
     *
     * @param basePath configured SDK route prefix, retained without route syntax validation
     * @param operations configured operation names, encoded in supplied order
     * @param canonicalOrigin configured canonical HTTPS origin, explicitly validated
     * @param maximumBodyBytes advertised listener body limit, encoded without a positivity check here
     * @return new closed capability JSON with existing request/proof/durable-admission ceilings
     * @throws NullPointerException if operations or an operation element is null
     * @throws IllegalArgumentException if the origin or encoded values fail their representation constraints
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
