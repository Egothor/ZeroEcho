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

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence;
import zeroecho.pki.application.PkiOperationValue;

/**
 * Exact bounded HTTP envelope for separate SDK OCSP evidence; decoding never establishes trust.
 */
/* default */ final class SdkOcspHttpCodec {
    private static final int BOUND_32 = 32;

    /**
     * Media type for the versioned hybrid-SDK OCSP JSON envelope.
     */
    /* default */ static final String MEDIA = "application/vnd.zeroecho.hybrid-sdk+json";
    /**
     * Exact hybrid-SDK version-one profile identifier accepted by this codec.
     */
    /* default */ static final String PROFILE = "zeroecho-hybrid-sdk-v1";
    private SdkOcspHttpCodec() { }
    /**
     * Decoded transport inputs before native OCSP validation or trust establishment.
     *
     * @param requestDer decoded OCSP request bytes; retained without copying by this carrier
     * @param clientNonce decoded 32-byte client nonce; retained without copying by this carrier
     */
    /* default */ record Query(byte[] requestDer,byte[] clientNonce) { }
    /**
     * Decodes the exact version-one SDK OCSP query envelope under independent byte bounds.
     *
     * @param bytes complete JSON request entity
     * @param maximumBytes maximum JSON entity length, in bytes
     * @param maximumNativeBytes maximum decoded OCSP request length, in bytes
     * @return decoded OCSP request and exact 32-byte client nonce
     * @throws IllegalArgumentException if fields, version, profile, base64url encoding or bounds are invalid
     */
    /* default */ static Query decode(byte[] bytes,int maximumBytes,int maximumNativeBytes) {
        if(!(StrictJson.parse(bytes,maximumBytes) instanceof PkiOperationValue.ObjectValue object)){ throw invalid(); }
        Map<String,PkiOperationValue> fields=object.fields();
        if(!fields.keySet().equals(Set.of("version","profile","requestDer","clientNonce"))
                || !(fields.get("version") instanceof PkiOperationValue.IntegerValue version) || version.value()!=1
                || !PROFILE.equals(text(fields,"profile"))){ throw invalid(); }
        byte[] request=decodeBytes(text(fields,"requestDer"),maximumNativeBytes);
        byte[] nonce=decodeBytes(text(fields,"clientNonce"),BOUND_32);
        if(nonce.length!=BOUND_32){ throw invalid(); }return new Query(request,nonce);
    }
    /**
     * Encodes public hybrid-SDK OCSP evidence into the version-one JSON transport envelope.
     *
     * @param evidence complete evidence carrier; encoding does not authenticate its contents
     * @return newly allocated UTF-8 JSON bytes
     * @throws NullPointerException if evidence is null
     */
    /* default */ static byte[] encode(SdkOcspEvidence evidence) {
        Map<String,PkiOperationValue> fields=new LinkedHashMap<>();
        fields.put("version",new PkiOperationValue.IntegerValue(1));fields.put("profile",text(PROFILE));
        fields.put("primaryResponseDer",bytes(evidence.primaryResponseDer()));
        fields.put("responderChain",new PkiOperationValue.ListValue(evidence.responderChain().stream().map(v->(PkiOperationValue)bytes(v)).toList()));
        fields.put("primaryFrame",bytes(evidence.primaryFrame().encode()));fields.put("alternativeFrame",bytes(evidence.alternativeFrame().encode()));
        fields.put("primarySignature",bytes(evidence.primarySignature()));fields.put("alternativeSignature",bytes(evidence.alternativeSignature()));
        return StrictJson.encode(new PkiOperationValue.ObjectValue(fields));
    }
    /**
     * Publishes the SDK OCSP route, profile and caller-visible request/response limits.
     *
     * @param origin canonical public server origin
     * @param bodyBytes maximum JSON request entity length, in bytes
     * @param nativeBytes maximum decoded native request length, in bytes
     * @param entries maximum requested certificate count
     * @return UTF-8 JSON capability document
     */
    /* default */ static byte[] capability(String origin,int bodyBytes,int nativeBytes,int entries) {
        return StrictJson.encode(new PkiOperationValue.ObjectValue(Map.ofEntries(
                Map.entry("version",new PkiOperationValue.IntegerValue(1)),Map.entry("profile",text(PROFILE)),
                Map.entry("canonicalOrigin",text(origin)),Map.entry("route",text("/ocsp/{alias}/hybrid-sdk/v1")),Map.entry("mediaType",text(MEDIA)),
                Map.entry("maximumBodyBytes",new PkiOperationValue.IntegerValue(bodyBytes)),
                Map.entry("maximumNativeRequestBytes",new PkiOperationValue.IntegerValue(nativeBytes)),
                Map.entry("maximumEntries",new PkiOperationValue.IntegerValue(entries)),
                Map.entry("clientNonceBytes",new PkiOperationValue.IntegerValue(BOUND_32)),
                Map.entry("maximumEvidenceLifetimeSeconds",new PkiOperationValue.IntegerValue(120)),
                Map.entry("maximumResponseBytes",new PkiOperationValue.IntegerValue(zeroecho.pki.application.SdkOcspProjection.MAXIMUM_RESPONSE_BYTES)))));
    }
    // Untrusted transport/parser failures retain the existing finite safe HTTP diagnostics.

    @SuppressWarnings({"PMD.PreserveStackTrace"})
    private static byte[] decodeBytes(String value,int maximum) {
        if(value.isEmpty()||value.indexOf('=')>=0||value.length()>((long)maximum*4+2)/3){ throw invalid(); }
        byte[] bytes;
        try{bytes=Base64.getUrlDecoder().decode(value);}catch(IllegalArgumentException failure){throw invalid();}
        if(bytes.length>maximum||!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)){ throw invalid(); }
        return bytes;
    }
    private static String text(Map<String,PkiOperationValue> fields,String key) {
        if(!(fields.get(key) instanceof PkiOperationValue.Text value)){ throw invalid(); }return value.value();
    }
    private static PkiOperationValue.Text bytes(byte[] value){return text(Base64.getUrlEncoder().withoutPadding().encodeToString(value));}
    private static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("SDK OCSP query envelope invalid");}
}
