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
package zeroecho.apispec;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.server.http.HybridSdkHttpCodec;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.application.PkiOperationValue;

class OpenApiSdkContractTest {
    @TempDir Path temporary;

    @Test void sdkSchemasMatchTheStrictEnrollmentCodecAndRejectExtraMembers() throws Exception {
        Path output=temporary.resolve("api.yaml");
        OpenApiGenerator.main(new String[]{"test","src/main/resources/openapi-supplement.yaml",output.toString()});
        String yaml=Files.readString(output);
        for (String adapter:List.of("Admin","Acme","Est","Scep","Cmp")) {
            Set<String> adapterFields=switch(adapter) {
                case "Admin" -> Set.of("operationId","arguments","requestDer");
                case "Acme" -> Set.of("csr");
                case "Est" -> Set.of("operation","requestDer");
                default -> Set.of("messageDer");
            };
            for(boolean accept:new boolean[]{false,true}) {
                Map<String,PkiOperationValue> fields=new LinkedHashMap<>();
                fields.put("version",new PkiOperationValue.IntegerValue(1));
                fields.put("profile",new PkiOperationValue.Text(HybridSdkHttpCodec.PROFILE));
                for(String field:adapterFields)fields.put(field,field.equals("arguments")?new PkiOperationValue.ObjectValue(Map.of()):text("AQ"));
                if(accept) {
                    fields.put("intentId",text("a".repeat(64)));fields.put("sdkRequestId",text("request-1"));
                    fields.put("primaryProof",text("AQ"));fields.put("alternativeProof",text(encoded(4627)));
                } else fields.put("clientNonce",text(encoded(32)));
                byte[] body=StrictJson.encode(new PkiOperationValue.ObjectValue(fields));
                assertEquals(fields.keySet(),HybridSdkHttpCodec.parse(body,100000,accept,adapterFields).keySet());
                String schema=block(yaml,"    Sdk"+adapter+(accept?"Accept":"Challenge")+"Request:",4);
                Set<String> required=new HashSet<>();
                var matcher=java.util.regex.Pattern.compile("(?m)^        - \"([^\"]+)\"$").matcher(schema);
                while(matcher.find())required.add(matcher.group(1));
                assertEquals(fields.keySet(),required);
                assertTrue(schema.contains("additionalProperties: false"));
                fields.put("unexpected",text("x"));
                assertThrows(IllegalArgumentException.class,()->HybridSdkHttpCodec.parse(StrictJson.encode(new PkiOperationValue.ObjectValue(fields)),100000,accept,adapterFields));
            }
        }
        assertTrue(yaml.contains("'/ocsp/{alias}/hybrid-sdk/v1':"));
        assertTrue(yaml.contains("'/acme/{alias}/hybrid-sdk/v1/accept/{orderId}':"));
        assertTrue(yaml.contains("OCSP_PROVISIONING_TARGET_CONFLICT"));
        assertTrue(yaml.contains("'202':"));
        String signing=block(yaml,"  '/operations/credential.issue':",2);
        String pending=block(signing,"        '202':",8);
        assertTrue(pending.contains("#/components/schemas/OperationResponse"));
        assertTrue(pending.contains("/admin/v1/signing-operations/{operationId}"));
        assertFalse(pending.contains("OCSP_PROVISIONING_TARGET_CONFLICT"));
        String ocsp=block(yaml,"  '/ocsp/{alias}/hybrid-sdk/v1':",2);
        assertTrue(ocsp.contains("url: \"https://{host}:{port}\""));
        assertTrue(ocsp.contains("security: []"));
        assertFalse(ocsp.contains("/admin/v1"));
        String est=block(yaml,"  '/.well-known/est/{label}/hybrid-sdk/v1/accept':",2);
        assertFalse(est.contains("security: []"));
        assertTrue(est.contains("application/pkcs7-mime; smime-type=certs-only"));
        assertTrue(est.contains("'202':"));
        String acme=block(yaml,"  '/acme/{alias}/hybrid-sdk/v1/accept/{orderId}':",2);
        assertTrue(acme.contains("application/jose+json"));
        assertTrue(acme.contains("x-zeroecho-jws-payload-schema"));
        var capability=(PkiOperationValue.ObjectValue)StrictJson.parse(HybridSdkHttpCodec.capability("/test",List.of("credential.issue"),"https://example.test:443",65536),65536);
        String capabilitySchema=block(yaml,"    SdkCapability:",4);
        for(String field:capability.fields().keySet())assertTrue(capabilitySchema.contains("        "+field+":"),field);

    }

    private static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
    private static String encoded(int count){return Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[count]);}
    private static String block(String text,String heading,int indent) {
        int start=text.indexOf(heading+"\n");assertTrue(start>=0,heading);
        var matcher=java.util.regex.Pattern.compile("(?m)^ {0,"+indent+"}\\S").matcher(text);
        int end=matcher.find(start+heading.length()+1)?matcher.start():text.length();
        return text.substring(start,end);
    }
}
