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

import java.util.List;
import zeroecho.pki.server.http.HybridSdkHttpCodec;

/**
 * Emits OpenAPI fragments for explicitly optional SDK adapters and retained admin requests.
 *
 * <p>The projection describes existing carrier authentication/media distinctions,
 * not listener activation or runtime authorization. Enrollment subject proofs do
 * not replace native authentication, and OCSP F4/F5 evidence is the separate SDK
 * profile rather than standard AltSignature OCSP.</p>
 */
final class SdkOpenApi {
    private SdkOpenApi() { }

    /**
     * Appends retained-request and optional adapter paths to the current YAML mapping.
     *
     * @param y caller-owned builder positioned in the paths mapping
     */
    static void paths(YamlBuilder y) {
        administrativeRequests(y);
        for(String adapter:List.of("Admin","Acme","Est","Scep","Cmp")) {
            String base=switch(adapter) {
                case "Admin" -> "/hybrid-sdk/v1";
                case "Acme" -> "/acme/{alias}/hybrid-sdk/v1";
                case "Est" -> "/.well-known/est/{label}/hybrid-sdk/v1";
                case "Scep" -> "/scep/{label}/hybrid-sdk/v1";
                default -> "/pkix/{label}/hybrid-sdk/v1";
            };
            y.blockMapping("'"+base+"'",()-> {
                listener(y,adapter);
                y.blockMapping("get",()-> {
                    authentication(y,adapter,true);
                    y.mapping("summary",adapter+" optional SDK capability");
                    parameters(y,base);
                    responses(y,"200",adapter.equals("Admin")||adapter.equals("Acme")?"application/json":HybridSdkHttpCodec.MEDIA_TYPE,"SdkCapability",false);
                });
            });
            for(boolean accept:new boolean[]{false,true}) {
                String path=base+(accept?"/accept":"/challenge")+(adapter.equals("Acme")?"/{orderId}":"");
                y.blockMapping("'"+path+"'",()-> {
                    listener(y,adapter);
                    y.blockMapping("post",()-> {
                        authentication(y,adapter,false);
                        y.mapping("summary",adapter+" SDK "+(accept?"acceptance":"challenge"));
                        y.mapping("description","Explicit listener and enrollment-profile opt-in required; otherwise 404. Native protocol authentication and policy remain mandatory. Subject proofs do not authenticate the protocol. Reuse retained intent/request identity after uncertain results; never silently create a fresh signing attempt.");
                        parameters(y,path);
                        if(adapter.equals("Acme"))y.mapping("x-zeroecho-jws-payload-schema","#/components/schemas/SdkAcme"+(accept?"Accept":"Challenge")+"Request");
                        body(y,adapter.equals("Acme")?"application/jose+json":HybridSdkHttpCodec.MEDIA_TYPE,adapter.equals("Acme")?"SdkAcmeJws":"Sdk"+adapter+(accept?"Accept":"Challenge")+"Request");
                        String media=!accept?(adapter.equals("Admin")||adapter.equals("Acme")?"application/json":HybridSdkHttpCodec.MEDIA_TYPE):switch(adapter) {
                            case "Admin","Acme" -> "application/json";
                            case "Est" -> "application/pkcs7-mime; smime-type=certs-only";
                            case "Scep" -> "application/x-pki-message";
                            default -> "application/pkixcmp";
                        };
                        responses(y,accept&&adapter.equals("Admin")?"202":"200",media,!accept?"SdkChallenge":adapter.equals("Admin")?"OperationResponse":adapter.equals("Acme")?"SdkAcmeOrder":null,accept&&adapter.equals("Est"));
                    });
                });
            }
        }
        y.blockMapping("'/ocsp/{alias}/hybrid-sdk/v1'",()-> {
            listener(y,"Ocsp");
            for(String method:List.of("get","post"))y.blockMapping(method,()-> {
                y.mappingLiteral("security","[]");
                y.mapping("summary",method.equals("get")?"Optional OCSP SDK capability":"Native OCSP response with separate dual-signature SDK evidence");
                y.mapping("description","Listener and responder must both opt in; otherwise 404. GET is metadata only. POST retains native signed/unsigned requester, trust, CertID, nonce and replay policy. The independent 32-byte SDK nonce does not replace the native OCSP nonce. This is ZeroEcho SDK evidence, not standard AltSignature OCSP. No partial bundle is returned.");
                parameters(y,"/ocsp/{alias}/hybrid-sdk/v1");
                if(method.equals("post"))body(y,HybridSdkHttpCodec.MEDIA_TYPE,"SdkOcspRequest");
                responses(y,"200",HybridSdkHttpCodec.MEDIA_TYPE,method.equals("get")?"SdkOcspCapability":"SdkOcspBundle",false);
            });
        });
    }

    private static void administrativeRequests(YamlBuilder y) {
        y.blockMapping("'/requests'",()->y.blockMapping("post",()-> {
            y.mapping("summary","Submit a retained administrative request");
            y.mapping("description","Normal operation authorization and explicit approval policy apply. Managed OCSP provisioning is canonical by actual key tuple and issuer generation: equivalent retries return the retained canonical request/result, including with another caller request ID. Changed targets return OCSP_PROVISIONING_TARGET_CONFLICT with canonicalRequestId. Same-slot renewal requires the exact completed predecessor credential; uncertain attempts must be inspected rather than replaced.");
            body(y,"application/json","AdministrativeSubmission");
            y.blockMapping("responses",()-> {
                response(y,"202","Accepted or replayed retained request; provisioning includes Location pointing to the canonical request.","application/json","OperationResponse");
                response(y,"409","REQUEST_ID_CONFLICT or OCSP_PROVISIONING_TARGET_CONFLICT; the latter includes result.canonicalRequestId and canonical Location.","application/json","OperationResponse");
                errors(y);
            });
        }));
        y.blockMapping("'/requests/{requestId}'",()->y.blockMapping("get",()-> {
            y.mapping("summary","Inspect an authorized retained administrative request");
            parameters(y,"/requests/{requestId}");
            responses(y,"200","application/json","OperationResponse",false);
        }));
    }

    private static void listener(YamlBuilder y,String adapter) {
        if(!adapter.equals("Admin"))y.blockMapping("servers",()->y.sequenceItem(()-> {
            y.mapping("url","https://{host}:{port}");
            y.mapping("description",adapter+" listener; configure its actual host and port independently of the administrative listener");
            y.blockMapping("variables",()-> {
                y.blockMapping("host",()->y.mapping("default","localhost"));
                y.blockMapping("port",()->y.mapping("default","443"));
            });
        }));
    }
    private static void authentication(YamlBuilder y,String adapter,boolean capability) {
        if(!adapter.equals("Admin")&&!adapter.equals("Est"))y.mappingLiteral("security","[]");
        y.mapping("x-zeroecho-authentication",switch(adapter) {
            case "Admin" -> "Administrative mutual TLS and current operation authorization";
            case "Est" -> "EST mutual TLS and endpoint principal/authorization policy";
            case "Acme" -> capability?"Public capability":"ACME account JWS, nonce, exact URL and order ownership";
            case "Scep" -> capability?"Public capability":"SCEP CMS message authentication and endpoint policy";
            default -> capability?"Public capability":"CMP protected-message authentication and endpoint policy";
        });
    }
    private static void parameters(YamlBuilder y,String path) {
        var names=java.util.regex.Pattern.compile("\\{([^}]+)}").matcher(path);
        var values=new java.util.ArrayList<String>();while(names.find())values.add(names.group(1));
        if(!values.isEmpty())y.blockMapping("parameters",()->values.forEach(name->y.sequenceItem(()-> {
            y.mapping("name",name);y.mapping("in","path");y.mappingLiteral("required","true");
            y.blockMapping("schema",()->y.mapping("type","string"));
        })));
    }
    private static void body(YamlBuilder y,String media,String schema) {
        y.blockMapping("requestBody",()-> {
            y.mappingLiteral("required","true");
            y.blockMapping("content",()->y.blockMapping("'"+media+"'",()->y.refMapping("schema","#/components/schemas/"+schema)));
        });
    }
    private static void responses(YamlBuilder y,String status,String media,String schema,boolean pending) {
        y.blockMapping("responses",()-> {
            response(y,status,"Existing native adapter result",media,schema);
            y.blockMapping("'409'",()->y.mapping("description","Native conflict; SDK_INTENT_CONFLICT retains the existing intent identity. Error media and grammar remain adapter-specific."));
            if(pending)response(y,"202","Enrollment pending; Retry-After retains native EST behavior","text/plain",null);
            errors(y);
        });
    }
    private static void response(YamlBuilder y,String status,String description,String media,String schema) {
        y.blockMapping("'"+status+"'",()-> {
            y.mapping("description",description);
            y.blockMapping("content",()->y.blockMapping("'"+media+"'",()-> {
                if(schema!=null)y.refMapping("schema","#/components/schemas/"+schema);
                else y.blockMapping("schema",()-> {y.mapping("type","string");y.mapping("format","binary");});
            }));
        });
    }
    private static void errors(YamlBuilder y) {
        for(String status:List.of("400","401","403","404","405","413","415","429","500","503"))
            y.blockMapping("'"+status+"'",()->y.mapping("description","Native adapter rejection, unavailable opt-in, resource bound or transient failure; response media and grammar remain adapter-specific"));
    }

    /**
     * Appends the shared request/response component schemas used by the emitted paths.
     *
     * <p>Patterns and declared bounds describe representation requirements; runtime
     * native decoders and listener/component budgets remain authoritative.</p>
     *
     * @param y caller-owned builder positioned in components.schemas
     */
    static void schemas(YamlBuilder y) {
        for(String adapter:List.of("Admin","Acme","Est","Scep","Cmp"))for(boolean accept:new boolean[]{false,true}) {
            var fields=new java.util.ArrayList<String>(List.of("version","profile"));
            fields.addAll(switch(adapter) {
                case "Admin" -> List.of("operationId","arguments","requestDer");
                case "Acme" -> List.of("csr");
                case "Est" -> List.of("operation","requestDer");
                default -> List.of("messageDer");
            });
            fields.addAll(accept?List.of("intentId","sdkRequestId","primaryProof","alternativeProof"):List.of("clientNonce"));
            object(y,"Sdk"+adapter+(accept?"Accept":"Challenge")+"Request",fields,fields);
        }
        var challenge=List.of("version","profile","intentId","primaryFrame","alternativeFrame","targetFrame","expiresAt");
        object(y,"SdkChallenge",challenge,challenge);
        var capability=List.of("version","profile","canonicalOrigin","maximumRequestDerBytes","maximumDurableAdmissionBytes","challenge","accept","operations","maximumBodyBytes","maximumPrimaryProofBytes","alternativeProofBytes");
        object(y,"SdkCapability",capability,capability);
        var ocsp=List.of("version","profile","requestDer","clientNonce");object(y,"SdkOcspRequest",ocsp,ocsp);
        var bundle=List.of("version","profile","primaryResponseDer","responderChain","primaryFrame","alternativeFrame","primarySignature","alternativeSignature");object(y,"SdkOcspBundle",bundle,bundle);
        var ocspCapability=List.of("version","profile","canonicalOrigin","route","mediaType","maximumBodyBytes","maximumNativeRequestBytes","maximumEntries","clientNonceBytes","maximumEvidenceLifetimeSeconds","maximumResponseBytes");
        object(y,"SdkOcspCapability",ocspCapability,ocspCapability);
        var submit=List.of("version","requestId","operation","arguments","authorityId","deadline");
        object(y,"AdministrativeSubmission",submit,List.of("version","requestId","operation","arguments"));
        var jws=List.of("protected","payload","signature");object(y,"SdkAcmeJws",jws,jws);
        y.blockMapping("SdkAcmeOrder",()-> {
            y.mapping("type","object");y.mapping("description","Native ACME order object; SDK acceptance returns the existing ACME order representation and Location.");
        });
    }
    private static void object(YamlBuilder y,String name,List<String> fields,List<String> required) {
        y.blockMapping(name,()-> {
            y.mappingLiteral("type","object");y.mappingLiteral("additionalProperties","false");
            y.blockMapping("required",()->required.forEach(y::sequenceItemString));
            y.blockMapping("properties",()->fields.forEach(field->y.blockMapping(field,()->field(y,name,field))));
        });
    }
    private static void field(YamlBuilder y,String schema,String field) {
        boolean integer=field.equals("version")||field.startsWith("maximum")||field.endsWith("Bytes");
        if(field.equals("arguments")) {y.mapping("type","object");return;}
        if(field.equals("operations")||field.equals("responderChain")) {
            y.mapping("type","array");y.blockMapping("items",()->y.mapping("type","string"));return;
        }
        y.mapping("type",integer?"integer":"string");
        if(field.equals("version"))y.mappingLiteral("const","1");
        else if(field.equals("profile"))y.mapping("const",HybridSdkHttpCodec.PROFILE);
        else if(field.equals("operationId"))y.blockMapping("enum",()->List.of("credential.issue","credential.renew","credential.reissue","credential.replace").forEach(y::sequenceItemString));
        else if(field.equals("operation")&&schema.startsWith("SdkEst"))y.blockMapping("enum",()->List.of("simpleenroll","simplereenroll").forEach(y::sequenceItemString));
        else if(field.equals("intentId"))y.mapping("pattern","^[0-9a-f]{64}$");
        else if(field.equals("sdkRequestId"))y.mapping("pattern","^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}$");
        else if(field.equals("clientNonce")) {y.mapping("pattern","^[A-Za-z0-9_-]{43}$");y.mapping("description","Canonical unpadded base64url of exactly 32 bytes; canonical pad bits are checked by the decoder.");}
        else if(field.equals("primaryProof"))binary(y,1,104);
        else if(field.equals("alternativeProof"))binary(y,4627,4627);
        else if(field.endsWith("Der")||field.equals("csr")||field.endsWith("Frame")||field.endsWith("Signature")) {
            y.mapping("pattern","^[A-Za-z0-9_-]+$");
            y.mapping("description","Canonical unpadded base64url of exact bytes; native codec/frame and advertised listener/component bounds apply.");
        }
    }
    private static void binary(YamlBuilder y,int minimum,int maximum) {
        y.mapping("pattern","^[A-Za-z0-9_-]+$");
        y.mappingLiteral("minLength",Integer.toString((minimum*4+2)/3));
        y.mappingLiteral("maxLength",Integer.toString((maximum*4+2)/3));
        y.mapping("description","Canonical unpadded base64url; decoded size "+minimum+".."+maximum+" bytes.");
    }
}
