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

import zeroecho.pki.server.http.HybridSdkHttpCodec;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Emits OpenAPI fragments for explicitly optional SDK adapters and retained admin requests.
 *
 * <p>The projection describes existing carrier authentication/media distinctions,
 * not listener activation or runtime authorization. Enrollment subject proofs do
 * not replace native authentication, and OCSP F4/F5 evidence is the separate SDK
 * profile rather than standard AltSignature OCSP.</p>
 */
final class SdkOpenApi {
    private static final String ADMIN = "Admin";
    private static final String ACME = "Acme";
    private static final String EST = "Est";
    private static final String JSON = "application/json";
    private static final String DESCRIPTION = "description";
    private static final String TYPE = "type";
    private static final String VERSION = "version";
    private static final String PROFILE = "profile";
    private static final List<Boolean> ACCEPTANCE_MODES = List.of(false, true);
    private static final Pattern PATH_PARAMETER = Pattern.compile("\\{([^}]+)}");

    private static final String POST = "post";
    private static final String ARGUMENTS = "arguments";
    private static final String INTENT_ID = "intentId";
    private static final String SDK_REQUEST_ID = "sdkRequestId";
    private static final String CLIENT_NONCE = "clientNonce";
    private static final String PRIMARY_PROOF = "primaryProof";
    private static final String ALTERNATIVE_PROOF = "alternativeProof";
    private static final String OPERATION_ID = "operationId";

    private SdkOpenApi() {}

    /**
     * Appends retained-request and optional adapter paths to the current YAML mapping.
     *
     * @param y caller-owned builder positioned in the paths mapping
     */
    /* default */ static void paths(YamlBuilder y) {
        administrativeRequests(y);
        for (String adapter : List.of(ADMIN, ACME, EST, "Scep", "Cmp")) {
            adapterPaths(y, adapter);
        }

        y.blockMapping(
                "'/ocsp/{alias}/hybrid-sdk/v1'",
                () -> {
                    listener(y, "Ocsp");
                    for (String method : List.of("get", POST)) {
                        y.blockMapping(
                                method,
                                () -> {
                                    y.mappingLiteral("security", "[]");
                                    y.mapping(
                                            "summary",
                                            "get".equals(method)
                                                    ? "Optional OCSP SDK capability"
                                                    : "Native OCSP response with separate dual-signature SDK evidence");
                                    y.mapping(
                                            DESCRIPTION,
                                            "Listener and responder must both opt in; otherwise 404. GET is metadata only. POST retains native signed/unsigned requester, trust, CertID, nonce and replay policy. The independent 32-byte SDK nonce does not replace the native OCSP nonce. This is ZeroEcho SDK evidence, not standard AltSignature OCSP. No partial bundle is returned.");
                                    parameters(y, "/ocsp/{alias}/hybrid-sdk/v1");
                                    if (POST.equals(method)) {
                                        body(y, HybridSdkHttpCodec.MEDIA_TYPE, "SdkOcspRequest");
                                    }
                                    responses(
                                            y,
                                            "200",
                                            HybridSdkHttpCodec.MEDIA_TYPE,
                                            "get".equals(method)
                                                    ? "SdkOcspCapability"
                                                    : "SdkOcspBundle",
                                            false);
                                });
                    }
                });
    }

    private static void adapterPaths(YamlBuilder y, String adapter) {
        String base =
                switch (adapter) {
                    case ADMIN -> "/hybrid-sdk/v1";
                    case ACME -> "/acme/{alias}/hybrid-sdk/v1";
                    case EST -> "/.well-known/est/{label}/hybrid-sdk/v1";
                    case "Scep" -> "/scep/{label}/hybrid-sdk/v1";
                    default -> "/pkix/{label}/hybrid-sdk/v1";
                };
        y.blockMapping(
                "'" + base + "'",
                () -> {
                    listener(y, adapter);
                    y.blockMapping(
                            "get",
                            () -> {
                                authentication(y, adapter, true);
                                y.mapping("summary", adapter + " optional SDK capability");
                                parameters(y, base);
                                responses(
                                        y,
                                        "200",
                                        ADMIN.equals(adapter) || ACME.equals(adapter)
                                                ? JSON
                                                : HybridSdkHttpCodec.MEDIA_TYPE,
                                        "SdkCapability",
                                        false);
                            });
                });
        for (boolean accept : ACCEPTANCE_MODES) {
            acceptancePath(y, adapter, base, accept);
        }
    }

    private static void acceptancePath(YamlBuilder y, String adapter, String base, boolean accept) {
        String path =
                base
                        + (accept ? "/accept" : "/challenge")
                        + (ACME.equals(adapter) ? "/{orderId}" : "");
        y.blockMapping(
                "'" + path + "'",
                () -> {
                    listener(y, adapter);
                    y.blockMapping(
                            POST,
                            () -> {
                                authentication(y, adapter, false);
                                y.mapping(
                                        "summary",
                                        adapter + " SDK " + (accept ? "acceptance" : "challenge"));
                                y.mapping(
                                        DESCRIPTION,
                                        "Explicit listener and enrollment-profile opt-in required; otherwise 404. Native protocol authentication and policy remain mandatory. Subject proofs do not authenticate the protocol. Reuse retained intent/request identity after uncertain results; never silently create a fresh signing attempt.");
                                parameters(y, path);
                                if (ACME.equals(adapter)) {
                                    y.mapping(
                                            "x-zeroecho-jws-payload-schema",
                                            "#/components/schemas/SdkAcme"
                                                    + (accept ? "Accept" : "Challenge")
                                                    + "Request");
                                }
                                body(
                                        y,
                                        ACME.equals(adapter)
                                                ? "application/jose+json"
                                                : HybridSdkHttpCodec.MEDIA_TYPE,
                                        ACME.equals(adapter)
                                                ? "SdkAcmeJws"
                                                : "Sdk"
                                                        + adapter
                                                        + (accept ? "Accept" : "Challenge")
                                                        + "Request");
                                String media =
                                        accept ? acceptanceMedia(adapter) : challengeMedia(adapter);
                                responses(
                                        y,
                                        accept && ADMIN.equals(adapter) ? "202" : "200",
                                        media,
                                        accept ? acceptanceSchema(adapter) : "SdkChallenge",
                                        accept && EST.equals(adapter));
                            });
                });
    }

    private static String challengeMedia(String adapter) {
        return ADMIN.equals(adapter) || ACME.equals(adapter) ? JSON : HybridSdkHttpCodec.MEDIA_TYPE;
    }

    private static String acceptanceMedia(String adapter) {
        return switch (adapter) {
            case ADMIN, ACME -> JSON;
            case EST -> "application/pkcs7-mime; smime-type=certs-only";
            case "Scep" -> "application/x-pki-message";
            default -> "application/pkixcmp";
        };
    }

    private static String acceptanceSchema(String adapter) {
        return switch (adapter) {
            case ADMIN -> "OperationResponse";
            case ACME -> "SdkAcmeOrder";
            default -> null;
        };
    }

    private static void administrativeRequests(YamlBuilder y) {
        y.blockMapping(
                "'/requests'",
                () ->
                        y.blockMapping(
                                POST,
                                () -> {
                                    y.mapping(
                                            "summary", "Submit a retained administrative request");
                                    y.mapping(
                                            DESCRIPTION,
                                            "Normal operation authorization and explicit approval policy apply. Managed OCSP provisioning is canonical by actual key tuple and issuer generation: equivalent retries return the retained canonical request/result, including with another caller request ID. Changed targets return OCSP_PROVISIONING_TARGET_CONFLICT with canonicalRequestId. Same-slot renewal requires the exact completed predecessor credential; uncertain attempts must be inspected rather than replaced.");
                                    body(y, JSON, "AdministrativeSubmission");
                                    y.blockMapping(
                                            "responses",
                                            () -> {
                                                response(
                                                        y,
                                                        "202",
                                                        "Accepted or replayed retained request; provisioning includes Location pointing to the canonical request.",
                                                        JSON,
                                                        "OperationResponse");
                                                response(
                                                        y,
                                                        "409",
                                                        "REQUEST_ID_CONFLICT or OCSP_PROVISIONING_TARGET_CONFLICT; the latter includes result.canonicalRequestId and canonical Location.",
                                                        JSON,
                                                        "OperationResponse");
                                                errors(y);
                                            });
                                }));
        y.blockMapping(
                "'/requests/{requestId}'",
                () ->
                        y.blockMapping(
                                "get",
                                () -> {
                                    y.mapping(
                                            "summary",
                                            "Inspect an authorized retained administrative request");
                                    parameters(y, "/requests/{requestId}");
                                    responses(y, "200", JSON, "OperationResponse", false);
                                }));
    }

    private static void listener(YamlBuilder y, String adapter) {
        if (!ADMIN.equals(adapter)) {
            y.blockMapping(
                    "servers",
                    () ->
                            y.sequenceItem(
                                    () -> {
                                        y.mapping("url", "https://{host}:{port}");
                                        y.mapping(
                                                DESCRIPTION,
                                                adapter
                                                        + " listener; configure its actual host and port independently of the administrative listener");
                                        y.blockMapping(
                                                "variables",
                                                () -> {
                                                    y.blockMapping(
                                                            "host",
                                                            () ->
                                                                    y.mapping(
                                                                            "default",
                                                                            "localhost"));
                                                    y.blockMapping(
                                                            "port",
                                                            () -> y.mapping("default", "443"));
                                                });
                                    }));
        }
    }

    private static void authentication(YamlBuilder y, String adapter, boolean capability) {
        if (!ADMIN.equals(adapter) && !EST.equals(adapter)) {
            y.mappingLiteral("security", "[]");
        }
        y.mapping(
                "x-zeroecho-authentication",
                switch (adapter) {
                    case ADMIN -> "Administrative mutual TLS and current operation authorization";
                    case EST -> "EST mutual TLS and endpoint principal/authorization policy";
                    case ACME ->
                            capability
                                    ? "Public capability"
                                    : "ACME account JWS, nonce, exact URL and order ownership";
                    case "Scep" ->
                            capability
                                    ? "Public capability"
                                    : "SCEP CMS message authentication and endpoint policy";
                    default ->
                            capability
                                    ? "Public capability"
                                    : "CMP protected-message authentication and endpoint policy";
                });
    }

    private static void parameters(YamlBuilder y, String path) {
        Matcher names = PATH_PARAMETER.matcher(path);
        List<String> values = new ArrayList<>();
        while (names.find()) {
            values.add(names.group(1));
        }
        if (!values.isEmpty()) {
            y.blockMapping(
                    "parameters",
                    () ->
                            values.forEach(
                                    name ->
                                            y.sequenceItem(
                                                    () -> {
                                                        y.mapping("name", name);
                                                        y.mapping("in", "path");
                                                        y.mappingLiteral("required", "true");
                                                        y.blockMapping(
                                                                "schema",
                                                                () -> y.mapping(TYPE, "string"));
                                                    })));
        }
    }

    private static void body(YamlBuilder y, String media, String schema) {
        y.blockMapping(
                "requestBody",
                () -> {
                    y.mappingLiteral("required", "true");
                    y.blockMapping(
                            "content",
                            () ->
                                    y.blockMapping(
                                            "'" + media + "'",
                                            () ->
                                                    y.refMapping(
                                                            "schema",
                                                            "#/components/schemas/" + schema)));
                });
    }

    private static void responses(
            YamlBuilder y, String status, String media, String schema, boolean pending) {
        y.blockMapping(
                "responses",
                () -> {
                    response(y, status, "Existing native adapter result", media, schema);
                    y.blockMapping(
                            "'409'",
                            () ->
                                    y.mapping(
                                            DESCRIPTION,
                                            "Native conflict; SDK_INTENT_CONFLICT retains the existing intent identity. Error media and grammar remain adapter-specific."));
                    if (pending) {
                        response(
                                y,
                                "202",
                                "Enrollment pending; Retry-After retains native EST behavior",
                                "text/plain",
                                null);
                    }
                    errors(y);
                });
    }

    private static void response(
            YamlBuilder y, String status, String description, String media, String schema) {
        y.blockMapping(
                "'" + status + "'",
                () -> {
                    y.mapping(DESCRIPTION, description);
                    y.blockMapping(
                            "content",
                            () ->
                                    y.blockMapping(
                                            "'" + media + "'",
                                            () -> {
                                                if (schema != null) {
                                                    y.refMapping(
                                                            "schema",
                                                            "#/components/schemas/" + schema);
                                                } else {
                                                    y.blockMapping(
                                                            "schema",
                                                            () -> {
                                                                y.mapping(TYPE, "string");
                                                                y.mapping("format", "binary");
                                                            });
                                                }
                                            }));
                });
    }

    private static void errors(YamlBuilder y) {
        for (String status :
                List.of("400", "401", "403", "404", "405", "413", "415", "429", "500", "503")) {
            y.blockMapping(
                    "'" + status + "'",
                    () ->
                            y.mapping(
                                    DESCRIPTION,
                                    "Native adapter rejection, unavailable opt-in, resource bound or transient failure; response media and grammar remain adapter-specific"));
        }
    }

    /**
     * Appends the shared request/response component schemas used by the emitted paths.
     *
     * <p>Patterns and declared bounds describe representation requirements; runtime
     * native decoders and listener/component budgets remain authoritative.</p>
     *
     * @param y caller-owned builder positioned in components.schemas
     */
    /* default */ static void schemas(YamlBuilder y) {
        for (String adapter : List.of(ADMIN, ACME, EST, "Scep", "Cmp")) {
            for (boolean accept : ACCEPTANCE_MODES) {
                List<String> fields = requestFields(adapter, accept);
                object(
                        y,
                        "Sdk" + adapter + (accept ? "Accept" : "Challenge") + "Request",
                        fields,
                        fields);
            }
        }
        List<String> challenge =
                List.of(
                        VERSION,
                        PROFILE,
                        INTENT_ID,
                        "primaryFrame",
                        "alternativeFrame",
                        "targetFrame",
                        "expiresAt");
        object(y, "SdkChallenge", challenge, challenge);
        List<String> capability =
                List.of(
                        VERSION,
                        PROFILE,
                        "canonicalOrigin",
                        "maximumRequestDerBytes",
                        "maximumDurableAdmissionBytes",
                        "challenge",
                        "accept",
                        "operations",
                        "maximumBodyBytes",
                        "maximumPrimaryProofBytes",
                        "alternativeProofBytes");
        object(y, "SdkCapability", capability, capability);
        List<String> ocsp = List.of(VERSION, PROFILE, "requestDer", CLIENT_NONCE);
        object(y, "SdkOcspRequest", ocsp, ocsp);
        List<String> bundle =
                List.of(
                        VERSION,
                        PROFILE,
                        "primaryResponseDer",
                        "responderChain",
                        "primaryFrame",
                        "alternativeFrame",
                        "primarySignature",
                        "alternativeSignature");
        object(y, "SdkOcspBundle", bundle, bundle);
        List<String> ocspCapability =
                List.of(
                        VERSION,
                        PROFILE,
                        "canonicalOrigin",
                        "route",
                        "mediaType",
                        "maximumBodyBytes",
                        "maximumNativeRequestBytes",
                        "maximumEntries",
                        "clientNonceBytes",
                        "maximumEvidenceLifetimeSeconds",
                        "maximumResponseBytes");
        object(y, "SdkOcspCapability", ocspCapability, ocspCapability);
        List<String> submit =
                List.of(VERSION, "requestId", "operation", ARGUMENTS, "authorityId", "deadline");
        object(
                y,
                "AdministrativeSubmission",
                submit,
                List.of(VERSION, "requestId", "operation", ARGUMENTS));
        List<String> jws = List.of("protected", "payload", "signature");
        object(y, "SdkAcmeJws", jws, jws);
        y.blockMapping(
                "SdkAcmeOrder",
                () -> {
                    y.mapping(TYPE, "object");
                    y.mapping(
                            DESCRIPTION,
                            "Native ACME order object; SDK acceptance returns the existing ACME order representation and Location.");
                });
    }

    private static List<String> requestFields(String adapter, boolean accept) {
        List<String> fields = new ArrayList<>(List.of(VERSION, PROFILE));
        fields.addAll(
                switch (adapter) {
                    case ADMIN -> List.of(OPERATION_ID, ARGUMENTS, "requestDer");
                    case ACME -> List.of("csr");
                    case EST -> List.of("operation", "requestDer");
                    default -> List.of("messageDer");
                });
        fields.addAll(
                accept
                        ? List.of(INTENT_ID, SDK_REQUEST_ID, PRIMARY_PROOF, ALTERNATIVE_PROOF)
                        : List.of(CLIENT_NONCE));
        return fields;
    }

    private static void object(
            YamlBuilder y, String name, List<String> fields, List<String> required) {
        y.blockMapping(
                name,
                () -> {
                    y.mappingLiteral(TYPE, "object");
                    y.mappingLiteral("additionalProperties", "false");
                    y.blockMapping("required", () -> required.forEach(y::sequenceItemString));
                    y.blockMapping(
                            "properties",
                            () ->
                                    fields.forEach(
                                            field ->
                                                    y.blockMapping(
                                                            field, () -> field(y, name, field))));
                });
    }

    private static void field(YamlBuilder y, String schema, String field) {
        boolean integer =
                VERSION.equals(field) || field.startsWith("maximum") || field.endsWith("Bytes");
        if (ARGUMENTS.equals(field)) {
            y.mapping(TYPE, "object");
            return;
        }
        if ("operations".equals(field) || "responderChain".equals(field)) {
            y.mapping(TYPE, "array");
            y.blockMapping("items", () -> y.mapping(TYPE, "string"));
            return;
        }
        y.mapping(TYPE, integer ? "integer" : "string");
        if (VERSION.equals(field)) {
            y.mappingLiteral("const", "1");
        } else if (PROFILE.equals(field)) {
            y.mapping("const", HybridSdkHttpCodec.PROFILE);
        } else {
            fieldConstraint(y, schema, field);
        }
    }

    private static void fieldConstraint(YamlBuilder y, String schema, String field) {
        if (enumeratedField(y, schema, field)) {
            return;
        }
        if (INTENT_ID.equals(field)) {
            y.mapping("pattern", "^[0-9a-f]{64}$");
        } else if (SDK_REQUEST_ID.equals(field)) {
            y.mapping("pattern", "^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}$");
        } else if (CLIENT_NONCE.equals(field)) {
            y.mapping("pattern", "^[A-Za-z0-9_-]{43}$");
            y.mapping(
                    DESCRIPTION,
                    "Canonical unpadded base64url of exactly 32 bytes; canonical pad bits are checked by the decoder.");
        } else if (PRIMARY_PROOF.equals(field)) {
            binary(y, 1, 104);
        } else if (ALTERNATIVE_PROOF.equals(field)) {
            binary(y, 4_627, 4_627);
        } else if (field.endsWith("Der")
                || "csr".equals(field)
                || field.endsWith("Frame")
                || field.endsWith("Signature")) {
            y.mapping("pattern", "^[A-Za-z0-9_-]+$");
            y.mapping(
                    DESCRIPTION,
                    "Canonical unpadded base64url of exact bytes; native codec/frame and advertised listener/component bounds apply.");
        }
    }

    private static boolean enumeratedField(YamlBuilder y, String schema, String field) {
        if (OPERATION_ID.equals(field)) {
            y.blockMapping(
                    "enum",
                    () ->
                            List.of(
                                            "credential.issue",
                                            "credential.renew",
                                            "credential.reissue",
                                            "credential.replace")
                                    .forEach(y::sequenceItemString));
            return true;
        }
        if ("operation".equals(field) && schema.startsWith("SdkEst")) {
            y.blockMapping(
                    "enum",
                    () -> List.of("simpleenroll", "simplereenroll").forEach(y::sequenceItemString));
            return true;
        }
        return false;
    }

    private static void binary(YamlBuilder y, int minimum, int maximum) {
        y.mapping("pattern", "^[A-Za-z0-9_-]+$");
        y.mappingLiteral("minLength", Integer.toString((minimum * 4 + 2) / 3));
        y.mappingLiteral("maxLength", Integer.toString((maximum * 4 + 2) / 3));
        y.mapping(
                DESCRIPTION,
                "Canonical unpadded base64url; decoded size "
                        + minimum
                        + ".."
                        + maximum
                        + " bytes.");
    }
}
