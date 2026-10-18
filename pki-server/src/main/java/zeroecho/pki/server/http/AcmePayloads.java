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

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import tools.jackson.core.json.JsonReadFeature;
import zeroecho.pki.server.acme.AcmeJwsVerifier;

/** Narrow large-scalar ACME endpoint payload decoder. */
@SuppressWarnings({ "PMD.ControlStatementBraces", "PMD.CyclomaticComplexity",
        "PMD.PreserveStackTrace", "PMD.AvoidCatchingGenericException" })
/* default */ final class AcmePayloads {
    private AcmePayloads() { }

    /* default */ static byte[] requiredBase64Url(byte[] document, String requiredField,
            int maximumDocumentBytes) {
        if (document == null || document.length == 0 || document.length > maximumDocumentBytes) {
            throw malformed();
        }
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(1)
                .maxDocumentLength(maximumDocumentBytes).maxTokenCount(4).maxNameLength(32)
                .maxStringLength(maximumDocumentBytes).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) builder.disable(feature);
        JsonFactory factory = builder.build();
        try (JsonParser parser = factory.createParser(ObjectReadContext.empty(), document, 0, document.length)) {
            if (parser.nextToken() != JsonToken.START_OBJECT || parser.nextToken() != JsonToken.PROPERTY_NAME
                    || !requiredField.equals(parser.currentName()) || parser.nextToken() != JsonToken.VALUE_STRING) {
                throw malformed();
            }
            String encoded = parser.getString();
            if (parser.nextToken() != JsonToken.END_OBJECT || parser.nextToken() != null
                    || encoded.indexOf('=') >= 0 || !encoded.matches("[A-Za-z0-9_-]+")) {
                throw malformed();
            }
            byte[] decoded = Base64.getUrlDecoder().decode(encoded);
            if (decoded.length > maximumDocumentBytes
                    || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(encoded)) {
                throw malformed();
            }
            return decoded;
        } catch (AcmeJwsVerifier.AcmeProblem problem) {
            throw problem;
        } catch (RuntimeException failure) {
            throw malformed();
        }
    }

    /* default */ static RevocationPayload revocation(byte[] document, int maximumDocumentBytes) {
        if (document == null || document.length == 0 || document.length > maximumDocumentBytes) throw malformed();
        StreamReadConstraints constraints = StreamReadConstraints.builder().maxNestingDepth(1)
                .maxDocumentLength(maximumDocumentBytes).maxTokenCount(7).maxNameLength(32)
                .maxStringLength(maximumDocumentBytes).maxNumberLength(3).build();
        JsonFactoryBuilder builder = JsonFactory.builder().streamReadConstraints(constraints)
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).disable(StreamReadFeature.AUTO_CLOSE_SOURCE);
        for (JsonReadFeature feature : JsonReadFeature.values()) builder.disable(feature);
        try (JsonParser parser = builder.build().createParser(ObjectReadContext.empty(), document, 0, document.length)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) throw malformed();
            String certificate = null; int reason = 0;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.PROPERTY_NAME) throw malformed();
                String name = parser.currentName(); JsonToken token = parser.nextToken();
                if ("certificate".equals(name) && token == JsonToken.VALUE_STRING && certificate == null) {
                    certificate = parser.getString();
                } else if ("reason".equals(name) && token == JsonToken.VALUE_NUMBER_INT) {
                    reason = parser.getIntValue();
                } else throw malformed();
            }
            if (parser.nextToken() != null || certificate == null || certificate.indexOf('=') >= 0
                    || !certificate.matches("[A-Za-z0-9_-]+")) throw malformed();
            byte[] decoded = Base64.getUrlDecoder().decode(certificate);
            if (decoded.length > maximumDocumentBytes
                    || !Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(certificate)) {
                throw malformed();
            }
            return new RevocationPayload(decoded, reason);
        } catch (AcmeJwsVerifier.AcmeProblem problem) {
            throw problem;
        } catch (RuntimeException failure) {
            throw malformed();
        }
    }

    /* default */ record RevocationPayload(byte[] certificateDer, int reasonCode) {
        RevocationPayload { certificateDer = certificateDer.clone(); }
        @Override public byte[] certificateDer() { return certificateDer.clone(); }
    }

    private static AcmeJwsVerifier.AcmeProblem malformed() {
        return new AcmeJwsVerifier.AcmeProblem("malformed");
    }
}
