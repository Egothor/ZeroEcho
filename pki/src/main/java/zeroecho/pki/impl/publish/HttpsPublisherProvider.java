/*******************************************************************************
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
package zeroecho.pki.impl.publish;

import java.net.URI;
import java.util.Set;

import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.publish.PublisherProvider;

/**
 * HTTPS publication destination provider.
 *
 * <p>Publishes PKI artefacts (certificates, CRLs, OCSP responses) to a
 * remote HTTPS endpoint via HTTP PUT or POST. The {@code credentials}
 * property, when present, is sent as the verbatim {@code Authorization}
 * header value and must be pre-resolved from the publisher secrets store
 * before this provider is allocated.</p>
 *
 * <h2>Required configuration keys</h2>
 * <dl>
 *   <dt>{@code url}</dt><dd>Target HTTPS URL. Must use the {@code https} scheme.</dd>
 *   <dt>{@code targetId}</dt><dd>Logical publication target identifier.</dd>
 * </dl>
 *
 * <h2>Optional configuration keys</h2>
 * <dl>
 *   <dt>{@code credentials}</dt>
 *   <dd>Verbatim {@code Authorization} header value (e.g. {@code Bearer <token>}
 *       or {@code Basic <base64>}). Secret references are resolved by
 *       {@code PublisherSecretResolver} before this provider is called.</dd>
 *   <dt>{@code method}</dt>
 *   <dd>HTTP method: {@code PUT} (default) or {@code POST}.</dd>
 * </dl>
 */
public final class HttpsPublisherProvider implements PublisherProvider {
    private static final String URL = "url";
    private static final String TARGET_ID = "targetId";
    private static final String CREDENTIALS = "credentials";
    private static final String METHOD = "method";

    /** Creates an HTTPS publisher provider descriptor. */
    public HttpsPublisherProvider() {
        // ServiceLoader creates this stateless provider descriptor.
    }

    @Override
    public String id() {
        return "https";
    }

    @Override
    public Set<String> supportedKeys() {
        return Set.of(URL, TARGET_ID, CREDENTIALS, METHOD);
    }

    @Override
    public void validateConfig(ProviderConfig config) {
        PublisherProvider.super.validateConfig(config);
        URI uri = URI.create(config.require(URL));
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException(
                    "HTTPS publisher URL must use the https scheme, got: " + uri.getScheme());
        }
        new PublicationTarget(PublicationTargetType.HTTP, config.require(TARGET_ID));
        config.get(METHOD).ifPresent(m -> {
            if (!"PUT".equalsIgnoreCase(m) && !"POST".equalsIgnoreCase(m)) {
                throw new IllegalArgumentException(
                        "HTTPS publisher method must be PUT or POST, got: " + m);
            }
        });
    }

    @Override
    public Publisher allocate(ProviderConfig config) {
        validateConfig(config);
        PublicationTarget target = new PublicationTarget(
                PublicationTargetType.HTTP, config.require(TARGET_ID));
        URI uri = URI.create(config.require(URL));
        String credentials = config.get(CREDENTIALS).orElse(null);
        String method = config.get(METHOD).orElse("PUT");
        return new HttpsPublisher(target, uri, credentials, method);
    }
}
