/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import zeroecho.core.annotation.Describable;
import zeroecho.core.annotation.DisplayName;

/**
 * Immutable snapshot of discovered {@link CryptoAlgorithm} implementations,
 * with utilities to validate and serialize the catalog.
 *
 * <p>
 * {@code CryptoCatalog} is a lightweight registry built at a point in time via
 * {@link #load()}. It collects algorithms published through the Java SPI for
 * {@link CryptoAlgorithm}, ensures identifier uniqueness, and exposes:
 * </p>
 *
 * <ul>
 * <li>{@link #validate()} — sanity checks that each algorithm publishes at
 * least one capability or key builder,</li>
 * <li>{@link #toJson()} — a compact JSON description of algorithms,
 * capabilities, and registered key builders, and</li>
 * <li>{@link #toXml()} — an XML rendition of the same data.</li>
 * </ul>
 *
 * <h2>Identity and uniqueness</h2> Algorithm ids are treated as canonical keys.
 * If two providers expose the same {@linkplain CryptoAlgorithm#id() id}, the
 * catalog build fails with {@link IllegalStateException}.
 *
 * <h2>Immutability &amp; thread-safety</h2> After construction, the internal
 * map is unmodifiable and safe to share across threads. This class performs no
 * lazy discovery or on-demand mutation.
 *
 * <h2>Serialization formats</h2>
 * <ul>
 * <li><b>JSON</b>: produced by {@link #toJson()} as a single object with an
 * {@code algorithms} array; trivial string escaping is applied.</li>
 * <li><b>XML</b>: produced by {@link #toXml()} with a {@code <cryptoCatalog>}
 * root; {@code &amp;&lt;&gt;} escaping is applied to element text and
 * attributes.</li>
 * </ul>
 *
 * <p>
 * <b>Note:</b> Default spec / key-spec values shown in outputs are derived from
 * {@code Supplier}s registered by algorithms. Suppliers may compute labels or
 * return lightweight descriptors; their intent is documentation, not
 * round‑tripping.
 * </p>
 *
 * @since 1.0
 */
public final class CryptoCatalog {
    private final Map<String, CryptoAlgorithm> algos;

    private CryptoCatalog(Map<String, CryptoAlgorithm> algos) {
        this.algos = algos;
    }

    /**
     * Discovers {@link CryptoAlgorithm} implementations via {@link ServiceLoader}
     * and returns an immutable catalog snapshot.
     *
     * <p>
     * During loading, algorithm ids are checked for uniqueness. A duplicate id
     * results in an {@link IllegalStateException} to prevent ambiguous resolution.
     * </p>
     *
     * @return an immutable {@code CryptoCatalog} with all discovered algorithms
     * @throws IllegalStateException if two providers declare the same algorithm id
     */
    public static CryptoCatalog load() {
        Map<String, CryptoAlgorithm> m = new HashMap<>();
        ServiceLoader.load(CryptoAlgorithm.class).forEach(a -> {
            CryptoAlgorithm prev = m.put(a.id(), a);
            if (prev != null) {
                throw new IllegalStateException("Duplicate algorithm id: " + a.id());
            }
        });
        return new CryptoCatalog(Collections.unmodifiableMap(m));
    }

    /**
     * Verifies that each algorithm in this catalog exposes at least one capability
     * or key builder.
     *
     * <p>
     * This is a sanity check for provider completeness. If an algorithm publishes
     * neither {@link CryptoAlgorithm#listCapabilities() capabilities} nor
     * asymmetric/symmetric key builders, the validation fails.
     * </p>
     *
     * @throws IllegalStateException if any algorithm has no capabilities and no key
     *                               builders
     */
    public void validate() {
        StringBuilder sb = null;
        for (CryptoAlgorithm a : algos.values()) {
            boolean hasCaps = !a.listCapabilities().isEmpty();
            boolean hasAsym = !a.asymmetricBuildersInfo().isEmpty();
            boolean hasSym = !a.symmetricBuildersInfo().isEmpty();
            if (!hasCaps && !hasAsym && !hasSym) {
                if (sb == null) {
                    sb = new StringBuilder(50 /* minimal record size */ * 6 /* suggested avg of error records */); // NOPMD
                }
                sb.append("Algorithm ").append(a.id()).append(" has no capabilities nor key builders.\n");
            }
        }
        if (sb != null) {
            throw new IllegalStateException(sb.toString());
        }
    }

    private static String labelOf(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof Describable) {
            return ((Describable) o).description();
        }
        Class<?> c = o instanceof Class<?> ? (Class<?>) o : o.getClass();
        DisplayName dn = c.getAnnotation(DisplayName.class);
        if (dn != null) {
            return dn.value();
        }
        return c.getSimpleName();
    }

    /**
     * Serializes the catalog to a compact JSON document.
     *
     * <p>
     * The schema is:
     * </p>
     * <pre>{@code
     * {
     *   "algorithms": [
     *     {
     *       "id": "AES/GCM",
     *       "displayName": "AES-GCM",
     *       "capabilities": [
     *         {
     *           "family": "SYMMETRIC",
     *           "role": "ENCRYPT",
     *           "contextType": "AeadEncryptContext",
     *           "keyType": "SecretKey",
     *           "specType": "AeadSpec",
     *           "defaultSpec": "Random nonce, 128-bit tag"
     *         }
     *       ],
     *       "asymmetricKeyBuilders": [
     *         { "specType": "Ed25519Spec", "defaultKeySpec": "Ed25519 default" }
     *       ],
     *       "symmetricKeyBuilders": [
     *         { "specType": "AesKeySpec", "defaultKeySpec": "AES-256" }
     *       ]
     *     }
     *   ]
     * }
     * }</pre>
     *
     * <p>
     * String values are escaped for quotes and backslashes. The method does not
     * attempt to pretty-print; callers can format the output if needed.
     * </p>
     *
     * @return a JSON string describing algorithms, capabilities, and key builders
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("{\"algorithms\":[");
        boolean firstAlgo = true;
        for (CryptoAlgorithm a : algos.values()) {
            if (!firstAlgo) {
                sb.append(',');
            }
            firstAlgo = false;

            sb.append('{').append(jsonField("id", a.id())).append(',').append(jsonField("displayName", a.displayName()))
                    .append(",\"capabilities\":[");

            boolean fc = true;
            for (Capability cap : a.listCapabilities()) {
                if (!fc) {
                    sb.append(',');
                }
                fc = false;
                sb.append('{').append(jsonField("family", cap.family().name())).append(',')
                        .append(jsonField("role", cap.role().name())).append(',')
                        .append(jsonField("contextType", cap.contextType().getSimpleName())).append(',')
                        .append(jsonField("keyType", cap.keyType().getSimpleName())).append(',')
                        .append(jsonField("specType", cap.specType().getSimpleName())).append(",\"defaultSpec\":")
                        .append(cap.defaultSpec() == null ? "null" : jsonString(labelOf(cap.defaultSpec().get())))
                        .append('}');
            }
            sb.append("],\"asymmetricKeyBuilders\":[");
            boolean fa = true;
            for (CryptoAlgorithm.AsymBuilderInfo kb : a.asymmetricBuildersInfo()) {
                if (!fa) {
                    sb.append(',');
                }
                fa = false;
                sb.append('{').append(jsonField("specType", kb.specType.getSimpleName())).append(",\"defaultKeySpec\":")
                        .append(kb.defaultKeySpec == null ? "null" : jsonString(labelOf(kb.defaultKeySpec)))
                        .append('}');
            }
            sb.append("],\"symmetricKeyBuilders\":[");
            boolean fs = true;
            for (CryptoAlgorithm.SymBuilderInfo kb : a.symmetricBuildersInfo()) {
                if (!fs) {
                    sb.append(',');
                }
                fs = false;
                sb.append('{').append(jsonField("specType", kb.specType().getSimpleName()))
                        .append(",\"defaultKeySpec\":")
                        .append(kb.defaultKeySpec() == null ? "null" : jsonString(labelOf(kb.defaultKeySpec())))
                        .append('}');
            }
            sb.append("]}");
        }
        sb.append("]}");
        return sb.toString();
    }

    /**
     * Serializes the catalog to an XML document.
     *
     * <p>
     * The root element is {@code <cryptoCatalog>}. Each algorithm becomes an
     * {@code <algorithm>} element with {@code id} and {@code name} attributes, plus
     * nested sections for {@code <capabilities>}, {@code <asymmetricKeyBuilders>},
     * and {@code <symmetricKeyBuilders>}.
     * </p>
     *
     * <p>
     * Element text and attribute values are escaped for {@code &amp;, &lt;, &gt;}.
     * </p>
     *
     * @return an XML string describing algorithms, capabilities, and key builders
     */
    public String toXml() {
        StringBuilder sb = new StringBuilder(4096);
        sb.append("<cryptoCatalog>");
        for (CryptoAlgorithm a : algos.values()) {
            sb.append("<algorithm id=\"").append(esc(a.id())).append("\" name=\"").append(esc(a.displayName()))
                    .append("\"><capabilities>");
            for (Capability cap : a.listCapabilities()) {
                sb.append("<capability family=\"").append(cap.family().name()).append("\" role=\"")
                        .append(cap.role().name()).append("\"><contextType>")
                        .append(esc(cap.contextType().getSimpleName())).append("</contextType><keyType>")
                        .append(esc(cap.keyType().getSimpleName())).append("</keyType><specType>")
                        .append(esc(cap.specType().getSimpleName())).append("</specType><defaultSpec>")
                        .append(esc(labelOf(cap.defaultSpec().get()))).append("</defaultSpec></capability>");
            }
            sb.append("</capabilities><asymmetricKeyBuilders>");
            for (CryptoAlgorithm.AsymBuilderInfo kb : a.asymmetricBuildersInfo()) {
                sb.append("<keyBuilder specType=\"").append(esc(kb.specType.getSimpleName()))
                        .append("\"><defaultKeySpec>")
                        .append(kb.defaultKeySpec == null ? "" : esc(labelOf(kb.defaultKeySpec)))
                        .append("</defaultKeySpec></keyBuilder>");
            }
            sb.append("</asymmetricKeyBuilders><symmetricKeyBuilders>");
            for (CryptoAlgorithm.SymBuilderInfo kb : a.symmetricBuildersInfo()) {
                sb.append("<keyBuilder specType=\"").append(esc(kb.specType().getSimpleName()))
                        .append("\"><defaultKeySpec>")
                        .append(kb.defaultKeySpec() == null ? "" : esc(labelOf(kb.defaultKeySpec())))
                        .append("</defaultKeySpec></keyBuilder>");
            }
            sb.append("</symmetricKeyBuilders></algorithm>");
        }
        sb.append("</cryptoCatalog>");
        return sb.toString();
    }

    private static String jsonField(String name, String value) {
        return jsonString(name) + ":" + jsonString(value);
    }

    private static String jsonString(String v) {
        return v == null ? "null" : "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String esc(String v) {
        return v == null ? "" : v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
