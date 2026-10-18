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
package zeroecho.core.audit;

import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

import zeroecho.core.spec.ContextSpec;

/**
 * Utility for reflective inspection of {@link zeroecho.core.spec.ContextSpec}
 * implementations.
 *
 * <p>
 * {@code SpecIntrospector} attempts to call common accessor methods on a
 * {@code ContextSpec} (such as {@code mode()}, {@code tagLength()},
 * {@code hash()}, etc.) and collect their values into a map. The output is
 * suitable for diagnostics, debugging, or summary views where a lightweight,
 * uniform description of diverse spec types is required.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Inspection is best-effort. If a method does not exist or invocation
 * fails, the field is silently skipped.</li>
 * <li>The returned map is unmodifiable. At minimum it always contains a
 * {@code "type"} entry naming the spec’s simple class name.</li>
 * <li>Values are stringified using {@link String#valueOf(Object)} to provide
 * stable rendering across implementations.</li>
 * </ul>
 *
 * <p>
 * This class is not intended for production cryptographic decisions. Its output
 * is informational only and should not be used to enforce security policies.
 * </p>
 *
 * @since 1.0
 */
final class SpecIntrospector {
    /**
     * Summarizes a {@link ContextSpec} into a diagnostic map.
     *
     * <p>
     * Known optional fields include:
     * <ul>
     * <li>{@code mode} – operation mode (e.g., ENCRYPT, DECRYPT)</li>
     * <li>{@code tagLen} – authentication tag length</li>
     * <li>{@code ivLen} – initialization vector length</li>
     * <li>{@code aad} – whether additional authenticated data is present</li>
     * <li>{@code hash} – hash algorithm (e.g., SHA256)</li>
     * <li>{@code pssSaltLen} – salt length for PSS signatures</li>
     * <li>{@code kdf} – key derivation function name</li>
     * <li>{@code saltLen} – KDF salt length</li>
     * <li>{@code infoLen} – KDF info/context length</li>
     * <li>{@code header} – identifier of any associated header codec</li>
     * </ul>
     * </p>
     *
     * <p>
     * Any field not available on the given spec type is omitted. If reflection
     * fails entirely, the result will only contain {@code "type"}.
     * </p>
     *
     * @param spec the context specification to summarize
     * @return unmodifiable map of field names to string values
     */
    /* package */ static Map<String, Object> summarize(ContextSpec spec) {
        try {
            String klass = spec.getClass().getSimpleName();
            Object mode = tryCall(spec, "mode");
            Object tagLen = tryCall(spec, "tagLength");
            Object ivLen = tryCall(spec, "ivLength");
            Object aad = tryCall(spec, "aadPresent");
            Object pssHash = tryCall(spec, "hash");
            Object pssSalt = tryCall(spec, "pssSaltLen");
            Object kdf = tryCall(spec, "kdfName");
            Object hkdfSaltLen = tryCall(spec, "saltLength");
            Object hkdfInfoLen = tryCall(spec, "infoLength");
            Object headerCodec = tryCall(spec, "headerCodecId");

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", klass);
            putIfNonNull(m, "mode", mode);
            putIfNonNull(m, "tagLen", tagLen);
            putIfNonNull(m, "ivLen", ivLen);
            putIfNonNull(m, "aad", aad);
            putIfNonNull(m, "hash", pssHash);
            putIfNonNull(m, "pssSaltLen", pssSalt);
            putIfNonNull(m, "kdf", kdf);
            putIfNonNull(m, "saltLen", hkdfSaltLen);
            putIfNonNull(m, "infoLen", hkdfInfoLen);
            putIfNonNull(m, "header", headerCodec);

            return Map.copyOf(m); // unmodifiable view
        } catch (Throwable ignore) { // NOPMD
            return Map.of("type", spec.getClass().getSimpleName());
        }
    }

    /**
     * Hidden constructor; this class cannot be instantiated.
     */
    private SpecIntrospector() {
        // empty
    }

    /**
     * Puts a stringified value into a map if it is non-null.
     *
     * @param m map to update
     * @param k field name
     * @param v value to stringify and insert; ignored if {@code null}
     */
    private static void putIfNonNull(Map<String, Object> m, String k, Object v) {
        if (v != null) {
            m.put(k, String.valueOf(v));
        }
    }

    /**
     * Attempts to call a no-arg method by reflection.
     *
     * <p>
     * If the method does not exist or invocation fails, {@code null} is returned.
     * </p>
     *
     * @param obj    target object
     * @param method method name to call
     * @return return value of the method, or {@code null} if unavailable
     */
    private static Object tryCall(Object obj, String method) {
        try {
            Method m = obj.getClass().getMethod(method);
            m.setAccessible(true); // NOPMD
            return m.invoke(obj);
        } catch (Throwable ignore) { // NOPMD
            return null;
        }
    }
}
