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
package zeroecho.pkix;

import java.util.Arrays;
import java.util.Objects;

/**
 * Provider-independent X.509 {@code AlgorithmIdentifier} (RFC 5280): an OID with
 * an exactly-typed parameter form.
 *
 * <p>
 * This is a canonical value type. It never depends on a concrete cryptographic
 * toolkit; it captures precisely how the algorithm parameters are encoded so that
 * a backend can reproduce the exact DER form:
 * </p>
 * <ul>
 * <li>{@link ParameterForm#ABSENT} — no {@code parameters} field is present;</li>
 * <li>{@link ParameterForm#DER_NULL} — the {@code parameters} field is DER NULL;</li>
 * <li>{@link ParameterForm#EXACT_DER} — the {@code parameters} field is the exact
 * canonical DER carried by {@link #parameters()}.</li>
 * </ul>
 */
public final class AlgorithmIdentifier {

    /** Encoding form of the optional {@code parameters} field. */
    public enum ParameterForm {
        /** No parameters field. */
        ABSENT,
        /** Parameters field present and equal to DER NULL. */
        DER_NULL,
        /** Parameters field present and equal to exact canonical DER. */
        EXACT_DER
    }

    private final String oid;
    private final ParameterForm parameterForm;
    private final byte[] parameters;

    private AlgorithmIdentifier(String oid, ParameterForm parameterForm, byte[] parameters) {
        this.oid = requireOid(oid);
        this.parameterForm = Objects.requireNonNull(parameterForm, "parameterForm");
        this.parameters = parameters == null ? null : parameters.clone();
    }

    /**
     * Creates an identifier with no {@code parameters} field.
     *
     * @param oid dotted-decimal object identifier
     * @return identifier with an absent parameter field
     */
    public static AlgorithmIdentifier absent(String oid) {
        return new AlgorithmIdentifier(oid, ParameterForm.ABSENT, null);
    }

    /**
     * Creates an identifier whose {@code parameters} field is DER NULL.
     *
     * @param oid dotted-decimal object identifier
     * @return identifier with a DER NULL parameter field
     */
    public static AlgorithmIdentifier derNull(String oid) {
        return new AlgorithmIdentifier(oid, ParameterForm.DER_NULL, null);
    }

    /**
     * Creates an identifier whose {@code parameters} field is exact canonical DER.
     *
     * @param oid dotted-decimal object identifier
     * @param derParameters exact DER encoding of the parameters field
     * @return identifier with an exact-DER parameter field
     */
    public static AlgorithmIdentifier exact(String oid, byte[] derParameters) {
        Objects.requireNonNull(derParameters, "derParameters");
        return new AlgorithmIdentifier(oid, ParameterForm.EXACT_DER, derParameters);
    }

    /**
     * Returns the dotted-decimal object identifier.
     *
     * @return the OID
     */
    public String oid() {
        return oid;
    }

    /**
     * Returns the parameter encoding form.
     *
     * @return the parameter form
     */
    public ParameterForm parameterForm() {
        return parameterForm;
    }

    /**
     * Returns a copy of the exact DER parameters, or {@code null} unless the form
     * is {@link ParameterForm#EXACT_DER}.
     *
     * @return a defensive copy of the parameter DER, or {@code null}
     */
    public byte[] parameters() {
        return parameters == null ? null : parameters.clone();
    }

    private static String requireOid(String oid) {
        Objects.requireNonNull(oid, "oid");
        if (oid.isBlank()) {
            throw new IllegalArgumentException("oid must not be blank");
        }
        return oid;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof AlgorithmIdentifier that)) {
            return false;
        }
        return oid.equals(that.oid) && parameterForm == that.parameterForm
                && Arrays.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(oid, parameterForm, Arrays.hashCode(parameters));
    }

    @Override
    public String toString() {
        return "AlgorithmIdentifier[oid=" + oid + ", parameterForm=" + parameterForm + ']';
    }
}
