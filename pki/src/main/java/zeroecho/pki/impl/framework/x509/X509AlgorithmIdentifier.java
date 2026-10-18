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
package zeroecho.pki.impl.framework.x509;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Provider-neutral canonical X.509 {@code AlgorithmIdentifier} representation.
 *
 * <p>
 * Parameters distinguish absent, DER NULL, and exact canonical structured DER.
 * Parameter bytes are defensively copied. This value contains no Bouncy Castle
 * object and is immutable.
 * </p>
 */
public final class X509AlgorithmIdentifier {

    private static final Pattern OID = Pattern.compile("[0-2](?:\\.[0-9]+)+");
    private static final byte[] DER_NULL = { 0x05, 0x00 };

    /**
     * Exact parameter representation.
     */
    public enum ParameterForm {
        /** Parameters are omitted. */
        ABSENT,
        /** Parameters are canonical DER NULL. */
        DER_NULL,
        /** Parameters are exact canonical structured DER. */
        EXACT_DER
    }

    private final String oid;
    private final ParameterForm parameterForm;
    private final byte[] parameters;

    private X509AlgorithmIdentifier(String oid, ParameterForm parameterForm, byte[] parameters) {
        Objects.requireNonNull(oid, "oid");
        if (!OID.matcher(oid).matches()) {
            throw new IllegalArgumentException("Invalid dotted-decimal OID");
        }
        this.oid = oid;
        this.parameterForm = Objects.requireNonNull(parameterForm, "parameterForm");
        this.parameters = Objects.requireNonNull(parameters, "parameters").clone();
        if (parameterForm == ParameterForm.ABSENT && parameters.length != 0) {
            throw new IllegalArgumentException("Absent parameters must have no DER");
        }
        if (parameterForm == ParameterForm.DER_NULL && !Arrays.equals(DER_NULL, parameters)) {
            throw new IllegalArgumentException("DER NULL parameters must be canonical");
        }
        if (parameterForm == ParameterForm.EXACT_DER && parameters.length == 0) {
            throw new IllegalArgumentException("Exact parameters must not be empty");
        }
    }

    /**
     * Creates an identifier with absent parameters.
     *
     * @param oid dotted-decimal OID
     * @return immutable identifier
     */
    public static X509AlgorithmIdentifier absent(String oid) {
        return new X509AlgorithmIdentifier(oid, ParameterForm.ABSENT, new byte[0]);
    }

    /**
     * Creates an identifier with canonical DER NULL parameters.
     *
     * @param oid dotted-decimal OID
     * @return immutable identifier
     */
    public static X509AlgorithmIdentifier derNull(String oid) {
        return new X509AlgorithmIdentifier(oid, ParameterForm.DER_NULL, DER_NULL);
    }

    /**
     * Creates an identifier with exact canonical structured parameters.
     *
     * @param oid        dotted-decimal OID
     * @param parameters complete DER parameter value
     * @return immutable identifier
     */
    public static X509AlgorithmIdentifier exact(String oid, byte[] parameters) {
        return new X509AlgorithmIdentifier(oid, ParameterForm.EXACT_DER, parameters);
    }

    /**
     * Returns the OID.
     *
     * @return dotted-decimal OID
     */
    public String oid() {
        return oid;
    }

    /**
     * Returns the exact parameter form.
     *
     * @return parameter form
     */
    public ParameterForm parameterForm() {
        return parameterForm;
    }

    /**
     * Returns independently owned parameter DER.
     *
     * @return defensive copy, empty for absent parameters
     */
    public byte[] parameters() {
        return parameters.clone();
    }

    /**
     * Returns the deterministic reverse-lookup representation.
     *
     * @return OID, form, and exact DER
     */
    public String canonicalForm() {
        return oid + "|" + parameterForm + "|" + HexFormat.of().formatHex(parameters);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof X509AlgorithmIdentifier identifier && oid.equals(identifier.oid)
                && parameterForm == identifier.parameterForm && Arrays.equals(parameters, identifier.parameters);
    }

    @Override
    public int hashCode() {
        return 31 * (31 * oid.hashCode() + parameterForm.hashCode()) + Arrays.hashCode(parameters);
    }
}
