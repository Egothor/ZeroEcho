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
package zeroecho.core;

import java.util.Objects;

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Immutable metadata for one exact key operation.
 *
 * @param operation   operation guaranteed by the associated lookup
 * @param specType    exact accepted specification type
 * @param defaultSpec resolved generation default, or {@code null} for import
 *                    operations and generators without a default
 * @since 1.0
 */
public record KeyOperationInfo(KeyOperation operation, Class<? extends AlgorithmKeySpec> specType,
        AlgorithmKeySpec defaultSpec) {

    /**
     * Validates the metadata invariant.
     *
     * @throws NullPointerException     if {@code operation} or {@code specType} is
     *                                  {@code null}
     * @throws IllegalArgumentException if a default is incompatible with
     *                                  {@code specType}, or an import operation
     *                                  declares a default
     */
    public KeyOperationInfo {
        Objects.requireNonNull(operation, "operation must not be null");
        Objects.requireNonNull(specType, "specType must not be null");
        if (defaultSpec != null && !specType.isInstance(defaultSpec)) {
            throw new IllegalArgumentException("defaultSpec must be an instance of " + specType.getName());
        }
        if (defaultSpec != null
                && (operation == KeyOperation.SYMMETRIC_IMPORT || operation == KeyOperation.ASYMMETRIC_PUBLIC_IMPORT
                        || operation == KeyOperation.ASYMMETRIC_PRIVATE_IMPORT)) {
            throw new IllegalArgumentException("import operations cannot declare a default specification");
        }
    }
}
