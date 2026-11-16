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
package zeroecho.pki.cli;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

import zeroecho.pki.application.PkiOperationValue;

/**
 * Immutable ordered plan with local structural checks and a normalized resolution base.
 *
 * <p>Construction copies the step list and makes the base path absolute without
 * reading the file system. It does not bind operations, validate argument schemas,
 * ensure unique step identifiers or resolve references; the parser/executor own
 * those checks. Retained immutable step values are not rebuilt.</p>
 *
 * @param version plan format version, currently one
 * @param failurePolicy sequential execution failure policy
 * @param steps nonempty ordered step list, copied into an unmodifiable list
 * @param baseDirectory base for relative inputs, normalized to an absolute path
 */
record PkiPlan(int version, FailurePolicy failurePolicy, List<Step> steps, Path baseDirectory) {

    /**
     * Schema version accepted by the plan parser and emitted by plan producers.
     */
    /* default */ static final int CURRENT_VERSION = 1;

    /**
     * Checks the supported version and snapshots required plan coordinates.
     *
     * @param version supported plan version
     * @param failurePolicy requested failure policy
     * @param steps nonempty ordered steps
     * @param baseDirectory relative-input resolution base
     * @throws IllegalArgumentException if the version is unsupported or steps are null/empty
     * @throws NullPointerException if the policy, base directory or a step is null
     */
    PkiPlan {
        if (version != CURRENT_VERSION || steps == null || steps.isEmpty()) {
            throw new IllegalArgumentException("Plan version or steps are invalid");
        }
        Objects.requireNonNull(failurePolicy, "failurePolicy");
        steps = List.copyOf(steps);
        baseDirectory = Objects.requireNonNull(baseDirectory, "baseDirectory").toAbsolutePath().normalize();
    }

    /**
     * Supported sequential failure policies.
     */
    /* default */ enum FailurePolicy {
        /**
         * Stops processing subsequent steps after an execution failure.
         */
        FAIL_FAST,
        /**
         * Continues independent steps while failed dependencies remain unavailable.
         */
        CONTINUE_INDEPENDENT
    }

    /**
     * Ordered step coordinates retained for later registry binding and reference resolution.
     *
     * <p>The constructor rejects null components only; blank identities, supported
     * operations and argument semantics must be checked by the parser/executor.</p>
     *
     * @param id step identity
     * @param operation semantic operation name
     * @param arguments immutable typed arguments, retained without copying
     */
    /* default */ record Step(String id, String operation, PkiOperationValue.ObjectValue arguments) {
        /**
         * Retains non-null step coordinates without binding or executing an operation.
         *
         * @param id step identity
         * @param operation semantic operation name
         * @param arguments immutable typed argument object
         * @throws IllegalArgumentException if any component is null
         */
        Step {
            if (id == null || operation == null || arguments == null) {
                throw new IllegalArgumentException("Plan step is incomplete");
            }
        }
    }
}
