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
package zeroecho.pki.api.profile;

import java.util.List;
import java.util.Set;

/**
 * Deny-by-default subject distinguished-name policy.
 *
 * @param allowEmpty whether an empty subject is permitted
 * @param rules      ordered immutable supported RDN rules
 */
public record SubjectPolicy(boolean allowEmpty, List<SubjectRdnRule> rules) {

    /** Maximum number of subject RDNs. */
    public static final int HARD_MAXIMUM_RDN_COUNT = 32;

    /**
     * Validates and constructs the policy.
     */
    public SubjectPolicy {
        if (rules == null) {
            throw new IllegalArgumentException("Subject rules must not be null");
        }
        rules = List.copyOf(rules);
        Set<SubjectRdnType> seen = java.util.EnumSet.noneOf(SubjectRdnType.class);
        int configuredMaximum = 0;
        for (SubjectRdnRule rule : rules) {
            if (rule == null || !seen.add(rule.type())) {
                throw new IllegalArgumentException("Subject RDN rules must be non-null and unique");
            }
            configuredMaximum = Math.addExact(configuredMaximum, rule.maximumOccurrences());
        }
        if (configuredMaximum > HARD_MAXIMUM_RDN_COUNT) {
            throw new IllegalArgumentException("Configured subject RDN maximum exceeds the hard limit");
        }
    }
}
