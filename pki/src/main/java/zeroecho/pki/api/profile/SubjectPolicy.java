/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
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
