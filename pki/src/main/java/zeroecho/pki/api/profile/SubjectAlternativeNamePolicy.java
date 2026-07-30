/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Deny-by-default Subject Alternative Name policy.
 *
 * @param minimumTotal                minimum total SAN count
 * @param maximumTotal                maximum total SAN count
 * @param rules                       permitted SAN type rules
 * @param allowDnsWildcard            whether a complete leftmost DNS wildcard
 *                                    is permitted
 * @param allowedUriSchemes           exact lowercase allowed URI schemes
 * @param criticalWithNonemptySubject SAN criticality for a nonempty subject
 * @param requireServiceIdentity      whether DNS, IP, or URI identity is
 *                                    required
 * @param requireEmailIdentity        whether an RFC822 identity is required
 */
public record SubjectAlternativeNamePolicy(int minimumTotal, int maximumTotal, List<SubjectAlternativeNameRule> rules,
        boolean allowDnsWildcard, Set<String> allowedUriSchemes, boolean criticalWithNonemptySubject,
        boolean requireServiceIdentity, boolean requireEmailIdentity) {

    /** Maximum number of SAN entries. */
    public static final int HARD_MAXIMUM_COUNT = 64;

    /**
     * Validates and constructs the policy.
     */
    public SubjectAlternativeNamePolicy {
        if (minimumTotal < 0 || maximumTotal < minimumTotal || maximumTotal > HARD_MAXIMUM_COUNT) {
            throw new IllegalArgumentException("Invalid SAN total bounds");
        }
        if (rules == null || allowedUriSchemes == null) {
            throw new IllegalArgumentException("SAN policy collections must not be null");
        }
        rules = List.copyOf(rules);
        Set<SubjectAlternativeNameType> seen = java.util.EnumSet.noneOf(SubjectAlternativeNameType.class);
        int configuredMinimum = 0;
        int configuredMaximum = 0;
        boolean serviceIdentityPossible = false;
        boolean emailIdentityPossible = false;
        boolean uriPossible = false;
        for (SubjectAlternativeNameRule rule : rules) {
            if (rule == null || !seen.add(rule.type()) || rule.maximum() > maximumTotal) {
                throw new IllegalArgumentException("SAN type rules must be non-null, unique, and bounded");
            }
            configuredMinimum = Math.addExact(configuredMinimum, rule.minimum());
            configuredMaximum = Math.addExact(configuredMaximum, rule.maximum());
            serviceIdentityPossible |= rule.maximum() > 0 && (rule.type() == SubjectAlternativeNameType.DNS_NAME
                    || rule.type() == SubjectAlternativeNameType.IP_ADDRESS
                    || rule.type() == SubjectAlternativeNameType.URI);
            emailIdentityPossible |= rule.maximum() > 0 && rule.type() == SubjectAlternativeNameType.RFC822_NAME;
            uriPossible |= rule.maximum() > 0 && rule.type() == SubjectAlternativeNameType.URI;
        }
        Set<String> schemes = new java.util.LinkedHashSet<>();
        for (String scheme : allowedUriSchemes) {
            if (scheme == null || !scheme.matches("[A-Za-z][A-Za-z0-9+.-]*")) {
                throw new IllegalArgumentException("Invalid URI scheme");
            }
            String canonical = scheme.toLowerCase(Locale.ROOT);
            if (!schemes.add(canonical)) {
                throw new IllegalArgumentException("Duplicate URI scheme");
            }
        }
        allowedUriSchemes = Set.copyOf(schemes);
        if (configuredMinimum > maximumTotal || configuredMaximum < minimumTotal
                || requireServiceIdentity && !serviceIdentityPossible || requireEmailIdentity && !emailIdentityPossible
                || uriPossible != !allowedUriSchemes.isEmpty()) {
            throw new IllegalArgumentException("SAN policy requirements are not satisfiable");
        }
    }
}
