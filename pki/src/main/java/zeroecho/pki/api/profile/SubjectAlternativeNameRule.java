/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

/**
 * Occurrence and IP-family rule for one supported SAN type.
 *
 * @param type      SAN type
 * @param minimum   minimum occurrences
 * @param maximum   maximum occurrences
 * @param allowIpv4 whether IPv4 is allowed for
 *                  {@link SubjectAlternativeNameType#IP_ADDRESS}
 * @param allowIpv6 whether IPv6 is allowed for
 *                  {@link SubjectAlternativeNameType#IP_ADDRESS}
 */
public record SubjectAlternativeNameRule(SubjectAlternativeNameType type, int minimum, int maximum, boolean allowIpv4,
        boolean allowIpv6) {

    /**
     * Validates and constructs the rule.
     */
    public SubjectAlternativeNameRule {
        if (type == null || minimum < 0 || maximum < minimum
                || maximum > SubjectAlternativeNamePolicy.HARD_MAXIMUM_COUNT) {
            throw new IllegalArgumentException("Invalid SAN type rule");
        }
        if (type == SubjectAlternativeNameType.IP_ADDRESS) {
            if (maximum > 0 && !allowIpv4 && !allowIpv6) {
                throw new IllegalArgumentException("An IP SAN rule must allow at least one address family");
            }
        } else if (allowIpv4 || allowIpv6) {
            throw new IllegalArgumentException("IP family flags apply only to IP SAN rules");
        }
    }
}
