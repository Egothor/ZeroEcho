/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.api.profile;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Immutable occurrence and ownership rule for one supported subject RDN type.
 *
 * @param type                 exact supported RDN type
 * @param minimumOccurrences   minimum number of occurrences
 * @param maximumOccurrences   maximum number of occurrences
 * @param maximumUtf8Bytes     maximum encoded value length, at most 256 bytes
 * @param fixedValue           optional profile-fixed value
 * @param requesterSupplied    whether the requester may supply the value
 */
public record SubjectRdnRule(SubjectRdnType type, int minimumOccurrences, int maximumOccurrences,
        int maximumUtf8Bytes, Optional<String> fixedValue, boolean requesterSupplied) {

    /** Maximum hard value size. */
    public static final int HARD_MAXIMUM_UTF8_BYTES = 256;

    /**
     * Validates and constructs a rule.
     */
    public SubjectRdnRule {
        if (type == null || fixedValue == null) {
            throw new IllegalArgumentException("Subject RDN rule values must not be null");
        }
        if (minimumOccurrences < 0 || maximumOccurrences < minimumOccurrences) {
            throw new IllegalArgumentException("Invalid subject RDN occurrence bounds");
        }
        if (maximumUtf8Bytes < 1 || maximumUtf8Bytes > HARD_MAXIMUM_UTF8_BYTES) {
            throw new IllegalArgumentException("Invalid subject RDN value bound");
        }
        if (fixedValue.isPresent()) {
            String value = canonicalValue(type, fixedValue.orElseThrow());
            if (value.getBytes(StandardCharsets.UTF_8).length > maximumUtf8Bytes) {
                throw new IllegalArgumentException("Fixed subject RDN value is too large");
            }
            if (requesterSupplied) {
                throw new IllegalArgumentException("A fixed subject RDN cannot be requester supplied");
            }
            if (minimumOccurrences != 1 || maximumOccurrences != 1) {
                throw new IllegalArgumentException("A fixed subject RDN must occur exactly once");
            }
            fixedValue = Optional.of(value);
        } else if (!requesterSupplied && maximumOccurrences != 0) {
            throw new IllegalArgumentException("A non-requester RDN requires a fixed value");
        }
    }

    /**
     * Applies the type-specific canonical form and validation.
     *
     * @param type  RDN type
     * @param value value to validate
     * @return canonical value
     */
    public static String canonicalValue(SubjectRdnType type, String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Subject RDN value must not be empty");
        }
        if (type == SubjectRdnType.COUNTRY_NAME) {
            if (value.length() != 2 || !isAsciiLetter(value.charAt(0)) || !isAsciiLetter(value.charAt(1))) {
                throw new IllegalArgumentException("Country name must contain two ASCII letters");
            }
            return value.toUpperCase(java.util.Locale.ROOT);
        }
        return value;
    }

    private static boolean isAsciiLetter(char value) {
        return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z';
    }
}
