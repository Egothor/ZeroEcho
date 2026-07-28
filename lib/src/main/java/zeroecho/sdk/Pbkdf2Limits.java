/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.sdk;

/**
 * Explicit PBKDF2 work-factor limits for trusted configuration and decoded data.
 *
 * @param operationalMaximum largest iteration count accepted from trusted local
 *                           configuration
 * @param absoluteDecodedMaximum hard safety ceiling for untrusted decoded data
 * @since 1.0
 */
public record Pbkdf2Limits(int operationalMaximum, int absoluteDecodedMaximum) {
    /** Mandatory minimum PBKDF2 iteration count. */
    public static final int MINIMUM = 10_000;

    /**
     * Validates {@code minimum <= operationalMaximum <= absoluteDecodedMaximum}.
     *
     * @throws IllegalArgumentException if the limits violate the ordering
     */
    public Pbkdf2Limits {
        if (operationalMaximum < MINIMUM) {
            throw new IllegalArgumentException("operationalMaximum must be at least " + MINIMUM);
        }
        if (absoluteDecodedMaximum < operationalMaximum) {
            throw new IllegalArgumentException("absoluteDecodedMaximum must be at least operationalMaximum");
        }
    }

    /**
     * Validates trusted local configuration.
     *
     * @param iterations requested iteration count
     * @throws IllegalArgumentException if outside the operational range
     */
    public void validateTrusted(int iterations) {
        if (iterations < MINIMUM || iterations > operationalMaximum) {
            throw new IllegalArgumentException("PBKDF2 iterations must be in range " + MINIMUM + ".."
                    + operationalMaximum + ": " + iterations);
        }
    }

    /**
     * Validates an untrusted decoded iteration count before KDF execution.
     *
     * @param iterations decoded iteration count
     * @throws IllegalArgumentException if outside the absolute safety range
     */
    public void validateDecoded(int iterations) {
        if (iterations < MINIMUM || iterations > absoluteDecodedMaximum) {
            throw new IllegalArgumentException("Decoded PBKDF2 iterations must be in range " + MINIMUM + ".."
                    + absoluteDecodedMaximum + ": " + iterations);
        }
        if (iterations > operationalMaximum) {
            throw new IllegalArgumentException("Decoded PBKDF2 iterations exceed the session policy maximum "
                    + operationalMaximum + ": " + iterations);
        }
    }
}
