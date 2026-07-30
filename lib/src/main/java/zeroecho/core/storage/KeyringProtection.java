/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

/**
 * Operational limits applied while opening an encrypted software keyring.
 *
 * @param operationalIterationMaximum maximum accepted PBKDF2 iteration count;
 *                                    it may restrict but never exceed the
 *                                    absolute decoded maximum
 */
public record KeyringProtection(int operationalIterationMaximum) {
    /** Iterations used when a new keyring is created. */
    public static final int CREATION_ITERATIONS = 600_000;
    /** Largest operationally accepted PBKDF2 iteration count. */
    public static final int MAX_OPERATIONAL_ITERATIONS = 1_000_000;
    /** Absolute safety ceiling for decoded PBKDF2 iteration counts. */
    public static final int MAX_DECODED_ITERATIONS = 10_000_000;

    /**
     * Validates the operational limit.
     *
     * @throws IllegalArgumentException if the limit is below the creation setting
     *                                  or above the absolute operational maximum
     */
    public KeyringProtection {
        if (operationalIterationMaximum < CREATION_ITERATIONS
                || operationalIterationMaximum > MAX_OPERATIONAL_ITERATIONS) {
            throw new IllegalArgumentException("operationalIterationMaximum must be in [600000,1000000]");
        }
    }

    /**
     * Returns the standard protection policy.
     *
     * @return policy accepting up to one million iterations
     */
    public static KeyringProtection standard() {
        return new KeyringProtection(MAX_OPERATIONAL_ITERATIONS);
    }
}
