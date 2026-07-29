/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Provides the authoritative process-wide cryptographic random source.
 */
public final class RandomSupport {
    private static final Logger LOG = Logger.getLogger(RandomSupport.class.getName());
    private static final SecureRandom RANDOM = createRandom();

    private RandomSupport() {
    }

    /**
     * Returns the shared thread-safe random source.
     *
     * @return shared secure random generator
     */
    public static SecureRandom getRandom() {
        return RANDOM;
    }

    /**
     * Allocates and fills a random byte array.
     *
     * @param size required array length
     * @return random bytes
     */
    public static byte[] generateRandom(int size) {
        return generateRandom(new byte[size]);
    }

    /**
     * Fills the supplied array with random bytes.
     *
     * @param buffer destination array
     * @return {@code buffer}
     */
    public static byte[] generateRandom(byte[] buffer) {
        RANDOM.nextBytes(buffer);
        return buffer;
    }

    /**
     * Returns a uniform value below the bound.
     *
     * @param bound exclusive positive upper bound
     * @return generated value
     */
    public static int nextInt(int bound) {
        return RANDOM.nextInt(bound);
    }

    private static SecureRandom createRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException exception) {
            LOG.log(Level.WARNING, "Strong SecureRandom unavailable; using the platform default");
            return new SecureRandom();
        }
    }
}
