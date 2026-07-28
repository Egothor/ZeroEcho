/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.guard;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Objects;

import zeroecho.sdk.util.Kdf;

/**
 * Defines the single KEM-recipient KEK derivation contract.
 */
final class KemKeyDerivation {
    private static final String INFO_PREFIX = "KDF:";

    private KemKeyDerivation() {
    }

    /**
     * Derives a KEK bound to the KEM algorithm identifier.
     *
     * @param sharedSecret KEM shared secret
     * @param salt HKDF salt
     * @param algorithmId canonical KEM algorithm identifier
     * @param outputBytes requested KEK size
     * @return newly allocated KEK bytes
     * @throws GeneralSecurityException if HKDF fails
     */
    /* default */ static byte[] derive(byte[] sharedSecret, byte[] salt, String algorithmId, int outputBytes)
            throws GeneralSecurityException {
        Objects.requireNonNull(algorithmId, "algorithmId must not be null");
        byte[] info = (INFO_PREFIX + algorithmId).getBytes(StandardCharsets.US_ASCII);
        return Kdf.hkdfSha256(sharedSecret, salt, info, outputBytes);
    }
}
