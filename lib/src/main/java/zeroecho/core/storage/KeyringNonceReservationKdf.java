/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.core.storage;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Fixed-purpose RFC 5869 derivation for nonce-reservation authentication.
 */
final class KeyringNonceReservationKdf {
    private static final int MASTER_KEY_BYTES = 32;
    private static final int STORE_ID_BYTES = 16;
    private static final int OUTPUT_BYTES = 32;
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String DOMAIN_LABEL = "zeroecho:keyring:nonce-reservation-mac:v1";

    private KeyringNonceReservationKdf() {
    }

    /**
     * Derives the store-specific nonce-reservation MAC key.
     *
     * @param masterKey borrowed 256-bit store master key
     * @param storeId   borrowed canonical 128-bit binary store UUID
     * @return newly owned 256-bit derived key
     * @throws GeneralSecurityException if HMAC-SHA-256 is unavailable
     */
    /* default */ static byte[] derive(byte[] masterKey, byte[] storeId) throws GeneralSecurityException {
        if (masterKey == null || masterKey.length != MASTER_KEY_BYTES || storeId == null
                || storeId.length != STORE_ID_BYTES) {
            throw new IllegalArgumentException("Invalid keyring derivation input");
        }
        byte[] salt = storeId.clone();
        byte[] info = DOMAIN_LABEL.getBytes(StandardCharsets.US_ASCII);
        byte[] prk = null;
        byte[] expandInput = null;
        try {
            prk = hmac(salt, masterKey);
            expandInput = Arrays.copyOf(info, info.length + 1);
            expandInput[expandInput.length - 1] = 1;
            byte[] output = hmac(prk, expandInput);
            if (output.length != OUTPUT_BYTES) {
                Arrays.fill(output, (byte) 0);
                throw new GeneralSecurityException("KEYRING_DERIVATION_FAILED");
            }
            return output;
        } finally {
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(info, (byte) 0);
            wipe(prk);
            wipe(expandInput);
        }
    }

    private static byte[] hmac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(input);
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
