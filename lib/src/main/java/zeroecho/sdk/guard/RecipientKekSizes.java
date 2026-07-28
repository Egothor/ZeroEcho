/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.sdk.guard;

/**
 * Defines the KEK sizes supported by recipient entries without an encoded size
 * discriminator.
 *
 * <p>The current recipient format permits AES-128 and AES-256 wrapping only.
 * Validation must occur before an entry is registered so every emitted entry
 * remains openable by the corresponding recipient opener.</p>
 *
 * @since 1.0
 */
public final class RecipientKekSizes {
    /** AES-128 key size in bytes. */
    public static final int AES_128_BYTES = 16;
    /** AES-256 key size in bytes. */
    public static final int AES_256_BYTES = 32;

    private RecipientKekSizes() {
    }

    /**
     * Validates and returns a supported recipient KEK size.
     *
     * @param kekBytes requested KEK size in bytes
     * @return {@code kekBytes} when it is exactly 16 or 32
     * @throws IllegalArgumentException if the size is not exactly 16 or 32
     */
    public static int requireSupported(int kekBytes) {
        if (kekBytes != AES_128_BYTES && kekBytes != AES_256_BYTES) {
            throw new IllegalArgumentException("Recipient KEK size must be exactly 16 or 32 bytes: " + kekBytes);
        }
        return kekBytes;
    }
}
