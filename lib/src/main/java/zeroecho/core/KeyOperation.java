/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core;

/**
 * Identifies one exact key-material operation exposed by an algorithm.
 *
 * @since 1.0
 */
public enum KeyOperation {
    /** Generates a symmetric key. */
    SYMMETRIC_GENERATE,
    /** Imports a symmetric key. */
    SYMMETRIC_IMPORT,
    /** Generates an asymmetric key pair. */
    ASYMMETRIC_KEY_PAIR_GENERATE,
    /** Imports an asymmetric public key. */
    ASYMMETRIC_PUBLIC_IMPORT,
    /** Imports an asymmetric private key. */
    ASYMMETRIC_PRIVATE_IMPORT
}
