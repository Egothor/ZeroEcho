/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.spi.publish;

/** Definitive outcomes a publisher may safely return for one exact attempt. */
public enum PublicationOutcome {
    /** The exact attempt completed successfully. */
    SUCCESS,
    /** No unsafe duplicate effect exists and an explicit retry is permitted. */
    RETRYABLE_FAILURE,
    /** The exact attempt definitively failed and must not be retried. */
    TERMINAL_FAILURE
}
