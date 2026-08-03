/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.api.publication;

/** Safe closed classifications for publication-operation failures. */
public enum PublicationFailure {
    /** The publisher authoritatively classified the attempt as retryable. */
    EXTERNAL_RETRYABLE,
    /** The publisher authoritatively classified the attempt as terminal. */
    EXTERNAL_TERMINAL,
    /** The publisher call did not establish whether an external effect occurred. */
    EXTERNAL_OUTCOME_UNKNOWN,
    /** The exact immutable source content could not be validated. */
    CONTENT_INVALID,
    /** Durable persistence of a returned result could not be established. */
    RESULT_PERSISTENCE_UNKNOWN
}
