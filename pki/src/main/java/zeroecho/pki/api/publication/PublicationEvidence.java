/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *******************************************************************************/
package zeroecho.pki.api.publication;

/** Identifies how an exact attempt outcome was established. */
public enum PublicationEvidence {
    /** The publisher returned a definitive result from direct dispatch. */
    DIRECT_RESPONSE,
    /** The publisher resolved the existing attempt through reconciliation. */
    RECONCILIATION_RESPONSE
}
