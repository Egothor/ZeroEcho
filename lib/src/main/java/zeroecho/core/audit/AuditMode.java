/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the conditions in the project LICENSE are met.
 ******************************************************************************/
package zeroecho.core.audit;

/**
 * Defines the session-owned automatic auditing strategy.
 *
 * <p>
 * Audit listener failures are best-effort diagnostics and never change the
 * outcome of a cryptographic operation.
 * </p>
 *
 * @since 1.0
 */
public enum AuditMode {
    /**
     * Emits one context-creation event and returns the original context.
     */
    OFF,
    /**
     * Emits one context-creation event and returns an operation-auditing wrapper.
     */
    WRAP,
    /**
     * Emits no automatic audit events and returns the original context.
     */
    MANUAL
}
