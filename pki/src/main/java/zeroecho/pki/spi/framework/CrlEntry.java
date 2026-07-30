/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.spi.framework;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Objects;

import zeroecho.pki.api.revocation.RevocationReason;

/**
 * Immutable structured input for one certificate-revocation-list entry.
 *
 * <p>
 * The serial number retains the full positive X.509 integer domain. The
 * transition time is authoritative runtime state and is not replaced by CRL
 * generation time. {@link RevocationReason#REMOVE_FROM_CRL} is excluded because
 * removal is represented by omission from the current CRL.
 * </p>
 *
 * @param serialNumber   positive certificate serial number
 * @param transitionTime authoritative revocation or hold transition time
 * @param reason         explicit CRL reason
 */
public record CrlEntry(BigInteger serialNumber, Instant transitionTime, RevocationReason reason) {

    /**
     * Validates one structured CRL entry.
     *
     * @throws IllegalArgumentException if the serial is non-positive, a value is
     *                                  missing, or the reason is
     *                                  {@code REMOVE_FROM_CRL}
     */
    public CrlEntry {
        Objects.requireNonNull(serialNumber, "serialNumber");
        Objects.requireNonNull(transitionTime, "transitionTime");
        Objects.requireNonNull(reason, "reason");
        if (serialNumber.signum() <= 0) {
            throw new IllegalArgumentException("serialNumber must be positive");
        }
        if (reason == RevocationReason.REMOVE_FROM_CRL) {
            throw new IllegalArgumentException("REMOVE_FROM_CRL is not an active CRL entry");
        }
    }
}
