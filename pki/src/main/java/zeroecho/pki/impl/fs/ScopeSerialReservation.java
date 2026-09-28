/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgement:
 *    This product includes software developed by the Egothor project.
 *
 * 4. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

package zeroecho.pki.impl.fs;

import java.math.BigInteger;
import java.util.Objects;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.impl.core.CrlScope;

/**
 * Permanent scope-wide serial reservation. Cancellation, failure, expiry,
 * retention purge and generation retirement never recycle its serial. The
 * owner must match exactly on replay; a digest lookup is not structural proof.
 * This immutable record performs no store operation.
 */
record ScopeSerialReservation(CrlScope scope, BigInteger serial, IssuanceOwner issuanceOwner) {
    ScopeSerialReservation {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(serial, "serial");
        Objects.requireNonNull(issuanceOwner, "issuanceOwner");
        if (serial.signum() <= 0 || serial.bitLength() > 159) {
            throw new IllegalArgumentException("Serial must be positive and fit 20 DER content octets");
        }
    }

    /** Closed reservation authority; neither an arbitrary label nor an authorization token. */
    /* default */ sealed interface IssuanceOwner permits SigningOwner, ImportedCertificateOwner { }

    /** Exact operation and canonical command SHA-256 commitment. */
    /* default */ record SigningOwner(PkiId operationId, String commandCommitment) implements IssuanceOwner {
        SigningOwner {
            CrlScopeMetadataCodec.requireId(operationId);
            CrlScopeMetadataCodec.requireHash(commandCommitment);
        }
    }

    /** Exact SHA-256 commitment to an imported certificate's canonical DER. */
    /* default */ record ImportedCertificateOwner(String certificateCommitment) implements IssuanceOwner {
        ImportedCertificateOwner {
            CrlScopeMetadataCodec.requireHash(certificateCommitment);
        }
    }
}
