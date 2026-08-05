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
package zeroecho.pki.server.spi;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Secret-confining external-account-binding verification SPI.
 * Implementations verify and consume nested EAB authority internally and never
 * return HMAC key material.
 */
@SuppressWarnings("PMD.ControlStatementBraces")
public interface AcmeExternalAccountBindingProvider {
    /** @return stable explicitly configured provider identity */
    String id();

    /** Verifies and, when configured, consumes one exact nested EAB JWS. */
    Binding verify(Request request, ProviderConfig configuration);

    /** Exact bounded EAB verification request. */
    record Request(String directoryId, PkiId authorityId, String profileId,
            String accountKeyThumbprint, byte[] nestedJws, Instant now) {
        /** Defensively snapshots non-secret protocol material. */
        public Request {
            if (directoryId == null || directoryId.isBlank()) throw new IllegalArgumentException("Invalid directory identity");
            Objects.requireNonNull(authorityId, "authorityId");
            if (profileId == null || profileId.isBlank()) throw new IllegalArgumentException("Invalid profile identity");
            if (accountKeyThumbprint == null || !accountKeyThumbprint.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid account commitment");
            nestedJws = Objects.requireNonNull(nestedJws, "nestedJws").clone();
            if (nestedJws.length == 0 || nestedJws.length > 65_536) throw new IllegalArgumentException("Invalid EAB document bound");
            Objects.requireNonNull(now, "now");
        }
        @Override public byte[] nestedJws() { return nestedJws.clone(); }
    }

    /** Finite EAB policy output without secret material. */
    record Binding(String keyId, String policyCommitment, Set<String> dnsNamespaces,
            Instant expiresAt, boolean consumed) {
        /** Validates complete EAB policy binding. */
        public Binding {
            if (keyId == null || keyId.isBlank() || keyId.length() > 128) throw new IllegalArgumentException("Invalid EAB key identity");
            if (policyCommitment == null || !policyCommitment.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Invalid EAB policy commitment");
            dnsNamespaces = Set.copyOf(Objects.requireNonNull(dnsNamespaces, "dnsNamespaces"));
            if (dnsNamespaces.isEmpty() || dnsNamespaces.size() > 64) throw new IllegalArgumentException("Invalid EAB namespace policy");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }
}
