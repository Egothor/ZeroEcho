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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import zeroecho.pki.server.RealmId;

/**
 * Bounded read-only mutual-TLS authentication input, independent of operation
 * arguments.
 *
 * @param peerCertificates trusted JSSE peer chain, leaf first
 * @param protocol negotiated TLS protocol
 * @param cipherSuite negotiated cipher suite
 * @param requestId safe request correlation identity
 * @param realmId exact server realm
 */
public record PkiServerAuthenticationContext(List<X509Certificate> peerCertificates, String protocol,
        String cipherSuite, String requestId, RealmId realmId) {
    /** Validates and snapshots the finite authentication context. */
    public PkiServerAuthenticationContext {
        peerCertificates = List.copyOf(Objects.requireNonNull(peerCertificates, "peerCertificates"));
        if (peerCertificates.isEmpty() || peerCertificates.size() > 64) {
            throw new IllegalArgumentException("Peer certificate chain length is invalid");
        }
        if (protocol == null || protocol.isBlank() || protocol.length() > 64
                || cipherSuite == null || cipherSuite.isBlank() || cipherSuite.length() > 128) {
            throw new IllegalArgumentException("TLS session metadata is invalid");
        }
        if (requestId == null || !requestId.matches("[A-Za-z0-9_-]{16,128}")) {
            throw new IllegalArgumentException("Request correlation identity is invalid");
        }
        Objects.requireNonNull(realmId, "realmId");
    }
}
