/* *****************************************************************************
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
package zeroecho.pki.server.cmp;

/**
 * Signals a CMP protocol-level error that maps to an HTTP error response.
 *
 * <p>The {@link #httpStatus()} returns the HTTP status code to send to the client.
 * For CMP over HTTP (RFC 6712), protocol errors are typically surfaced as
 * {@code PKIMessage} with {@code PKIStatus} {@code rejection}; transport-layer
 * errors use the HTTP status code returned here.</p>
 *
 * @since 1.0
 */
public final class CmpProtocolException extends Exception {

    /** Serialization identity for this exception type. */
    private static final long serialVersionUID = 1L;

    /** HTTP response status selected by the protocol adapter. */
    private final int httpStatus;

    /**
     * Creates a CMP protocol exception.
     *
     * @param httpStatus HTTP status code (4xx or 5xx)
     * @param message    human-readable error description
     */
    public CmpProtocolException(int httpStatus, String message) {
        super(message);
        if (httpStatus < 400 || httpStatus > 599) {
            throw new IllegalArgumentException("httpStatus must be 4xx or 5xx: " + httpStatus);
        }
        this.httpStatus = httpStatus;
    }

    /**
     * Creates a CMP protocol exception with a cause.
     *
     * @param httpStatus HTTP status code
     * @param message    human-readable error description
     * @param cause      underlying cause
     */
    public CmpProtocolException(int httpStatus, String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    /**
     * Returns the HTTP status code.
     *
     * @return HTTP status code in the 400–599 range
     */
    public int httpStatus() {
        return httpStatus;
    }
}
