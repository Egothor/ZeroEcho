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
package zeroecho.pki.cli;

/**
 * Transport-level failure that occurs before a meaningful operation envelope can
 * be exchanged (TLS handshake, authentication, connection, or an undecodable
 * response).
 *
 * <p>It carries a stable non-sensitive {@code category}/{@code code} pair and the
 * process exit code the CLI must return, and never a provider exception graph.</p>
 */
final class PkiRemoteTransportException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int exitCode;
    private final String category;
    private final String code;

    /**
     * Creates a transport failure.
     *
     * @param exitCode stable process exit code to return
     * @param category stable safe failure category label
     * @param code stable safe failure code
     */
    /* default */ PkiRemoteTransportException(int exitCode, String category, String code) {
        super(category + ':' + code);
        this.exitCode = exitCode;
        this.category = category;
        this.code = code;
    }

    /** @return stable process exit code */
    /* default */ int exitCode() {
        return exitCode;
    }

    /** @return stable safe failure category label */
    /* default */ String category() {
        return category;
    }

    /** @return stable safe failure code */
    /* default */ String code() {
        return code;
    }
}
