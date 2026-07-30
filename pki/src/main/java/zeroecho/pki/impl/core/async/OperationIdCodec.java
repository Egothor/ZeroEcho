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
package zeroecho.pki.impl.core.async;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.Principal;

/**
 * Utility for constructing canonical PKI operation identifiers for asynchronous
 * orchestration.
 *
 * <p>
 * This codec is intentionally internal to the PKI implementation layer. It
 * derives stable operation identifiers from the tuple
 * {@code (owner, clientOpId)} so that asynchronous workflows can be re-attached
 * deterministically after restart and stored safely in persistence layers
 * without escaping ambiguities.
 * </p>
 *
 * <p>
 * The canonical identifier model intentionally separates:
 * </p>
 * <ul>
 * <li><b>canonical base identifiers</b>, which are stable persistence keys and
 * are used by backend lookup and workflow state records,</li>
 * <li><b>display identifiers</b>, which extend the canonical base identifier
 * with a human-readable suffix after {@code '#'} for operator-facing
 * readability.</li>
 * </ul>
 *
 * <h2>Identifier form</h2>
 * <p>
 * The canonical base identifier has the form:
 * </p>
 *
 * <pre>
 * op:v1:sha256:&lt;hex(sha256(owner.type + "\n" + owner.name))&gt;:&lt;hex(sha256(clientOpId.value))&gt;
 * </pre>
 *
 * <p>
 * The use of a versioned prefix and fixed-length SHA-256 digests makes the
 * identifier suitable for durable storage, equality comparison, and
 * deterministic re-derivation without exposing the original client identifier
 * or owner fields directly in the persistence key.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>The canonical base form intentionally avoids embedding raw owner or
 * client identifier values in the persisted identifier.</li>
 * <li>The display suffix is not authoritative and must not be used for security
 * decisions, ownership checks, or persistence lookup.</li>
 * <li>Backend logic must always operate on the canonical base identifier and
 * ignore any display suffix.</li>
 * </ul>
 */
public final class OperationIdCodec {

    private static final String PREFIX = "op:v1:sha256:";

    private OperationIdCodec() {
        // utility
    }

    /**
     * Computes the canonical base operation identifier for the supplied owner and
     * client-provided operation identifier.
     *
     * <p>
     * The returned identifier never contains a display suffix after {@code '#'}. It
     * is intended to be used as the stable persistence key for workflow state,
     * durable bus status tracking, and result lookup.
     * </p>
     *
     * @param clientOpId client-chosen operation identifier; must not be
     *                   {@code null}
     * @param owner      operation owner; must not be {@code null}
     * @return canonical base operation identifier suitable for persistence and
     *         deterministic re-attach
     * @throws NullPointerException  if {@code clientOpId} or {@code owner} is
     *                               {@code null}
     * @throws IllegalStateException if SHA-256 is unexpectedly unavailable in the
     *                               runtime
     */
    public static PkiId toCanonicalBase(PkiId clientOpId, Principal owner) {
        Objects.requireNonNull(clientOpId, "clientOpId");
        Objects.requireNonNull(owner, "owner");

        String ownerToken = owner.type() + "\n" + owner.name();
        String ownerHex = sha256Hex(ownerToken.getBytes(StandardCharsets.UTF_8));
        String clientHex = sha256Hex(clientOpId.value().getBytes(StandardCharsets.UTF_8));
        return new PkiId(PREFIX + ownerHex + ":" + clientHex);
    }

    /**
     * Creates a display-oriented operation identifier by appending a readable
     * suffix after {@code '#'} to an already canonical base identifier.
     *
     * <p>
     * The appended suffix is intended only for operator readability in logs, UI,
     * and troubleshooting tools. It is not parsed or interpreted by the backend
     * orchestration logic.
     * </p>
     *
     * <p>
     * The current implementation derives the readable suffix from the owner in the
     * form {@code o=&lt;type&gt;:&lt;name&gt;} and truncates it when it exceeds
     * {@code displaySuffixMaxLen}.
     * </p>
     *
     * @param canonicalBase       canonical base identifier produced by
     *                            {@link #toCanonicalBase(PkiId, Principal)}; must
     *                            not be {@code null}
     * @param owner               owner used to derive the readable suffix; must not
     *                            be {@code null}
     * @param displaySuffixMaxLen positive maximum number of characters allowed
     *                            after {@code '#'}
     * @return display-oriented operation identifier containing the canonical base
     *         form plus a readable suffix
     * @throws NullPointerException     if {@code canonicalBase} or {@code owner} is
     *                                  {@code null}
     * @throws IllegalArgumentException if {@code displaySuffixMaxLen} is zero or
     *                                  negative
     */
    public static PkiId toDisplay(PkiId canonicalBase, Principal owner, int displaySuffixMaxLen) {
        Objects.requireNonNull(canonicalBase, "canonicalBase");
        Objects.requireNonNull(owner, "owner");
        if (displaySuffixMaxLen <= 0) {
            throw new IllegalArgumentException("displaySuffixMaxLen must be positive");
        }

        String base = canonicalBase.value();
        String readable = owner.type() + ":" + owner.name();
        String suffix = "o=" + readable;
        if (suffix.length() > displaySuffixMaxLen) {
            suffix = suffix.substring(0, displaySuffixMaxLen);
        }

        return new PkiId(base + "#" + suffix);
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(data));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }
}
