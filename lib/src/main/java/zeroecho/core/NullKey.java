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
package zeroecho.core;

import java.security.Key;
import java.util.Objects;

/**
 * Sentinel {@link Key} representing the intentional absence of cryptographic
 * key material.
 *
 * <p>
 * {@code NullKey} satisfies APIs that require a {@code Key} reference even when
 * no secret exists (e.g., unkeyed digests or placeholder capabilities). It
 * contains no sensitive data and is safe to log and share.
 * </p>
 *
 * <h2>Intended uses</h2>
 * <ul>
 * <li>Unkeyed operations such as {@code DIGEST} roles where keys are
 * semantically undefined but a {@code Key} parameter is part of a common
 * interface.</li>
 * <li>Testing and scaffolding where a non-null {@code Key} is required to
 * exercise type and flow without provisioning secrets.</li>
 * <li>Metadata publication for capabilities that don’t depend on key
 * material.</li>
 * </ul>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li>Contains no secret; {@link #getEncoded()} returns an empty byte
 * array.</li>
 * <li>Algorithm and format are the literal string {@code "NONE"}.</li>
 * <li>All instances are equal by type; prefer the {@link #INSTANCE}
 * singleton.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Immutable; the singleton instance is safe to reuse
 * across threads.
 *
 * @since 1.0
 */
public final class NullKey implements Key {
    private static final long serialVersionUID = -3423524955655163523L;
    /**
     * Singleton instance for all uses where a {@link Key} is required but no key
     * exists.
     *
     * <p>
     * Use this constant rather than constructing new instances. Equality for
     * {@code NullKey} is defined by type, so all instances compare equal; the
     * singleton avoids unnecessary allocations and clarifies intent.
     * </p>
     */
    public static final NullKey INSTANCE = new NullKey();

    private NullKey() {
    }

    /**
     * Returns the algorithm identifier for this sentinel key.
     *
     * <p>
     * The value is the literal string {@code "NONE"} to signal that no real
     * cryptographic algorithm is associated with this key.
     * </p>
     *
     * @return the string {@code "NONE"}
     */
    @Override
    public String getAlgorithm() {
        return "NONE";
    }

    /**
     * Returns the primary encoding format for this sentinel key.
     *
     * <p>
     * The value is the literal string {@code "NONE"}; {@link #getEncoded()} returns
     * an empty byte array.
     * </p>
     *
     * @return the string {@code "NONE"}
     */
    @Override
    public String getFormat() {
        return "NONE";
    }

    /**
     * Returns the key in its primary encoding.
     *
     * <p>
     * For {@code NullKey}, this is an empty byte array because no material exists.
     * Callers MAY rely on this to avoid special-casing unkeyed flows.
     * </p>
     *
     * @return a new zero-length byte array
     */
    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }

    /**
     * Compares this object to another for equality.
     *
     * <p>
     * All {@code NullKey} instances are considered equal regardless of identity;
     * equality is defined by <em>type</em> rather than state. Prefer comparing
     * against {@link #INSTANCE} when intent matters, but this method ensures
     * generic collections and caches behave as expected.
     * </p>
     *
     * @param obj the reference object with which to compare
     * @return {@code true} if {@code obj} is a {@code NullKey}; {@code false}
     *         otherwise
     */
    @Override
    public boolean equals(Object obj) {
        return obj instanceof NullKey;
    }

    /**
     * Returns a stable hash code consistent with {@link #equals(Object)}.
     *
     * <p>
     * Derived from a fixed class-based token so that all {@code NullKey} instances
     * hash identically, matching the type-based equality semantics.
     * </p>
     *
     * @return a stable hash code value
     */
    @Override
    public int hashCode() {
        return Objects.hash("NullKey");
    }

    /**
     * Returns a diagnostic string for logs and debugging.
     *
     * <p>
     * The returned value is the literal {@code "NullKey"}. It contains no secrets
     * and is safe for inclusion in logs and error messages.
     * </p>
     *
     * @return the string {@code "NullKey"}
     */
    @Override
    public String toString() {
        return "NullKey";
    }
}
