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
package zeroecho.core.alg.xmss;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an XMSS private key in PKCS#8 format.
 *
 * <p>
 * XMSS private keys are <strong>stateful</strong> with a finite signing
 * capacity. The PKCS#8 encoding captures the current leaf-index state.
 * Callers must persist the updated key state after every signing operation to
 * prevent key-state reuse. See {@link XmssSignatureContext} for lifecycle
 * guidance.
 * </p>
 *
 * <p>
 * This class implements {@link Destroyable} to allow zeroing of key material
 * when the spec is no longer needed.
 * </p>
 *
 * @since 1.0
 */
public final class XmssPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new spec from PKCS#8 DER encoded XMSS private key bytes.
     *
     * @param pkcs8Der PKCS#8 DER bytes
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public XmssPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8 encoded key bytes.
     *
     * @return PKCS#8 DER bytes
     * @throws IllegalStateException if this spec has been destroyed
     */
    public byte[] pkcs8() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return pkcs8.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes this spec to a {@link PairSeq}.
     *
     * @param spec the spec to serialize
     * @return serialized representation
     */
    public static PairSeq marshal(XmssPrivateKeySpec spec) {
        return PairSeq.of("type", "XmssPrivateKeySpec", PKCS8_B64, spec.encodedKey());
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation
     * @return reconstructed spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static XmssPrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("XmssPrivateKeySpec: missing pkcs8.b64");
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return new XmssPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(pkcs8, (byte) 0);
                destroyed = true;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public boolean isDestroyed() {
        lifecycleLock.lock();
        try {
            return destroyed;
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public String toString() {
        return "XmssPrivateKeySpec[len=" + pkcs8.length + "]";
    }

    private String encodedKey() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return Base64.getEncoder().withoutPadding().encodeToString(pkcs8);
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void ensureActive() {
        if (destroyed) {
            throw new IllegalStateException("XMSS private key specification has been destroyed");
        }
    }
}
