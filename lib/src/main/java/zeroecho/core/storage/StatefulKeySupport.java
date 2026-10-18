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
package zeroecho.core.storage;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.alg.lms.LmsAlgorithm;
import zeroecho.core.alg.lms.LmsKeyGenSpec;
import zeroecho.core.alg.lms.LmsSignatureContext;
import zeroecho.core.alg.xmss.XmssAlgorithm;
import zeroecho.core.alg.xmss.XmssKeyGenSpec;
import zeroecho.core.alg.xmss.XmssSignatureContext;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/** Provider mechanics only; the keyring owns every durable transition. */
final class StatefulKeySupport {
    private StatefulKeySupport() { }

    /* default */ static void destroy(PrivateKey key) {
        if (key != null) {
            try {
                key.destroy();
            } catch (DestroyFailedException unsupported) { // NOPMD EmptyCatchBlock - Best-effort destruction must not replace the signing/persistence result.
                // BC implementations may retain private state until collection.
                // Never replace a signing/persistence failure with cleanup failure.
            }
        }
    }

    /* default */ static KeyPair generate(CryptoAlgorithm algorithm) throws GeneralSecurityException {
        if (!algorithm.requiresStatefulSigning()) {
            throw new GeneralSecurityException("Stateful signing capability required");
        }
        if (algorithm instanceof LmsAlgorithm) {
            return algorithm.asymmetricKeyPairGenerator(LmsKeyGenSpec.class).generateKeyPair(LmsKeyGenSpec.DEFAULT);
        }
        if (algorithm instanceof XmssAlgorithm) {
            return algorithm.asymmetricKeyPairGenerator(XmssKeyGenSpec.class).generateKeyPair(XmssKeyGenSpec.DEFAULT);
        }
        throw new GeneralSecurityException("Unsupported stateful signing capability");
    }

    /* default */ static long remaining(PrivateKey key) throws GeneralSecurityException {
        if (key instanceof LMSPrivateKey lms) {
            return lms.getUsagesRemaining();
        }
        if (key instanceof XMSSPrivateKey xmss) {
            return xmss.getUsagesRemaining();
        }
        throw new GeneralSecurityException("Unsupported stateful private key");
    }

    /* default */ static long index(PrivateKey key, long capacity) throws GeneralSecurityException {
        if (remaining(key) == 0) {
            return capacity;
        }
        if (key instanceof LMSPrivateKey lms) {
            return lms.getIndex();
        }
        if (key instanceof XMSSPrivateKey xmss) {
            return xmss.getIndex();
        }
        throw new GeneralSecurityException("Unsupported stateful private key");
    }

    /* default */ static PrivateKey reserve(PrivateKey key) throws GeneralSecurityException {
        if (key instanceof LMSPrivateKey lms) {
            return lms.extractKeyShard(1);
        }
        if (key instanceof XMSSPrivateKey xmss) {
            return xmss.extractKeyShard(1);
        }
        throw new GeneralSecurityException("Unsupported stateful private key");
    }

    /* default */ static int signatureLength(CryptoAlgorithm algorithm, PublicKey key) throws GeneralSecurityException, IOException {
        try (SignatureContext verifier = algorithm instanceof LmsAlgorithm
                ? new LmsSignatureContext(algorithm, key) : new XmssSignatureContext(algorithm, key)) {
            return verifier.tagLength();
        }
    }

    /* default */ static byte[] sign(PrivateKey shard, RepeatableContent content, CancellationSignal cancellation,
            int maximumMessageBytes, int expectedLength) throws IOException, GeneralSecurityException {
        Signature signer = Signature.getInstance(shard instanceof LMSPrivateKey ? "LMS" : "XMSS", "BCPQC");
        signer.initSign(shard);
        byte[] buffer = new byte[8192];
        long count = 0;
        try (InputStream input = content.openStream()) {
            while (true) {
                cancellation.throwIfCancelled();
                int read = input.read(buffer);
                if (read == -1) {
                    break;
                }
                if (read <= 0 || count + read > maximumMessageBytes) {
                    throw new IOException("Stateful signing content limit or progress failure");
                }
                count += read;
                signer.update(buffer, 0, read);
            }
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
        cancellation.throwIfCancelled();
        byte[] signature = signer.sign();
        if (remaining(shard) != 0 || signature.length != expectedLength) {
            Arrays.fill(signature, (byte) 0);
            throw new GeneralSecurityException("Stateful signature postcondition failed");
        }
        return signature;
    }
}
