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
package zeroecho.core.alg.common.sig;

import java.security.Key;
import java.util.Locale;

import org.bouncycastle.pqc.jcajce.interfaces.LMSKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSMTKey;

import zeroecho.core.err.UnsupportedRoleException;
import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Fail-closed containment for stateful signing until durable leaf reservation is
 * available. Verification and key import are unaffected. This class is stateless
 * and thread-safe; it never encodes a key or invokes a cryptographic provider.
 */
public final class StatefulSigningGuard {
    private StatefulSigningGuard() { }

    /**
     * Identifies LMS/HSS and XMSS/XMSSMT names and their supported OID families.
     * Canonical identities are checked by family, without interpreting their
     * namespace or parameters as provider aliases. Work and auxiliary memory are
     * O(n) in the identifier length.
     *
     * @param algorithm algorithm name or OID; {@code null} means unspecified
     * @return whether the identifier is unavailable for signing
     */
    public static boolean isStateful(String algorithm) {
        if (algorithm == null) { return false; }
        if (algorithm.startsWith("zealg:2:")) {
            String family = canonicalFamily(algorithm);
            return "lms".equals(family) || "hss".equals(family) || "xmss".equals(family)
                    || "xmssmt".equals(family) || "xmss-mt".equals(family);
        }
        String name = algorithm.toUpperCase(Locale.ROOT);
        if (name.startsWith("OID.")) { name = name.substring(4); }
        int slash = name.indexOf('/');
        if (slash >= 0 && name.substring(slash + 1).startsWith("XMSS")) {
            name = name.substring(slash + 1);
        }
        return "LMS".equals(name) || "HSS".equals(name) || "HSS/LMS".equals(name)
                || "XMSS".equals(name) || name.startsWith("XMSS-")
                || "XMSSMT".equals(name) || name.startsWith("XMSSMT-")
                || name.endsWith("WITHXMSS") || name.endsWith("WITHXMSSMT")
                || name.endsWith("WITHXMSS-SHA256") || name.endsWith("WITHXMSS-SHA512")
                || name.endsWith("WITHXMSS-SHAKE128") || name.endsWith("WITHXMSS-SHAKE256")
                || name.endsWith("WITHXMSSMT-SHA256") || name.endsWith("WITHXMSSMT-SHA512")
                || name.endsWith("WITHXMSSMT-SHAKE128") || name.endsWith("WITHXMSSMT-SHAKE256")
                || "1.2.840.113549.1.9.16.3.17".equals(name)
                || "0.4.0.127.0.15.1.1.13.0".equals(name) || "0.4.0.127.0.15.1.1.14.0".equals(name)
                || "1.3.6.1.5.5.7.6.34".equals(name) || "1.3.6.1.5.5.7.6.35".equals(name)
                || "1.3.6.1.4.1.22554.2.2".equals(name) || name.startsWith("1.3.6.1.4.1.22554.2.2.")
                || "1.3.6.1.4.1.22554.2.3".equals(name) || name.startsWith("1.3.6.1.4.1.22554.2.3.");
    }

    // Inspect only kind/namespace/family, independently of extension parameter codecs.
    // Never decode parameters, whose recursive representation is irrelevant here.
    private static String canonicalFamily(String identity) {
        int offset = "zealg:2:".length();
        String[] fields = new String[3];
        for (int index = 0; index < fields.length; index++) {
            int separator = identity.indexOf(':', offset);
            if (separator <= offset || separator - offset > 9) { return null; }
            int length = 0;
            for (int digitIndex = offset; digitIndex < separator; digitIndex++) {
                char digit = identity.charAt(digitIndex);
                if (digit < '0' || digit > '9') { return null; }
                length = length * 10 + digit - '0';
            }
            offset = separator + 1;
            if (length > identity.length() - offset) { return null; }
            fields[index] = identity.substring(offset, offset + length);
            offset += length;
        }
        try {
            AlgorithmIdentity.Kind.valueOf(fields[0].toUpperCase(Locale.ROOT));
            return new AlgorithmIdentity.Family(fields[1], fields[2]).name();
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }

    /**
     * Checks both declared algorithm and actual key identity without using the key.
     *
     * @param algorithm declared name or OID, or {@code null}
     * @param key actual key, or {@code null} when only metadata is available
     * @throws UnsupportedRoleException if stateful signing is requested
     */
    public static void requireStateless(String algorithm, Key key) {
        if (isStateful(algorithm) || key instanceof LMSKey || key instanceof XMSSKey
                || key instanceof XMSSMTKey || (key != null && isStateful(key.getAlgorithm()))) {
            throw new UnsupportedRoleException("LMS/XMSS signing is unavailable until durable leaf reservation is supported");
        }
    }
}
