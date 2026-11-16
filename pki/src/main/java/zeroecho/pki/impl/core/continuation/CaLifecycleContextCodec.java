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
package zeroecho.pki.impl.core.continuation;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.spi.store.DomainContinuationStore;

/**
 * Bounded canonical version-one lifecycle context; never consults mutable state.
 */
public final class CaLifecycleContextCodec {
    private static final String DOMAIN = "CA_LIFECYCLE_CONTEXT_V1";
    private static final int MAXIMUM_TEXT = 131_072;
    private CaLifecycleContextCodec() { }

    /**
     * Encodes an immutable expected-head context for a captured command field.
     * @param context complete public predecessor evidence
     * @return canonical unpadded Base64url encoding
     * @throws IllegalArgumentException if encoded evidence exceeds the finite field bound
     */
    public static String encode(CaLifecycleContext context) {
        var head = context.expectedHead();
        byte[] bytes = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA, DOMAIN,
                context.operation().name(), head.caId().value(), Long.toString(head.epoch()), head.issuerId().value(),
                head.pathId().value(), head.bindingCommitment(), context.originalCredentialId().value(),
                context.originalCertificateSha256(), context.transitionId().map(PkiId::value).orElse("")).command().bytes();
        String text = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        if (text.length() > MAXIMUM_TEXT) throw invalid();
        return text;
    }

    /**
     * Decodes exact versioned fields, rejecting noncanonical or unknown input.
     * @param text bounded canonical encoding
     * @return complete checked expected-head context
     * @throws IllegalArgumentException if encoding, epoch, version or fields are invalid
     */
    public static CaLifecycleContext decode(String text) {
        if (text == null || text.length() > MAXIMUM_TEXT) throw invalid();
        byte[] bytes = Base64.getUrlDecoder().decode(text);
        if (!Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(text)) throw invalid();
        var fields = DomainCommandEncoding.decode(new EncodedObject(Encoding.BINARY, bytes));
        if (!fields.operation().equals(DOMAIN)) throw invalid();
        fields.requireFields(9);
        long epoch = Long.parseLong(fields.field(2));
        if (!Long.toString(epoch).equals(fields.field(2))) throw invalid();
        var head = new CaHeadSnapshot(1, new PkiId(fields.field(1)), epoch, new PkiId(fields.field(3)),
                new PkiId(fields.field(4)), fields.field(5));
        return new CaLifecycleContext(1, CaLifecycleContext.Operation.valueOf(fields.field(0)), head,
                new PkiId(fields.field(6)), fields.field(7), fields.field(8).isEmpty()
                        ? Optional.empty() : Optional.of(new PkiId(fields.field(8))));
    }

    /**
     * Commits to all context fields with the codec's explicit domain separator.
     * @param context exact expected-head evidence
     * @return lowercase canonical SHA-256
     * @throws IllegalStateException if the runtime does not provide SHA-256
     */
    public static String commitment(CaLifecycleContext context) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(Base64.getUrlDecoder().decode(encode(context))));
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid CA lifecycle context encoding"); }
}
