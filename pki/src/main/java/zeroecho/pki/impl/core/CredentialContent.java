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
package zeroecho.pki.impl.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Optional;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.bc.BcX509SignedObjectValidator;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Internal individual-certificate adapter around store-owned content.
 */
final class CredentialContent {
    /* default */ static final int MAXIMUM_CERTIFICATE_BYTES = 1024 * 1024;

    private CredentialContent() {
    }

    /* default */ static DurableContentReference stage(PkiStore store, byte[] encoded) {
        if (encoded.length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(encoded);
            return sink.complete();
        } catch (IOException exception) {
            throw new PkiException("Credential staging failed: code=SPOOL_STORAGE_FAILED", exception);
        }
    }

    /* default */ static byte[] materializeForBc(PkiStore store, DurableContentReference reference) {
        long length = reference.length();
        if (reference.encoding() != Encoding.DER || length <= 0L || length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        byte[] result = new byte[(int) length];
        try {
            readExact(store, reference, result);
            return result;
        } catch (IOException exception) {
            java.util.Arrays.fill(result, (byte) 0);
            throw new PkiException("Credential content failed: code=CONTENT_IO_FAILED", exception);
        }
    }

    /* default */ static BcX509SignedObjectValidator.CertificateBindings validateCertificate(PkiStore store,
            DurableContentReference reference, X509AuthoritySnapshot authority,
            Optional<AlgorithmIdentity> expectedSignature) {
        long length = reference.length();
        if (reference.encoding() != Encoding.DER || length <= 0L || length > MAXIMUM_CERTIFICATE_BYTES) {
            throw new PkiException("Certificate exceeds artifact limit: code=CERTIFICATE_TOO_LARGE");
        }
        try (RepeatableContent content = store.stagedContent().openContent(reference)) {
            return new BcX509SignedObjectValidator(authority).validateCertificate(content, expectedSignature,
                    CancellationSignal.NONE);
        } catch (IOException | IllegalArgumentException exception) {
            throw new PkiException("Certificate validation failed: code=NON_CANONICAL_DER", exception);
        }
    }

    private static void readExact(PkiStore store, DurableContentReference reference, byte[] result)
            throws IOException {
        try (RepeatableContent content = store.stagedContent().openContent(reference);
                InputStream input = content.openStream()) {
            int offset = 0;
            while (offset != result.length) {
                int count = input.read(result, offset, result.length - offset);
                if (count < 0) {
                    throw new IOException("Credential content is truncated");
                }
                offset += count;
            }
            if (input.read() >= 0) {
                throw new IOException("Credential content length changed");
            }
        }
    }
}
