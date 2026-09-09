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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import java.security.MessageDigest;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;

/** Performs bounded durable content reads, publication staging, and failed-publication cleanup. */
final class DomainContentAccess {
    private static final int MAXIMUM_CONTENT_BYTES = 1_048_576;
    private final PkiStore store;

    /* default */ DomainContentAccess(PkiStore store) {
        this.store = Objects.requireNonNull(store, "store");
    }

    /* default */ byte[] materialize(DurableContentReference reference, String invalidCode) {
        if (reference.length() <= 0L || reference.length() > MAXIMUM_CONTENT_BYTES) {
            throw new DomainContinuationPublisher.PostconditionFailure(invalidCode);
        }
        byte[] bytes = new byte[Math.toIntExact(reference.length())];
        boolean complete;
        try (RepeatableContent content = store.stagedContent().openContent(reference);
                InputStream input = content.openStream()) {
            complete = readExact(input, bytes);
        } catch (IOException failure) {
            Arrays.fill(bytes, (byte) 0);
            throw new DomainContinuationPublisher.PostconditionFailure(invalidCode, failure);
        }
        if (!complete) {
            Arrays.fill(bytes, (byte) 0);
            throw new DomainContinuationPublisher.PostconditionFailure(invalidCode);
        }
        return bytes;
    }

    /* default */ DurableContentReference persist(byte[] bytes) {
        try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER,
                DurableContentReference.Lifecycle.PERSISTED); OutputStream output = sink.outputStream()) {
            output.write(bytes);
            return sink.complete();
        } catch (IOException failure) {
            throw new PkiException("Domain result staging failed: code=SPOOL_STORAGE_FAILED", failure);
        }
    }

    /* default */ void requireExact(DurableContentReference reference, byte[] expected,
            String invalidCode) {
        if (reference.length() != expected.length
                || !reference.sha256().equals(DomainContinuationPublisher.sha256(expected))) {
            throw new DomainContinuationPublisher.PostconditionFailure(invalidCode);
        }
        byte[] actual = materialize(reference, invalidCode);
        try {
            if (!MessageDigest.isEqual(actual, expected)) {
                throw new DomainContinuationPublisher.PostconditionFailure(invalidCode);
            }
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    /* default */ void releaseUnlessPublished(DurableContentReference content, boolean published) {
        if (published) {
            return;
        }
        try {
            store.stagedContent().retireUnownedContent(content);
        } catch (IOException failure) {
            throw new PkiException("Domain result cleanup failed: code=SPOOL_STORAGE_FAILED", failure);
        }
    }

    private static boolean readExact(InputStream input, byte[] target) throws IOException {
        int offset = 0;
        while (offset < target.length) {
            int count = input.read(target, offset, target.length - offset);
            if (count < 0) {
                return false;
            }
            if (count > 0) {
                offset += count;
            }
        }
        return input.read() == -1;
    }
}
