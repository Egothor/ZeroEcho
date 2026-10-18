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
package zeroecho.pki.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;

/** Bounded regular-file input used by the CLI trust boundary. */
final class PkiCliFiles {

    private static final int BUFFER_BYTES = 8_192;

    private PkiCliFiles() {
    }

    /* default */ static byte[] readRegularFile(Path path, int maximumBytes) throws IOException {
        Path exact = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        if (maximumBytes <= 0) {
            throw new IllegalArgumentException("maximumBytes must be positive");
        }
        int readLimit = Math.addExact(maximumBytes, 1);
        BasicFileAttributes attributes = Files.readAttributes(exact, BasicFileAttributes.class,
                LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile() || attributes.isSymbolicLink() || attributes.size() < 0L
                || attributes.size() > maximumBytes) {
            throw new IOException("CLI input file is invalid");
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.min(attributes.size(), BUFFER_BYTES));
        byte[] buffer = new byte[BUFFER_BYTES];
        int total = 0;
        try (SeekableByteChannel channel = Files.newByteChannel(exact, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS);
                InputStream input = Channels.newInputStream(channel)) {
            while (true) {
                int remaining = readLimit - total;
                int count = input.read(buffer, 0, Math.min(buffer.length, remaining));
                if (count < 0) {
                    break;
                }
                if (count == 0) {
                    continue;
                }
                output.write(buffer, 0, count);
                total = Math.addExact(total, count);
                if (total > maximumBytes) {
                    throw new IOException("CLI input file is too large");
                }
            }
        }
        return output.toByteArray();
    }
}
