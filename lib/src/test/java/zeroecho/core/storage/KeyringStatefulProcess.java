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
import java.nio.file.Path;
import java.security.SecureRandom;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.sdk.util.BouncyCastleActivator;

/** Forked JVM fixture: no JUnit dependency and deliberately abrupt crash points. */
public final class KeyringStatefulProcess {
    public static void main(String[] args) throws Exception {
        BouncyCastleActivator.init();
        Path authorityPath = Path.of(args[1]);
        CrashOperations operations = new CrashOperations(args[0]);
        try (LocalStatefulSigningAuthority authority = LocalStatefulSigningAuthority.acquire(authorityPath, false, operations)) {
            if (args[0].equals("lock")) {
                System.out.println("READY");
                System.out.flush();
                System.in.read();
                return;
            }
            try (KeyringPassword password = new KeyringPassword("stateful-test".toCharArray());
                    KeyringStore store = KeyringStore.open(Path.of(args[2]), password, KeyringProtection.standard(),
                            new SecureRandom()::nextBytes, operations)) {
                store.statefulSigner("key", authority).sign(new ImmutableByteContent(new byte[] { 1, 2, 3, 4 }),
                        CancellationSignal.NONE, 4);
                throw new AssertionError("Expected crash was not reached");
            }
        }
    }

    private static final class CrashOperations implements KeyringFileOperations {
        private final String mode;
        private int authorities;
        private CrashOperations(String mode) { this.mode = mode; }
        @Override public Path createTemporary(Target target, Path parent, String prefix, String suffix) throws IOException {
            return NIO.createTemporary(target, parent, prefix, suffix);
        }
        @Override public void writeTemporary(Target target, Path temporary, byte[] image) throws IOException {
            NIO.writeTemporary(target, temporary, image);
        }
        @Override public void forceTemporary(Target target, Path temporary) throws IOException { NIO.forceTemporary(target, temporary); }
        @Override public void atomicReplace(Target target, Path temporary, Path destination) throws IOException {
            NIO.atomicReplace(target, temporary, destination);
        }
        @Override public void forceDirectory(Target target, Path parent) throws IOException {
            NIO.forceDirectory(target, parent);
            if (target == Target.STATEFUL_AUTHORITY) { authorities++; }
            if ((mode.equals("reserved") && target == Target.STATEFUL_AUTHORITY && authorities == 1)
                    || (mode.equals("image") && target == Target.MAIN_IMAGE)
                    || (mode.equals("ready") && target == Target.STATEFUL_AUTHORITY && authorities == 2)) {
                Runtime.getRuntime().halt(23);
            }
        }
        @Override public void deleteTemporary(Target target, Path temporary) throws IOException { NIO.deleteTemporary(target, temporary); }
    }
}
