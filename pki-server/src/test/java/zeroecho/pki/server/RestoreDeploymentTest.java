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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RestoreDeploymentTest {
    @TempDir Path directory;

    @Test void legacyVolumeIsRejectedBeforeAnyLauncherOrBootstrap() throws Exception {
        Path script = Path.of("deploy/pki-server/entrypoint.sh").toAbsolutePath();
        if (!Files.exists(script)) script = Path.of("../deploy/pki-server/entrypoint.sh").toAbsolutePath();
        Path parent = directory.resolve("store-container");
        Files.createDirectory(parent);
        Files.writeString(parent.resolve("VERSION"), "v18");
        Path output = directory.resolve("entrypoint.log");
        ProcessBuilder builder = new ProcessBuilder("/bin/sh", script.toString());
        builder.environment().put("ZEROECHO_STORE_DIR", parent.resolve("store").toString());
        builder.environment().put("ZEROECHO_SERVER_HOME", directory.resolve("nonexistent-launcher").toString());
        Process process = builder.redirectErrorStream(true).redirectOutput(output.toFile()).start();
        assertTrue(process.waitFor(10, TimeUnit.SECONDS));
        assertEquals(1, process.exitValue());
        assertTrue(Files.readString(output).contains("legacy store volume requires offline layout migration"));
        assertFalse(Files.exists(parent.resolve("store")));
        assertEquals("v18", Files.readString(parent.resolve("VERSION")));
    }
}
