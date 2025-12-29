/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.spi.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Path;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;

/**
 * JUnit 5 tests for {@link PkiBootstrap}.
 *
 * <p>
 * The tests validate provider selection and configuration conventions based on
 * {@link java.util.ServiceLoader} providers and {@link System#getProperties()}.
 * </p>
 *
 * <p>
 * Security note: tests must not print configuration values that might be
 * sensitive. Here we only print safe information (provider ids, class names,
 * and key presence).
 * </p>
 */
public final class PkiBootstrapTest {

    @TempDir
    private Path tempDir;

    private Properties savedProperties;

    @BeforeEach
    public void beforeEach() {
        System.out.println("beforeEach");
        this.savedProperties = (Properties) System.getProperties().clone();

        clearPrefix("zeroecho.pki.store.");
        clearPrefix("zeroecho.pki.audit.");

        System.clearProperty("zeroecho.pki.store");
        System.clearProperty("zeroecho.pki.audit");

        System.out.println("...tempDir=" + this.tempDir);
        System.out.println("...ok");
    }

    @AfterEach
    public void afterEach() {
        System.out.println("afterEach");
        System.setProperties(this.savedProperties);
        System.out.println("...ok");
    }

    @Test
    public void openStore_fs_usesTempRoot() {
        System.out.println("openStore_fs_usesTempRoot");

        System.setProperty("zeroecho.pki.store", "fs");
        System.setProperty("zeroecho.pki.store.root", this.tempDir.resolve("store").toString());

        PkiStore store = PkiBootstrap.openStore();
        assertNotNull(store);

        String storeClassName = store.getClass().getName();
        System.out.println("...storeClass=" + storeClassName);

        // Do not rely on implementation type at compile time; compare by name.
        assertEquals("zeroecho.pki.impl.fs.FilesystemPkiStore", storeClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_defaultIsStdout() {
        System.out.println("openAudit_defaultIsStdout");

        // Per bootstrap: if no -Dzeroecho.pki.audit is set, default is "stdout".
        // This must work even if multiple audit providers exist.
        // :contentReference[oaicite:1]{index=1}
        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.StdoutAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_file_usesTempRoot() {
        System.out.println("openAudit_file_usesTempRoot");

        System.setProperty("zeroecho.pki.audit", "file");
        System.setProperty("zeroecho.pki.audit.root", this.tempDir.resolve("audit").toString());

        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.FileAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_memory_acceptsSize() {
        System.out.println("openAudit_memory_acceptsSize");

        System.setProperty("zeroecho.pki.audit", "memory");
        System.setProperty("zeroecho.pki.audit.size", "123");

        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.InMemoryAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    private static void clearPrefix(String prefix) {
        Properties props = System.getProperties();
        for (Object keyObj : props.keySet().toArray()) {
            if (keyObj instanceof String) {
                String key = (String) keyObj;
                if (key.startsWith(prefix)) {
                    System.clearProperty(key);
                }
            }
        }
    }
}
