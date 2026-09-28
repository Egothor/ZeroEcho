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

package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.PkiStore;

final class FilesystemPkiStoreProviderTest {
    @Test
    void defaultsAndCanonicalValuesFlowThroughSharedAllocationOptions(@TempDir Path directory) throws Exception {
        FilesystemPkiStoreProvider provider = new FilesystemPkiStoreProvider();
        assertTrue(provider.supportedKeys().contains("initialCrlNumber"));
        ProviderConfig defaults = new ProviderConfig("fs", Map.of("root", directory.resolve("default").toString()));
        provider.validateConfig(defaults);
        assertEquals(BigInteger.ONE, FilesystemPkiStoreProvider.options(defaults).initialCrlNumber());
        for (String value : List.of("0", "1", "12345", BigInteger.ONE.shiftLeft(159).subtract(BigInteger.ONE).toString())) {
            ProviderConfig config = config(directory.resolve(value), value);
            provider.validateConfig(config);
            assertEquals(new BigInteger(value), FilesystemPkiStoreProvider.options(config).initialCrlNumber());
            try (PkiStore store = provider.allocate(config)) {
                assertInstanceOf(FilesystemPkiStore.class, store);
            }
        }
    }

    @Test
    void validationAndAllocationRejectNoncanonicalOrOutOfRangeBeforeCreatingStore(@TempDir Path directory) {
        FilesystemPkiStoreProvider provider = new FilesystemPkiStoreProvider();
        List<String> invalid = List.of("", "-1", "+1", "00", "01", " 1", "1 ", "1\n", "1.0", "1e2",
                "١", "9".repeat(49), "1".repeat(10000), BigInteger.ONE.shiftLeft(159).toString());
        for (int index = 0; index < invalid.size(); index++) {
            Path root = directory.resolve("invalid-" + index);
            ProviderConfig config = config(root, invalid.get(index));
            assertThrows(IllegalArgumentException.class, () -> provider.validateConfig(config));
            assertThrows(IllegalArgumentException.class, () -> provider.allocate(config));
            assertFalse(Files.exists(root));
        }
    }

    private static ProviderConfig config(Path root, String value) {
        return new ProviderConfig("fs", Map.of("root", root.toString(), "initialCrlNumber", value));
    }
}
