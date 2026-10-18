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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.module.Configuration;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.nio.file.Path;
import java.sql.Driver;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class H2ModuleCompatibilityTest {
    @TempDir
    Path directory;

    @Test
    void embeddedDriverRetainsClasspathAndPlainNamedLayerCompatibility() throws Exception {
        System.out.println("embeddedDriverRetainsClasspathAndPlainNamedLayerCompatibility");
        Path artifact = Path.of(org.h2.Driver.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        ModuleFinder finder = ModuleFinder.of(artifact);
        ModuleDescriptor descriptor = finder.find("com.h2database").orElseThrow().descriptor();
        assertFalse(descriptor.isAutomatic());
        assertTrue(descriptor.isOpen());
        assertEquals(descriptor.packages(), descriptor.exports().stream()
                .map(ModuleDescriptor.Exports::source).collect(Collectors.toSet()));
        assertEquals(Set.of("java.base", "java.compiler", "java.desktop", "java.instrument",
                "java.management", "java.naming", "java.scripting", "java.sql", "jdk.net"),
                descriptor.requires().stream().map(ModuleDescriptor.Requires::name).collect(Collectors.toSet()));
        assertEquals(List.of("org.h2.Driver"), descriptor.provides().stream()
                .filter(service -> service.service().equals("java.sql.Driver"))
                .findFirst().orElseThrow().providers());
        verifyEmbeddedFile(new org.h2.Driver(), "classpath");

        Configuration configuration = Configuration.resolve(finder,
                List.of(ModuleLayer.boot().configuration()), ModuleFinder.of(), Set.of("com.h2database"));
        ModuleLayer layer = ModuleLayer.defineModulesWithOneLoader(configuration,
                List.of(ModuleLayer.boot()), ClassLoader.getPlatformClassLoader()).layer();
        Class<?> provider = Class.forName("org.h2.Driver", true, layer.findLoader("com.h2database"));
        assertSame(layer, provider.getModule().getLayer());
        try {
            verifyEmbeddedFile(Driver.class.cast(provider.getDeclaredConstructor().newInstance()), "named-layer");
        } finally {
            provider.getMethod("unload").invoke(null);
        }
        System.out.println("...ok");
    }

    private void verifyEmbeddedFile(Driver driver, String name) throws Exception {
        String url = "jdbc:h2:file:" + directory.resolve(name)
                + ";AUTO_SERVER=FALSE;DB_CLOSE_ON_EXIT=FALSE;TRACE_LEVEL_FILE=0";
        try (var connection = driver.connect(url, new Properties());
                var statement = connection.createStatement()) {
            statement.execute("CREATE TABLE probe (value_id INT PRIMARY KEY)");
            assertEquals(1, statement.executeUpdate("INSERT INTO probe VALUES (42)"));
        }
        try (var connection = driver.connect(url, new Properties());
                var statement = connection.createStatement();
                var result = statement.executeQuery("SELECT value_id FROM probe")) {
            assertTrue(result.next());
            assertEquals(42, result.getInt(1));
            assertFalse(result.next());
        }
    }
}
