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
package zeroecho.ext.integrations.covert.jpeg;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SlotModuleCompatibilityTest {
    @TempDir
    Path directory;

    @Test
    void namedConsumerCanReadAndRegisterPublicTagInfoWithoutDirectImagingDependency() throws Exception {
        System.out.println("namedConsumerCanReadAndRegisterPublicTagInfoWithoutDirectImagingDependency");
        Class<?>[] artifacts = { Slot.class, zeroecho.core.CryptoAlgorithm.class, conflux.CtxInterface.class,
                org.bouncycastle.jce.spec.ElGamalParameterSpec.class,
                org.bouncycastle.cert.X509CertificateHolder.class, org.bouncycastle.asn1.cms.ContentInfo.class,
                org.apache.commons.imaging.formats.tiff.taginfos.TagInfo.class,
                org.apache.commons.io.IOUtils.class, org.apache.commons.lang3.StringUtils.class };
        String dependencies = Arrays.stream(artifacts).map(type -> {
            try {
                return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
            } catch (java.net.URISyntaxException failure) {
                throw new IllegalStateException(failure);
            }
        }).distinct().collect(Collectors.joining(File.pathSeparator));
        Path module = directory.resolve("module-info.java");
        Files.writeString(module, "module consumer { requires zeroecho.ext; }");
        Path source = directory.resolve("consumer/Consumer.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package consumer;
                import org.apache.commons.imaging.formats.tiff.taginfos.TagInfo;
                import zeroecho.ext.integrations.covert.jpeg.Slot;
                public final class Consumer {
                    private Consumer() { }
                    public static void main(String[] args) {
                        TagInfo tag = Slot.parse("usercomment").tagInfo;
                        Slot registered = Slot.register("module-consumer", Slot.SlotGroup.EXIF, tag, 128);
                        if (registered.tagInfo != tag) throw new AssertionError();
                    }
                }
                """);
        Path output = Files.createDirectory(directory.resolve("classes"));
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics,
                "-Xlint:all", "-Werror", "--module-path", dependencies, "-d", output.toString(),
                module.toString(), source.toString()), diagnostics.toString());
        Path log = directory.resolve("consumer.log");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--module-path", output + File.pathSeparator + dependencies,
                "-m", "consumer/consumer.Consumer").redirectErrorStream(true).redirectOutput(log.toFile()).start();
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Named consumer timed out");
        assertEquals(0, process.exitValue(), Files.readString(log));
        System.out.println("...ok");
    }
}
