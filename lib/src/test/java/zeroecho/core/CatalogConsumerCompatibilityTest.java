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
package zeroecho.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import javax.tools.ToolProvider;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CatalogConsumerCompatibilityTest {
    @TempDir
    Path directory;

    @Test
    void classpathAndNamedModuleConsumersCompileAndDiscoverProviders() throws Exception {
        String dependencies = StreamPaths.of(CryptoAlgorithm.class, org.bouncycastle.jce.spec.ElGamalParameterSpec.class,
                org.bouncycastle.cert.X509CertificateHolder.class, org.bouncycastle.asn1.cms.ContentInfo.class,
                conflux.CtxInterface.class);
        Path source = directory.resolve("consumer/Consumer.java");
        Files.createDirectories(source.getParent());
        Files.writeString(source, """
                package consumer;
                import java.util.List;
                import java.util.Map;
                import java.util.ServiceLoader;
                import zeroecho.core.*;
                import zeroecho.core.alg.elgamal.ElgamalParamSpec;
                import zeroecho.core.alg.rsa.RsaKeyGenSpec;
                import zeroecho.core.storage.KeyringStore;
                import zeroecho.core.storage.LocalStatefulSigningAuthority;
                import zeroecho.core.storage.StatefulSigner;
                public final class Consumer {
                    public static byte[] alternative(zeroecho.pkix.cert.CertificateBuilder builder) {
                        return builder.buildAlternativeSignatureTbs();
                    }
                    public static boolean verifyAlternative(java.security.cert.X509Certificate certificate,
                            java.security.PublicKey issuer) {
                        return zeroecho.pkix.Pkix.verifyAlternativeSignature(certificate, issuer);
                    }
                    public static StatefulSigner durable(KeyringStore store, LocalStatefulSigningAuthority authority)
                            throws Exception {
                        store.generateStatefulKey("new-key", "LMS", authority);
                        return store.statefulSigner("new-key", authority);
                    }
                    public static void main(String[] args) {
                        TemplateParameter p = new TemplateParameter("bits", "Bits", Integer.class, "Size");
                        if (!(p instanceof TemplateParameter(String n, String l, Class<?> t, String d))) {
                            throw new AssertionError();
                        }
                        ParameterSetDescriptor.Template<RsaKeyGenSpec> old = new ParameterSetDescriptor.Template<>(
                            "rsa", "RSA", SecurityLevel.classical(112), List.of(p), values -> RsaKeyGenSpec.rsa2048());
                        if (!(old instanceof ParameterSetDescriptor.Template(
                            String id, String label, SecurityLevel level, List parameters, java.util.function.Function factory))) {
                            throw new AssertionError();
                        }
                        if (old.constraints().size() != 1 || old.factory().apply(Map.of()).keySize() != 2048) {
                            throw new AssertionError();
                        }
                        org.bouncycastle.jce.spec.ElGamalParameterSpec group = ElgamalParamSpec.ffdhe2048().parameters();
                        if (group.getP().bitLength() != 2048) throw new AssertionError();
                        if (ServiceLoader.load(CryptoAlgorithm.class).findFirst().isEmpty()) throw new AssertionError();
                        if (!CryptoAlgorithms.available().contains("RSA")) throw new AssertionError();
                    }
                }
                """);
        Path plain = Files.createDirectories(directory.resolve("plain"));
        ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics,
                "-classpath", dependencies, "-d", plain.toString(), source.toString()), diagnostics.toString());
        Path module = directory.resolve("module-info.java");
        Files.writeString(module, "module consumer { requires zeroecho.lib; uses zeroecho.core.CryptoAlgorithm; }");
        Path modular = Files.createDirectories(directory.resolve("modular"));
        diagnostics.reset();
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, diagnostics, diagnostics,
                "--module-path", dependencies, "-d", modular.toString(), module.toString(), source.toString()),
                diagnostics.toString());
        Path log = directory.resolve("consumer.log");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "--module-path", modular + File.pathSeparator + dependencies, "-m", "consumer/consumer.Consumer")
                .redirectErrorStream(true).redirectOutput(log.toFile()).start();
        assertTrue(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS), "Consumer timed out");
        assertEquals(0, process.exitValue(), Files.readString(log, StandardCharsets.UTF_8));
    }

    private static final class StreamPaths {
        private static String of(Class<?>... types) throws Exception {
            java.util.ArrayList<String> paths = new java.util.ArrayList<>();
            for (Class<?> type : types) {
                paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
            }
            return paths.stream().distinct().collect(Collectors.joining(File.pathSeparator));
        }
    }
}
