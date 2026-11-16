/*
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
 */
package zeroecho.pki.application;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.testkit.IntermediateCreationFixture;
import zeroecho.pki.testkit.IntermediateIssuanceFixture;

/**
 * Provider-owned certificate representations preserve native bytes and expose PEM only for X.509.
 */
class CredentialExportsTest {
    /**
     * Exports bounded integrity checked native and framework owned PEM.
     *
     * @param root isolated temporary store root supplied by JUnit
     * @throws Exception if fixture setup, execution, or cleanup fails
     */
    @Test void exportsBoundedIntegrityCheckedNativeAndFrameworkOwnedPem(@TempDir Path root) throws Exception { exercise(root); }
    /**
     * Requires a fixture invariant without relying on enabled JVM assertions.
     *
     * @param condition condition that must hold for the fixture assertion to succeed
     * @param message diagnostic attached to a failed fixture assertion
     * @throws AssertionError if the required condition is false
     */
    static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    /**
     * Checked test operation used to assert input rejection without mutation.
     */
    interface Action {
        /**
         * Executes the checked test action supplied by an input-validation case.
         *
         * @throws Exception if fixture construction, execution, or cleanup fails
         */
        void run() throws Exception; }
    /**
     * Requires the supplied invalid-input action to throw a runtime exception.
     *
     * @param action checked operation that must reject the supplied invalid input
     * @throws Exception if fixture construction, execution, or cleanup fails
     * @throws AssertionError if the action returns normally instead of rejecting input
     */
    static void rejected(Action action) throws Exception {
        try { action.run(); throw new AssertionError("Unsupported export accepted"); }
        catch (IOException | RuntimeException expected) { }
    }
    /**
     * Runs the complete actual-store scenario and its persisted-state assertions in the supplied root.
     *
     * @param root filesystem root retaining the test store and keyring artifacts
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    static void exercise(Path root) throws Exception {
        try (var store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), IntermediateCreationFixture.CLOCK)) {
            var fixture = new IntermediateIssuanceFixture(); fixture.initialize(store);
            var ca = store.getCa(IntermediateCreationFixture.CA).orElseThrow();
            var credentialId = store.getIssuerGeneration(ca.currentIssuanceIssuerId()).orElseThrow().credentialId();
            var original = store.getCredential(credentialId).orElseThrow();
            var framework = new BcX509CredentialFramework(fixture.base.signing, fixture.base.verifier);
            var repository = new DefaultPkiRepository(store, () -> { }, List.of(framework));
            var formats = repository.credentialRepresentations(credentialId);
            check(formats.stream().map(value -> value.id()).toList().equals(List.of("original", "pem")), "Wrong X.509 representations");
            check(formats.getFirst().label().equals("DER") && formats.get(1).fileExtension().equals("pem"), "Framework metadata lost");
            byte[] nativeBytes;
            try (var legacy = repository.openCredential(credentialId); var stream = legacy.openStream()) { nativeBytes = stream.readAllBytes(); }
            try (var raw = repository.openCredential(credentialId, "original", CancellationSignal.NONE); var stream = raw.openStream()) {
                check(Arrays.equals(nativeBytes, stream.readAllBytes()), "Original representation altered bytes");
                check(raw.length() == nativeBytes.length && raw.sha256().equals(original.content().sha256()), "Raw length/hash changed");
            }
            var pem = repository.openCredential(credentialId, "pem", CancellationSignal.NONE);
            byte[] pemBytes;
            try (pem; var stream = pem.openStream()) {
                pemBytes = stream.readAllBytes();
                check(pemBytes.length == pem.length(), "PEM output length differs");
                check(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(pemBytes)).equals(pem.sha256()), "PEM digest differs");
                var parsed = CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(pemBytes));
                check(Arrays.equals(nativeBytes, parsed.getEncoded()), "PEM changed the certificate");
                check(new String(pemBytes, java.nio.charset.StandardCharsets.US_ASCII).startsWith("-----BEGIN CERTIFICATE-----\n"), "Not certificate PEM");
            }
            rejected(pem::openStream);
            rejected(() -> repository.openCredential(credentialId, "unknown", CancellationSignal.NONE));
            rejected(() -> repository.openCredential(credentialId, "pem", () -> true));
            rejected(() -> repository.credentialRepresentations(new PkiId("missing")));
            var opaque = new PkiId("opaque:credential");
            store.putCredential(new Credential(opaque, new FormatId("opaque-format"), original.issuerRef(), original.subjectRef(), original.validity(), "opaque17",
                    original.publicKeyId(), original.profileBinding(), original.status(), original.content(), original.attributes()));
            check(repository.credentialRepresentations(opaque).stream().map(value -> value.id()).toList().equals(List.of("original")), "Opaque format gained PEM");
            check(repository.credentialRepresentations(opaque).getFirst().label().equals("Original"), "Opaque format guessed DER label");
            try (var raw = repository.openCredential(opaque, "original", CancellationSignal.NONE); var stream = raw.openStream()) {
                check(Arrays.equals(nativeBytes, stream.readAllBytes()), "Opaque native bytes changed");
            }
            rejected(() -> repository.openCredential(opaque, "pem", CancellationSignal.NONE));
            rejected(() -> repository.openCredential(opaque)); // Existing legacy X.509-only contract is preserved.
            var closes = new java.util.concurrent.atomic.AtomicInteger();
            byte[] corrupt = nativeBytes.clone(); corrupt[0] ^= 1;
            rejected(() -> faultRepository(store, original, framework, corrupt, false, closes)
                    .openCredential(credentialId, "original", CancellationSignal.NONE));
            check(closes.get() == 1, "Integrity failure leaked its native lease");
            closes.set(0);
            rejected(() -> faultRepository(store, original, framework, new byte[]{5,0}, true, closes)
                    .openCredential(credentialId, "pem", CancellationSignal.NONE));
            check(closes.get() == 1, "Malformed format content leaked its native lease");
            byte[] maximum = new byte[1024 * 1024]; java.util.Arrays.fill(maximum, (byte)0x5a);
            var exactBudgetId = new PkiId("opaque:maximum");
            var oversizedId = new PkiId("opaque:oversized");
            putOpaque(store, original, exactBudgetId, maximum);
            putOpaque(store, original, oversizedId, java.util.Arrays.copyOf(maximum, maximum.length + 1));
            try (var exact = repository.openCredential(exactBudgetId, "original", CancellationSignal.NONE)) {
                check(exact.length() == maximum.length, "Exact input budget was rejected");
            }
            rejected(() -> repository.openCredential(oversizedId, "original", CancellationSignal.NONE));
        }
        System.out.println("PASS framework-owned native/PEM certificate exports, certificate roundtrip/hash/length, close/cancel/unknown handling, generic opaque original bytes, legacy API preserved");
    }
    private static void putOpaque(FilesystemPkiStore store, Credential original, PkiId id, byte[] bytes) throws IOException {
        zeroecho.pki.api.content.DurableContentReference reference;
        try (var sink = store.stagedContent().beginContent(zeroecho.pki.api.Encoding.BINARY,
                zeroecho.pki.api.content.DurableContentReference.Lifecycle.PERSISTED)) {
            try (var output = sink.outputStream()) { output.write(bytes); }
            reference = sink.complete();
        }
        store.putCredential(new Credential(id, new FormatId("opaque-format"), original.issuerRef(), original.subjectRef(), original.validity(), id.value(),
                original.publicKeyId(), original.profileBinding(), original.status(), reference, original.attributes()));
    }

    private static DefaultPkiRepository faultRepository(FilesystemPkiStore store, Credential original,
            BcX509CredentialFramework framework, byte[] bytes, boolean coherentMetadata,
            java.util.concurrent.atomic.AtomicInteger closes) throws Exception {
        var reference = (zeroecho.pki.api.content.DurableContentReference) java.lang.reflect.Proxy.newProxyInstance(
                zeroecho.pki.api.content.DurableContentReference.class.getClassLoader(),
                new Class<?>[]{zeroecho.pki.api.content.DurableContentReference.class}, (proxy, method, values) -> {
                    if (coherentMetadata && method.getName().equals("length")) return (long)bytes.length;
                    if (coherentMetadata && method.getName().equals("sha256")) return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
                    try { return method.invoke(original.content(), values); }
                    catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
        var metadata = new Credential(original.credentialId(), original.formatId(), original.issuerRef(), original.subjectRef(), original.validity(), original.serialOrUniqueId(),
                original.publicKeyId(), original.profileBinding(), original.status(), reference, original.attributes());
        var content = new zeroecho.core.io.RepeatableContent() {
            @Override public java.io.InputStream openStream() { return new java.io.ByteArrayInputStream(bytes); }
            @Override public java.util.OptionalLong length() { return java.util.OptionalLong.of(bytes.length); }
            @Override public String contentId() { return "fault-fixture"; }
            @Override public void close() { closes.incrementAndGet(); }
        };
        var staged = (zeroecho.pki.spi.store.StagedContentStore) java.lang.reflect.Proxy.newProxyInstance(
                zeroecho.pki.spi.store.StagedContentStore.class.getClassLoader(), new Class<?>[]{zeroecho.pki.spi.store.StagedContentStore.class},
                (proxy, method, values) -> { if (method.getName().equals("openContent")) return content; throw new AssertionError("Unexpected content mutation"); });
        var observed = (zeroecho.pki.spi.store.PkiStore) java.lang.reflect.Proxy.newProxyInstance(
                zeroecho.pki.spi.store.PkiStore.class.getClassLoader(), new Class<?>[]{zeroecho.pki.spi.store.PkiStore.class}, (proxy, method, values) -> {
                    if (method.getName().equals("getCredential")) return java.util.Optional.of(metadata);
                    if (method.getName().equals("stagedContent")) return staged;
                    try { return method.invoke(store, values); }
                    catch (java.lang.reflect.InvocationTargetException failure) { throw failure.getCause(); }
                });
        return new DefaultPkiRepository(observed, () -> { }, List.of(framework));
    }

    /**
     * Runs the standalone fixture scenario using a newly created temporary directory.
     *
     * @param args unused console arguments; the fixture creates its own temporary root
     * @throws Exception if fixture construction, execution, or cleanup fails
     */
    public static void main(String[] args) throws Exception { exercise(Files.createTempDirectory("zeroecho-credential-exports-")); }
}
