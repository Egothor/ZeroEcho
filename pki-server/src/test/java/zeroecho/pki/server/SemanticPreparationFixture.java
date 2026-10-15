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

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.ProviderConfig;

/** Actual unused opaque custody for transport unit tests; no signing admission occurs. */
public final class SemanticPreparationFixture implements AutoCloseable {
    private static final char[] PASSWORD = "test-only-preparation-password".toCharArray();
    private PkiSession session;
    private final PreparedSemanticSigningRequest prepared;
    private final PkiSessionConfiguration configuration;
    private final Clock clock;
    private boolean accepted;

    private SemanticPreparationFixture(PkiSession session, PreparedSemanticSigningRequest prepared,
            PkiSessionConfiguration configuration, Clock clock) {
        this.session = session;
        this.prepared = prepared;
        this.configuration = configuration;
        this.clock = clock;
    }

    public static SemanticPreparationFixture open(Path root) throws Exception {
        return open(root, ServerTestSupport.CLOCK);
    }

    static SemanticPreparationFixture open(Path root, Clock clock) throws Exception {
        Files.createDirectories(root);
        try {
            Files.setPosixFilePermissions(root, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        } catch (UnsupportedOperationException ignored) {
            // Windows does not support POSIX file permissions.
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        Path keyring = root.resolve("keys.zek");
        try (KeyringPassword password = new KeyringPassword(PASSWORD.clone());
                KeyringStore store = KeyringStore.create(keyring, password)) {
            store.putPrivate("root.prv", "RSA", keys.getPrivate());
            store.putPublic("root.pub", "RSA", keys.getPublic());
        }
        PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                new PkiSessionConfiguration.SigningCoordinatorLimits(1, Duration.ofSeconds(10),
                        Duration.ofSeconds(5), Duration.ofMillis(10), Duration.ofSeconds(5)),
                List.of(), new PkiSessionConfiguration.SigningLanePool(1, 1));
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyring.toString(),
                        "keyRefPrefix", "fixture:", "requireComponentSuffix", "true")),
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm(), Duration.ofSeconds(30),
                Optional.empty(), topology, OptionalLong.empty());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", root.resolve("pki").toString())),
                new ProviderConfig("memory", Map.of("size", "256")), Optional.of(signing), List.of(), List.of());
        PkiSession session = PkiSession.open(configuration,
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> new KeyringPassword(PASSWORD.clone())),
                clock);
        try {
            BuiltInCertificateProfileTemplate profile = BuiltInCertificateProfileCatalog.load(
                    SemanticPreparationFixture.class.getClassLoader()).stream()
                    .filter(value -> value.definition().profileId().equals("root-ca")).findFirst().orElseThrow();
            session.profiles().importBuiltIn(profile);
            session.profiles().activateProfile("root-ca", profile.definition().profileVersion());
            PreparedSemanticSigningRequest prepared = session.semanticSigning().orElseThrow().prepareRootCreation(
                    new AccessContext(new Principal("SYSTEM", "test"), new Purpose("ca.create"),
                            Optional.empty(), Optional.empty()),
                    new CaCreateCommand(profile.definition().formatId(), new SubjectRef("CN=Transport Test"),
                            "root-ca", new KeyRef("fixture:root.prv"), new SimpleAttributeSet()),
                    CancellationSignal.NONE);
            return new SemanticPreparationFixture(session, prepared, configuration, clock);
        } catch (Exception failure) {
            session.close();
            throw failure;
        }
    }

    public PreparedSemanticSigningRequest prepared() { return prepared; }

    PkiSession session() { return session; }

    zeroecho.pki.api.signing.SigningAcceptanceReceipt acceptRoot() {
        zeroecho.pki.api.signing.SigningAcceptanceResult result = session.semanticSigning().orElseThrow().accept(prepared);
        accepted = true;
        return result.receipt();
    }

    void reopenSession() throws Exception {
        if (!accepted) throw new IllegalStateException("Fixture still owns unused preparation");
        session.close();
        session = PkiSession.open(configuration,
                PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> new KeyringPassword(PASSWORD.clone())), clock);
    }

    @Override public void close() throws Exception {
        try {
            if (!accepted) session.semanticSigning().orElseThrow().discard(prepared);
        } finally {
            session.close();
        }
    }
}
