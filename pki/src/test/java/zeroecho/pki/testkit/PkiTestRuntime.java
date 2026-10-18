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
package zeroecho.pki.testkit;

import java.io.IOException;
import java.io.OutputStream;
import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmSuite;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.core.spi.AlgorithmExecutionCapabilityProvider;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.StagedContentStore;

/** Small store and workflow fixtures shared by focused PKI tests. */
public final class PkiTestRuntime {

    private PkiTestRuntime() {
    }

    /** Creates real CSR verification and leaf preparation for focused semantic-service tests. */
    public static zeroecho.pki.impl.core.EndEntitySigningPreparation endEntityPreparation(PkiStore store, Clock clock) {
        zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor verification =
                new zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor();
        X509AuthoritySnapshot authority = X509AuthoritySnapshot.compose(List.of(), List.of(verification),
                List.of(X509AuthoritySnapshot.bindExecutor(
                        zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor.IMPLEMENTATION_ID,
                        AlgorithmExecutionCapability.Direction.VERIFY, verification)), new X509AlgorithmResolver.Policy() {
                    @Override public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                        return direction == AlgorithmExecutionCapability.Direction.VERIFY;
                    }
                    @Override public String semanticFingerprint() { return "semantic-test-verification"; }
                });
        return new zeroecho.pki.impl.core.EndEntitySigningPreparation(store, clock, authority, verification,
                zeroecho.pki.impl.framework.x509.ImmutableX509AlgorithmBindingRegistry.create(
                        zeroecho.pki.impl.framework.x509.StandardX509Bindings.descriptors()),
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm());
    }

    /** Stages one credential fixture in the supplied store. */
    public static DurableContentReference stageCredential(PkiStore store, byte[] encoded) throws IOException {
        try (ContentSink sink = store.stagedContent().beginContent(
                Encoding.DER, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(encoded);
            return sink.complete();
        }
    }

    /** Stages bytes with the requested encoding and persistent lifecycle. */
    public static DurableContentReference fixtureReference(StagedContentStore store, Encoding encoding, byte[] bytes)
            throws IOException {
        try (ContentSink sink = store.beginContent(encoding, DurableContentReference.Lifecycle.PERSISTED);
                OutputStream output = sink.outputStream()) {
            output.write(bytes);
            return sink.complete();
        }
    }

    /** Stages an operation-owned signing candidate. */
    public static DurableContentReference operationReference(StagedContentStore store,
            Encoding encoding, byte[] bytes) throws IOException {
        try (ContentSink sink = store.beginContent(encoding, DurableContentReference.Lifecycle.OPERATION);
                OutputStream output = sink.outputStream()) {
            output.write(bytes);
            return sink.complete();
        }
    }

    /** Creates a non-store-issued reference for trust-boundary tests. */
    public static DurableContentReference untrustedReference(DurableContentReference source, Encoding encoding) {
        return new UntrustedReference(source.storeId(), source.contentId(), encoding, source.length(), source.sha256(),
                source.lifecycle());
    }

    /** Reads one store-owned content fixture. */
    public static byte[] readContent(PkiStore store, DurableContentReference reference) throws IOException {
        try (zeroecho.core.io.RepeatableContent content = store.stagedContent().openContent(reference);
                java.io.InputStream input = content.openStream()) {
            return input.readAllBytes();
        }
    }

    /** Composes an X.509 authority owning exactly the supplied signing provider. */
    public static X509AuthoritySnapshot signingAuthority(SigningProvider workflow) {
        Objects.requireNonNull(workflow, "workflow");
        Set<String> supported = Set.copyOf(
                Objects.requireNonNull(workflow.supportedAlgorithms(), "workflow.supportedAlgorithms"));
        Set<AlgorithmIdentity> exact = BootstrapAlgorithmIdentities.catalog().identities().stream()
                .filter(identity -> identity.kind() == AlgorithmIdentity.Kind.SIGNATURE)
                .filter(identity -> supported.contains(identity.canonicalForm())
                        || BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                                .anyMatch(entry -> entry.getValue().equals(identity)
                                        && supported.contains(entry.getKey())))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        AlgorithmExecutionCapability capability = new AlgorithmExecutionCapability() {
            @Override
            public String implementationId() {
                return "workflow." + workflow.id();
            }

            @Override
            public String domainFingerprint() {
                return "test-workflow-v1:" + workflow.id() + ":" + exact.stream()
                        .map(AlgorithmIdentity::canonicalForm).sorted().reduce("", (left, right) -> left + right);
            }

            @Override
            public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
                return direction == Direction.SIGN && exact.contains(identity) && identity.equals(suite.signature());
            }
        };
        AlgorithmExecutionCapabilityProvider provider = () -> List.of(capability);
        X509AlgorithmResolver.Policy policy = new X509AlgorithmResolver.Policy() {
            @Override
            public boolean permits(AlgorithmSuite suite, AlgorithmExecutionCapability.Direction direction) {
                return true;
            }

            @Override
            public String semanticFingerprint() {
                return "pki-test-runtime-policy-v1:allow-authorized-capability";
            }
        };
        return X509AuthoritySnapshot.compose(List.of(), List.of(provider),
                List.of(X509AuthoritySnapshot.bindExecutor(capability.implementationId(),
                        AlgorithmExecutionCapability.Direction.SIGN, workflow)), policy);
    }

    private record UntrustedReference(String storeId, String contentId, Encoding encoding, long length, String sha256,
            DurableContentReference.Lifecycle lifecycle) implements DurableContentReference {
    }
}
