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
package zeroecho.pki.application;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.application.OcspResponseService.SdkSigningRole;
import zeroecho.pki.impl.framework.x509.X509AlgorithmResolver;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves native and SDK signing algorithm metadata against the captured authority snapshot.
 */
final class OcspSigningAlgorithms {
    private final X509AuthoritySnapshot authority;
    private final SigningProvider provider;

    /* default */ OcspSigningAlgorithms(X509AuthoritySnapshot authority, SigningProvider provider) {
        this.authority = authority;
        this.provider = provider;
    }

    /* default */ record SigningAlgorithm(
            AlgorithmIdentity identity, AlgorithmIdentifier identifier) {}

    /* default */ record SdkResolvedRole(
            SigningAlgorithm algorithm, HybridSdkValue value, byte[] spki) {}

    /* default */ SigningAlgorithm algorithm(
            X509Certificate responder, String requested, Optional<String> binding) {
        AlgorithmIdentity identity = authority.resolveIdentity(requested);
        X509SecurityFloor.requirePermitted(identity);
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity publicKey =
                adapter.decode(
                        Pkix.subjectPublicKeyAlgorithm(Pkix.subjectPublicKeyInfo(responder)),
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(identity, publicKey);
        X509ExecutionPlan<SigningProvider> plan =
                binding.isPresent()
                        ? authority.plan(
                                identity,
                                publicKey,
                                Direction.SIGN,
                                Optional.empty(),
                                "explicit",
                                binding.orElseThrow(),
                                SigningProvider.class)
                        : authority.plan(
                                identity,
                                publicKey,
                                Direction.SIGN,
                                Optional.empty(),
                                "default",
                                SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        return new SigningAlgorithm(
                identity, BcX509AlgorithmAdapter.toLib(plan.selection().binding()));
    }

    /* default */ SdkResolvedRole sdkRole(
            SdkSigningRole selected, byte[] expectedSpki, boolean alternative) throws IOException {
        if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys)) {
            throw new UnsupportedOperationException("SDK managed public metadata unavailable");
        }
        EncodedObject info = keys.resolvePublicKeyInfo(selected.keyRef());
        if (info.encoding() != Encoding.DER || !Arrays.equals(info.bytes(), expectedSpki)) {
            throw new IllegalArgumentException("SDK responder key differs");
        }
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity publicKey =
                adapter.decode(
                        Pkix.subjectPublicKeyAlgorithm(expectedSpki),
                        X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        AlgorithmIdentity signature = authority.resolveIdentity(selected.signatureAlgorithm());
        X509SecurityFloor.requirePermitted(signature);
        X509SuiteCompatibility.requireCompatible(signature, publicKey);
        X509ExecutionPlan<SigningProvider> plan =
                selected.signatureBindingId().isPresent()
                        ? authority.plan(
                                signature,
                                publicKey,
                                Direction.SIGN,
                                Optional.empty(),
                                "explicit",
                                selected.signatureBindingId().orElseThrow(),
                                SigningProvider.class)
                        : authority.plan(
                                signature,
                                publicKey,
                                Direction.SIGN,
                                Optional.empty(),
                                "default",
                                SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        // Raw SigningRequest carries identity, not a format-binding selector. Only
        // the exact default-equivalent execution can therefore be honored here.
        X509ExecutionPlan<SigningProvider> rawPlan =
                authority.plan(
                        signature,
                        publicKey,
                        Direction.SIGN,
                        Optional.empty(),
                        "default",
                        SigningProvider.class);
        authority.authorize(rawPlan, provider, Direction.SIGN);
        X509AlgorithmResolver.Selection captured = plan.selection();
        X509AlgorithmResolver.Selection raw = rawPlan.selection();
        requireSameSelection(captured, raw, plan, rawPlan);
        AlgorithmIdentifier algorithm = BcX509AlgorithmAdapter.toLib(raw.binding());
        byte[] expected =
                alternative
                        ? HybridSdkFrame.alternativeAlgorithm()
                        : HybridSdkFrame.primaryAlgorithm();
        if (!Arrays.equals(Pkix.encodeAlgorithmIdentifier(algorithm), expected)) {
            throw new IllegalArgumentException("SDK responder signature suite differs");
        }
        HybridSdkValue role =
                HybridSdkValue.object(
                        Map.of(
                                "spki",
                                HybridSdkValue.bytes(expectedSpki),
                                "publicKeyAlgorithm",
                                HybridSdkValue.text(publicKey.canonicalForm()),
                                "signatureAlgorithm",
                                HybridSdkValue.text(signature.canonicalForm()),
                                "algorithmIdentifier",
                                HybridSdkValue.bytes(expected)));
        return new SdkResolvedRole(new SigningAlgorithm(signature, algorithm), role, expectedSpki);
    }

    // Executor object identity is part of the captured signing implementation binding.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    private static void requireSameSelection(
            X509AlgorithmResolver.Selection captured,
            X509AlgorithmResolver.Selection raw,
            X509ExecutionPlan<SigningProvider> plan,
            X509ExecutionPlan<SigningProvider> rawPlan) {
        if (!captured.requested().equals(raw.requested())
                || !captured.suite().equals(raw.suite())
                || !captured.binding().equals(raw.binding())
                || captured.direction() != raw.direction()
                || !captured.authorityFingerprint().equals(raw.authorityFingerprint())
                || !captured.implementation()
                        .implementationId()
                        .equals(raw.implementation().implementationId())
                || !captured.implementation()
                        .domainFingerprint()
                        .equals(raw.implementation().domainFingerprint())
                || plan.executor() != rawPlan.executor()) {
            throw new IllegalArgumentException(
                    "SDK responder binding cannot be carried by raw signing");
        }
    }
}
