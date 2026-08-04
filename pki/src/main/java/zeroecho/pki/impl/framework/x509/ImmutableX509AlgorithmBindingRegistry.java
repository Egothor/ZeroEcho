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
package zeroecho.pki.impl.framework.x509;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;

/** Package-owned immutable registry implementation used by session bootstrap. */
public final class ImmutableX509AlgorithmBindingRegistry implements X509AlgorithmBindingRegistry {

    /** Egothor Private Enterprise Number root. */
    public static final String EGOTHOR_PEN = "1.3.6.1.4.1.31424";
    /** Frozen ZeroEcho private assignment branch. */
    public static final String ZEROECHO_ASSIGNMENT_ROOT = EGOTHOR_PEN + ".1.1";
    /** Deployment-local experimental branch. */
    public static final String ZEROECHO_DEPLOYMENT_ROOT = EGOTHOR_PEN + ".1.2";

    private final List<X509AlgorithmBinding> bindings;
    private final Map<String, X509AlgorithmBinding> byId;
    private final Map<String, X509AlgorithmBinding> standards;
    private final String commitment;

    private ImmutableX509AlgorithmBindingRegistry(List<X509AlgorithmBinding> source) {
        this.bindings = source;
        Map<String, X509AlgorithmBinding> identifiers = new LinkedHashMap<>();
        Map<String, X509AlgorithmBinding> official = new LinkedHashMap<>();
        Map<String, X509AlgorithmBinding> reverse = new LinkedHashMap<>();
        for (X509AlgorithmBinding binding : source) {
            if (identifiers.putIfAbsent(binding.bindingId(), binding) != null) {
                throw new IllegalArgumentException("Duplicate X.509 binding identifier");
            }
            String reverseKey = binding.role() + "|" + binding.oid() + "|"
                    + (binding.parameterRule() == X509AlgorithmBinding.ParameterRule.STRUCTURED_DER
                            ? binding.algorithmIdentity().canonicalForm() : "fixed");
            if (reverse.putIfAbsent(reverseKey, binding) != null) {
                throw new IllegalArgumentException("Ambiguous X.509 role and OID");
            }
            if (binding.origin() == X509AlgorithmBinding.Origin.STANDARD
                    && official.putIfAbsent(key(binding.algorithmIdentity(), binding.role()), binding) != null) {
                throw new IllegalArgumentException("Ambiguous standard X.509 binding");
            }
        }
        this.byId = Map.copyOf(identifiers);
        this.standards = Map.copyOf(official);
        this.commitment = digest(source);
    }

    /**
     * Constructs and validates one deterministic registry snapshot.
     *
     * @param bindings complete explicitly selected binding set
     * @return immutable registry
     */
    public static ImmutableX509AlgorithmBindingRegistry create(List<X509AlgorithmBinding> bindings) {
        Objects.requireNonNull(bindings, "bindings");
        List<X509AlgorithmBinding> ordered = new ArrayList<>(bindings);
        ordered.sort(Comparator.comparing(X509AlgorithmBinding::bindingId));
        for (X509AlgorithmBinding binding : ordered) {
            Objects.requireNonNull(binding, "binding");
            if (binding.origin() == X509AlgorithmBinding.Origin.ZEROECHO_PRIVATE
                    && !isWithin(binding.oid(), ZEROECHO_ASSIGNMENT_ROOT)) {
                throw new IllegalArgumentException("ZeroEcho binding is outside the frozen assignment branch");
            }
            if (binding.origin() == X509AlgorithmBinding.Origin.STANDARD
                    && isWithin(binding.oid(), EGOTHOR_PEN)) {
                throw new IllegalArgumentException("Standard binding cannot use the Egothor private namespace");
            }
        }
        return new ImmutableX509AlgorithmBindingRegistry(List.copyOf(ordered));
    }

    /** Tests whether one OID is strictly below or exactly at an authorized root. */
    public static boolean isWithin(String oid, String root) {
        Objects.requireNonNull(oid, "oid");
        Objects.requireNonNull(root, "root");
        return oid.equals(root) || oid.startsWith(root + ".");
    }

    @Override
    public List<X509AlgorithmBinding> bindings() {
        return bindings;
    }

    @Override
    public Optional<X509AlgorithmBinding> find(String bindingId) {
        return Optional.ofNullable(byId.get(Objects.requireNonNull(bindingId, "bindingId")));
    }

    @Override
    public Optional<X509AlgorithmBinding> standard(AlgorithmIdentity identity, X509AlgorithmBinding.Role role) {
        return Optional.ofNullable(standards.get(key(Objects.requireNonNull(identity, "identity"),
                Objects.requireNonNull(role, "role"))));
    }

    @Override
    public String commitment() {
        return commitment;
    }

    @Override
    public X509AlgorithmBinding require(String bindingId, String expectedCommitment) {
        X509AlgorithmBinding binding = find(bindingId)
                .orElseThrow(() -> new IllegalArgumentException("X.509 binding is not active"));
        if (!binding.semanticCommitment().equals(Objects.requireNonNull(expectedCommitment, "expectedCommitment"))) {
            throw new IllegalArgumentException("X.509 binding contract has changed");
        }
        return binding;
    }

    private static String key(AlgorithmIdentity identity, X509AlgorithmBinding.Role role) {
        return identity.canonicalForm() + "|" + role;
    }

    private static String digest(List<X509AlgorithmBinding> bindings) {
        StringBuilder semantic = new StringBuilder();
        for (X509AlgorithmBinding binding : bindings) {
            semantic.append(binding.bindingId()).append('|').append(binding.algorithmIdentity().canonicalForm())
                    .append('|').append(binding.role()).append('|').append(binding.oid()).append('|')
                    .append(binding.origin()).append('|').append(binding.encodingVersion()).append('|')
                    .append(binding.parameterRule()).append('|').append(binding.publicKeyEncoding()).append('|')
                    .append(binding.signatureEncoding()).append('|').append(binding.interoperability()).append('|')
                    .append(binding.providerId().orElse("")).append('|').append(binding.semanticCommitment())
                    .append('\n');
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(semantic.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
}
