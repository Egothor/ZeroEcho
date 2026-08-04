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
package zeroecho.pki.api.algorithm;

import java.util.Objects;
import java.util.Optional;

import zeroecho.core.spec.AlgorithmIdentity;

/**
 * Immutable safe descriptor of one role-specific X.509 algorithm binding.
 *
 * <p>The descriptor separates cryptographic identity, ASN.1 identity, namespace
 * ownership, encoding rules, and provider implementation. It contains no codec
 * class, key material, provider secret, or caller-supplied DER.</p>
 *
 * @param bindingId stable semantic binding identifier
 * @param algorithmIdentity exact provider-independent cryptographic identity
 * @param role exact X.509 use role
 * @param oid complete dotted-decimal object identifier
 * @param origin namespace ownership
 * @param encodingVersion positive immutable encoding-contract version
 * @param parameterRule canonical AlgorithmIdentifier parameter rule
 * @param publicKeyEncoding public-key BIT STRING contract
 * @param signatureEncoding signature BIT STRING contract
 * @param interoperability finite interoperability classification
 * @param providerId contributing provider for deployer bindings
 * @param semanticCommitment deterministic commitment to the complete contract
 */
public record X509AlgorithmBinding(String bindingId, AlgorithmIdentity algorithmIdentity, Role role, String oid,
        Origin origin, int encodingVersion, ParameterRule parameterRule, PublicKeyEncoding publicKeyEncoding,
        SignatureEncoding signatureEncoding, Interoperability interoperability, Optional<String> providerId,
        String semanticCommitment) {

    /** X.509 locations whose representations are independently authorized. */
    public enum Role {
        /** SubjectPublicKeyInfo algorithm and public-key BIT STRING. */
        SUBJECT_PUBLIC_KEY,
        /** PKCS#10 certification-request signature. */
        CSR_SIGNATURE,
        /** Certificate signature. */
        CERTIFICATE_SIGNATURE,
        /** Certificate-revocation-list signature. */
        CRL_SIGNATURE
    }

    /** Authority that owns the OID assignment. */
    public enum Origin {
        /** Published standards assignment. */
        STANDARD,
        /** Frozen ZeroEcho assignment under the Egothor PEN. */
        ZEROECHO_PRIVATE,
        /** Explicitly enabled deployment-owned assignment. */
        DEPLOYER_PRIVATE
    }

    /** Canonical AlgorithmIdentifier parameter representation. */
    public enum ParameterRule {
        /** Parameters must be absent. */
        ABSENT,
        /** Parameters must be canonical DER NULL. */
        DER_NULL,
        /** Parameters are a binding-owned canonical DER structure. */
        STRUCTURED_DER
    }

    /** Subject-public-key BIT STRING representation. */
    public enum PublicKeyEncoding {
        /** This binding is not an SPKI binding. */
        NOT_APPLICABLE,
        /** Standard RSA PKCS#1 public-key DER. */
        RSA_PKCS1_DER,
        /** SEC1 elliptic-curve point. */
        EC_POINT,
        /** Algorithm-defined raw public-key bytes. */
        RAW,
        /** Canonical native SPKI DER nested as the BIT STRING payload. */
        NESTED_SPKI_DER
    }

    /** Signature BIT STRING representation. */
    public enum SignatureEncoding {
        /** This binding is not a signature binding. */
        NOT_APPLICABLE,
        /** Algorithm-defined opaque signature bytes. */
        OPAQUE,
        /** Canonical DER sequence of positive ECDSA integers. */
        ECDSA_DER
    }

    /** Relying-party interoperability expectation. */
    public enum Interoperability {
        /** Published standards ecosystems. */
        STANDARD_INTEROPERABLE,
        /** Relying parties with matching ZeroEcho bindings. */
        ZEROECHO_ECOSYSTEM,
        /** One explicitly configured deployment ecosystem. */
        DEPLOYER_ECOSYSTEM,
        /** Experimental representation without general interoperability. */
        EXPERIMENTAL
    }

    /** Validates and snapshots one descriptor. */
    public X509AlgorithmBinding {
        bindingId = requireText(bindingId, "bindingId");
        Objects.requireNonNull(algorithmIdentity, "algorithmIdentity");
        Objects.requireNonNull(role, "role");
        oid = requireText(oid, "oid");
        Objects.requireNonNull(origin, "origin");
        if (encodingVersion <= 0) {
            throw new IllegalArgumentException("encodingVersion must be positive");
        }
        Objects.requireNonNull(parameterRule, "parameterRule");
        Objects.requireNonNull(publicKeyEncoding, "publicKeyEncoding");
        Objects.requireNonNull(signatureEncoding, "signatureEncoding");
        Objects.requireNonNull(interoperability, "interoperability");
        providerId = Objects.requireNonNull(providerId, "providerId").map(value -> requireText(value, "providerId"));
        semanticCommitment = requireText(semanticCommitment, "semanticCommitment");
        if (origin == Origin.DEPLOYER_PRIVATE != providerId.isPresent()) {
            throw new IllegalArgumentException("Only deployer bindings declare a providerId");
        }
        if ((role == Role.SUBJECT_PUBLIC_KEY) != (signatureEncoding == SignatureEncoding.NOT_APPLICABLE)) {
            throw new IllegalArgumentException("Binding role and signature encoding disagree");
        }
        if ((role != Role.SUBJECT_PUBLIC_KEY) != (publicKeyEncoding == PublicKeyEncoding.NOT_APPLICABLE)) {
            throw new IllegalArgumentException("Binding role and public-key encoding disagree");
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
