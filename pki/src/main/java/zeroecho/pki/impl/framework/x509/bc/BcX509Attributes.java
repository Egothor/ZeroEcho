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
package zeroecho.pki.impl.framework.x509.bc;

import zeroecho.pki.api.attr.AttributeId;

/**
 * Internal attribute identifiers used by the Bouncy Castle backed X.509 PKI
 * framework adapter.
 *
 * <p>
 * These identifiers define the internal runtime wiring contract between PKI
 * core services and the X.509 framework implementation in this package. They
 * are used to pass X.509-specific input material and derived values through
 * {@code AttributeSet}-based override channels without exposing those details
 * as part of the higher-level public PKI API surface.
 * </p>
 *
 * <p>
 * Typical producers of these attributes are PKI core orchestration services
 * such as issuance, CA management, certification request processing, and status
 * object generation. Typical consumers are X.509-specific backend components
 * that build, parse, verify, or publish PKCS#10 requests, certificates, and
 * CRLs.
 * </p>
 *
 * <h2>Stability note</h2>
 * <p>
 * This class is part of an internal implementation package. The identifiers are
 * intended to be stable within the current runtime wiring model, but they
 * should not be treated as a general-purpose public extension contract unless
 * they are explicitly promoted to a higher-level API package.
 * </p>
 *
 * <h2>Value typing</h2>
 * <p>
 * The {@link AttributeId} constants defined here identify attributes whose
 * values are expected to use specific {@code AttributeValue} representations,
 * such as byte arrays, strings, or integers. Producers and consumers must agree
 * on those value forms exactly; the identifier alone does not enforce the value
 * type.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Several attributes carried under these identifiers may contain
 * operationally sensitive material, such as raw CSR bytes, issuer certificate
 * encodings, or key references.</li>
 * <li>These identifiers must never be used to transport private key
 * material.</li>
 * <li>Callers and implementations must avoid logging raw attribute values
 * unless such logging is explicitly required and appropriately sanitized.</li>
 * </ul>
 */
@SuppressWarnings("PMD.DataClass")
public final class BcX509Attributes {
    /** Original canonical CRMF CertReqMsg bytes; mutually exclusive with {@link #CSR_DER}. */
    public static final AttributeId CRMF_DER = new AttributeId("urn:zeroecho:pki:x509:crmf:der");

    /**
     * Attribute identifier for a DER-encoded PKCS#10 certification request.
     *
     * <p>
     * The associated value is expected to carry the raw CSR bytes, typically as an
     * {@code AttributeValue.BytesValue}. This attribute is used when the X.509
     * adapter must parse, validate, or process an externally supplied certification
     * request in its native PKCS#10 form.
     * </p>
     */
    public static final AttributeId CSR_DER = new AttributeId("urn:zeroecho:pki:x509:csr:der");

    /**
     * Attribute identifier for a DER-encoded issuer X.509 certificate.
     *
     * <p>
     * The associated value is expected to carry the issuer certificate bytes,
     * typically as an {@code AttributeValue.BytesValue}. This attribute is used by
     * X.509 issuance and status-object generation flows that need the issuer
     * certificate as input material for certificate or CRL construction.
     * </p>
     */
    public static final AttributeId ISSUER_CERT_DER = new AttributeId("urn:zeroecho:pki:x509:issuer:cert:der");

    /**
     * Attribute identifier for the issuer signing key reference.
     *
     * <p>
     * The associated value is expected to carry the issuer key reference as a
     * string, typically as an {@code AttributeValue.StringValue}. It identifies the
     * signing key that the X.509 adapter should use indirectly through the runtime
     * signing boundary. This attribute must reference a signing-capable key but
     * must never contain private key material itself.
     * </p>
     */
    public static final AttributeId ISSUER_KEYREF = new AttributeId("urn:zeroecho:pki:x509:issuer:keyref");

    /**
     * Attribute identifier for an X.509 certificate serial number.
     *
     * <p>
     * The associated value is expected to carry the serial number in integer form,
     * typically as an {@code AttributeValue.IntegerValue}. This attribute may be
     * used when an issuance or status-object workflow needs to inject or transport
     * an explicit certificate serial number rather than deriving it internally.
     * </p>
     */
    public static final AttributeId SERIAL = new AttributeId("urn:zeroecho:pki:x509:serial");

    /**
     * Attribute identifier for DER-encoded subject SubjectPublicKeyInfo data.
     *
     * <p>
     * The associated value is expected to carry the raw DER bytes of the subject's
     * {@code SubjectPublicKeyInfo}, typically as an
     * {@code AttributeValue.BytesValue}. This attribute is used when the X.509
     * adapter must construct or validate certificate content based on explicit
     * subject public key material.
     * </p>
     */
    public static final AttributeId SUBJECT_SPKI_DER = new AttributeId("urn:zeroecho:pki:x509:subject:spki");

    /**
     * Attribute identifier for the authoritative X.509 subject distinguished name.
     *
     * <p>
     * The associated value is a {@code StringValue}. Core CA orchestration
     * overwrites this reserved value from its authoritative subject record before
     * invoking the privileged issuer backend.
     * </p>
     */
    public static final AttributeId SUBJECT_DN = new AttributeId("urn:zeroecho:pki:x509:subject:dn");

    /**
     * Attribute identifier for the monotonic CRL number assigned to a generated
     * (full or delta) CRL.
     *
     * <p>
     * The associated value is a decimal {@code StringValue} holding a non-negative
     * integer (CRL numbers may exceed the range of a {@code long}). Core status-object
     * generation allocates the next value per issuer; the X.509 generator writes it as
     * the RFC 5280 {@code cRLNumber} extension and it is persisted on the status object
     * so subsequent allocations remain monotonic across restart.
     * </p>
     */
    public static final AttributeId CRL_NUMBER = new AttributeId("urn:zeroecho:pki:x509:crl:number");

    /**
     * Attribute identifier for the base CRL number a delta CRL is computed against.
     *
     * <p>
     * The associated value is a decimal {@code StringValue}. It is present only for
     * {@code DELTA_CRL} generation and is written as the RFC 5280 {@code deltaCRLIndicator}
     * (base CRL number) critical extension.
     * </p>
     */
    public static final AttributeId BASE_CRL_NUMBER = new AttributeId("urn:zeroecho:pki:x509:crl:base-number");

    /**
     * Attribute identifier for the certificate serial a persistent OCSP status
     * object covers.
     *
     * <p>
     * The associated value is a decimal {@code StringValue} holding the positive
     * X.509 serial (serials may exceed the range of a {@code long}). Core
     * status-object generation resolves the target's current status and the X.509
     * generator produces a single-response, issuer-signed OCSP response for it.
     * </p>
     */
    public static final AttributeId OCSP_TARGET_SERIAL = new AttributeId("urn:zeroecho:pki:x509:ocsp:target-serial");

    /**
     * Attribute identifier for the resolved OCSP certificate status snapshot.
     *
     * <p>
     * The associated value is a {@code StringValue} equal to {@code "GOOD"} or
     * {@code "REVOKED"}. When {@code "REVOKED"}, {@link #OCSP_REVOCATION_TIME} and
     * {@link #OCSP_REVOCATION_REASON} accompany it.
     * </p>
     */
    public static final AttributeId OCSP_CERT_STATUS = new AttributeId("urn:zeroecho:pki:x509:ocsp:cert-status");

    /**
     * Attribute identifier for the revocation instant of a revoked OCSP target.
     *
     * <p>The associated value is an {@code InstantValue}; present only for a
     * {@code "REVOKED"} status.</p>
     */
    public static final AttributeId OCSP_REVOCATION_TIME = new AttributeId("urn:zeroecho:pki:x509:ocsp:revocation-time");

    /**
     * Attribute identifier for the revocation reason of a revoked OCSP target.
     *
     * <p>The associated value is a {@code StringValue} equal to a
     * {@code RevocationReason} constant name; present only for a {@code "REVOKED"}
     * status.</p>
     */
    public static final AttributeId OCSP_REVOCATION_REASON =
            new AttributeId("urn:zeroecho:pki:x509:ocsp:revocation-reason");

    private BcX509Attributes() {
        // utility
    }
}
