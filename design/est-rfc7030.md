# EST — Enrollment over Secure Transport (RFC 7030)

**Status:** Design specification — not yet implemented  
**Target modules:** `pki-server` (new route + listener), `lib` (new Pkix facade methods)  
**Protocol reference:** RFC 7030, RFC 8951 (CMS over HTTPS), RFC 5272 (CMC subset)

---

## 1. Protocol Overview

EST provides HTTPS-based certificate enrollment using standard CMS wire formats.
ZeroEcho implements the enterprise-grade subset defined below.

### 1.1 URL Structure

```
https://<host>:<port>/.well-known/est/{label}/{operation}
```

- **`{label}`** — identifies an EST endpoint configuration (authority + profile pair, registered via admin API)
- **`{operation}`** — one of the defined EST operations below

All paths are under `/.well-known/est/` per RFC 7030 §3.2.2. The server MUST NOT
expose any EST endpoint without an explicit label.

### 1.2 Content-Types

| Direction | Media type |
|-----------|------------|
| CSR request body | `application/pkcs10` (DER, base64 decoded from optional base64 wrapping per RFC 2986) |
| CMS signed response | `application/pkcs7-mime; smime-type=certs-only` |
| Server-keygen response | `multipart/mixed` (first part: private key as `application/pkcs8`, second part: certificate chain as `application/pkcs7-mime`) |
| Error response | `application/problem+json` (RFC 9457) or plain `text/plain` |

For responses, the `Content-Transfer-Encoding: base64` header indicates that the
body is base64-encoded (line-wrapped at 76 characters per MIME convention). The
server SHOULD emit this header and the client MUST tolerate both raw DER and
base64-encoded DER.

### 1.3 Operations Summary

| Operation | Method | Path suffix | Required | Description |
|-----------|--------|-------------|----------|-------------|
| CA certificates | GET | `/cacerts` | Yes | Returns the CA certificate(s) for the EST label |
| Simple enroll | POST | `/simpleenroll` | Yes | Submit PKCS#10 CSR, receive signed certificate |
| Simple re-enroll | POST | `/simplereenroll` | Yes | Renew an existing certificate |
| CSR attributes | GET | `/csrattrs` | Yes | Server-suggested attributes for CSR generation |
| Server keygen | POST | `/serverkeygen` | Yes | Server generates key pair, issues certificate, returns both |
| Full CMC | POST | `/fullcmc` | **No** — deferred | Complex CMC; not justified for the initial release |

**Decision on `/fullcmc`:** CMC (RFC 5272) adds significant complexity (ASN.1 state
machine, multi-step workflows) without adding capabilities that the simpler EST
operations already cover for enterprise enrollment. Omit in v1; revisit if a
customer integration requires it.

---

## 2. Module Placement and JPMS

### 2.1 Module

EST routes belong in the **existing `pki-server` module** (`zeroecho.pki.server`),
matching the ACME precedent. A separate module would add deployment complexity without
architectural benefit — EST and ACME serve the same purpose (automated enrollment)
and share the same runtime dependencies.

Package: `zeroecho.pki.server.est.*`

Classes:
- `EstHttpHandler` — route adapter (mirrors `AcmeHttpHandler`)
- `EstService` — protocol state + PKI integration (mirrors `AcmeService`)
- `EstCmsCodec` — CMS encode/decode bridge to `zeroecho.pkix` facade (new)
- `EstEndpoint` — immutable record: label → authority ID + profile ID + keygen policy

### 2.2 JPMS Changes

No new `exports` are needed; all new packages are `pki-server`-internal. The `lib`
module gains new `Pkix` methods (§5) which are already exported via `exports
zeroecho.pkix`.

New `requires` in `pki-server/module-info.java`: none — all required packages
(`zeroecho.pkix`, `zeroecho.pki.api`, `com.sun.net.httpserver`) are already on the
module graph.

---

## 3. HTTP Listener Design

### 3.1 Dedicated EST Listener

EST is **not** served on the administrative listener (port varies, client cert
required for admin operations). EST clients are end-entities enrolling certificates,
not admins — mixing them on the same listener conflates authentication domains.

EST gets its own listener, parallel to `AcmeListener`:

```java
// PkiServerConfiguration addition
Optional<EstListener> estListener
```

```java
public record EstListener(
    InetAddress address,
    int port,
    URI externalBaseUri,
    EstTransportMode transportMode,      // DIRECT_TLS | TRUSTED_REVERSE_PROXY
    List<ProxyTransportMapping> proxyTransportMappings,
    int maximumBodyBytes,                // default: 65536 (64 KiB)
    int maximumHeaderBytes,             // default: 16384
    Execution execution                 // shared bounded execution config
) { ... }

public enum EstTransportMode { DIRECT_TLS, TRUSTED_REVERSE_PROXY }
```

The EST listener requires TLS. It requires mutual TLS from every client (no
anonymous enrollment). This is enforced by `SSLContext` configuration at listener
startup: `setNeedClientAuth(true)`.

### 3.2 ServerRuntime Lane

Add `EST` to `ServerRuntime.Lane`:

```java
enum Lane { ADMIN, PUBLIC, ACME, OCSP, EST }
```

Thread name prefixes:
- Transport: `zeroecho-pki-est-https-`
- Operations: `zeroecho-pki-est-operation-`

### 3.3 Label Routing

An `EstEndpoint` record maps a label string to a CA authority and issuance profile:

```java
public record EstEndpoint(
    String label,          // URL-safe, non-blank, max 64 chars
    String authorityId,    // resolves to an existing CA authority
    String profileId,      // resolves to an existing issuance profile
    KeygenPolicy keygen    // controls /serverkeygen eligibility
) { }

public record KeygenPolicy(
    boolean enabled,
    List<String> permittedAlgorithms,  // e.g. ["RSA", "EC"]
    int maximumKeySizeBytes,            // for RSA: bits/8; guards memory
    boolean storeGeneratedKeys          // if true, key is written to KeyringStore
) { }
```

Endpoints are registered and de-registered via the admin API (§3.4) and held in a
`ConcurrentHashMap<String, EstEndpoint>` within `EstService`.

### 3.4 Admin API Registration

New admin operations (descriptor additions to the existing 99-descriptor catalog):

| Operation ID | Action | Resource | Description |
|---|---|---|---|
| `est.endpoint.register` | `write` | `est.endpoint` | Register a new EST label endpoint |
| `est.endpoint.deregister` | `write` | `est.endpoint` | Remove an EST label endpoint |
| `est.endpoint.get` | `read` | `est.endpoint` | Get endpoint configuration by label |
| `est.endpoint.list` | `read` | `est.endpoint` | List all registered endpoints |

---

## 4. Per-Operation Design

### 4.1 GET `/cacerts`

**Purpose:** Returns the CA certificate chain for the authority bound to the label.
No client authentication is required for this operation (RFC 7030 §4.1 allows
anonymous access to `/cacerts`).

**Request:**
- Method: `GET`
- No request body
- No authentication check (unauthenticated access permitted)

**Response:**
- Status: `200 OK`
- Content-Type: `application/pkcs7-mime; smime-type=certs-only`
- Body: DER-encoded `CMS ContentInfo` wrapping `SignedData` with `certificates` field
  populated with the full issuer chain from `EstEndpoint.authorityId` upward.
  The `encapContentInfo` contains `id-data` with empty content (certs-only).

**Integration:**
```java
// Fetch chain from existing session
IssuerChainPath chain = realm.session().repository().chainPath(authorityId);
// Encode as CMS certs-only via EstCmsCodec
byte[] response = EstCmsCodec.encodeCertsOnly(chain.certificates());
```

**Errors:**
- `404 Not Found` — label not registered
- `503 Service Unavailable` — authority chain unavailable

---

### 4.2 POST `/simpleenroll`

**Purpose:** Submit a PKCS#10 CSR; receive a newly issued certificate.

**Authentication:** mTLS — the peer certificate from the TLS handshake is the client
identity. See §6 for principal mapping.

**Request:**
- Method: `POST`
- Content-Type: `application/pkcs10`
- Body: DER-encoded PKCS#10 CSR (optionally base64-wrapped)
- Maximum size: `EstListener.maximumBodyBytes`

**Processing:**
1. Parse the EST principal from the TLS peer certificate (§6.1).
2. Decode and parse the PKCS#10 CSR via `EstCmsCodec.parsePkcs10(byte[])`.
3. Verify the proof-of-possession (signature on the CSR) using the public key in the CSR.
4. Construct a `CertificationRequest` with `FormatId` = `"x509-pkcs10-v1"` and pass
   to the issuance pipeline via `realm.session().issuanceService()`.
5. Authorization check: the mapped principal must have the `credential.issue` grant
   for the profile bound to the label.
6. If the profile requires approval, the enrollment enters the pending state (the EST
   server returns `202 Accepted` with a `Retry-After` header; the client polls).
7. On issuance, encode the signed certificate as a CMS `certs-only` response.

**Response (immediate issuance):**
- Status: `200 OK`
- Content-Type: `application/pkcs7-mime; smime-type=certs-only`
- Body: DER-encoded CMS wrapping the issued certificate (leaf only; no chain)

**Response (pending approval):**
- Status: `202 Accepted`
- Headers: `Retry-After: 30` (configurable), `Location: /.well-known/est/{label}/pending/{requestId}`
- Body: empty

**Pending status resource** `GET /.well-known/est/{label}/pending/{requestId}`:
- Returns `202` while awaiting approval
- Returns `200` with the certificate once approved
- Returns `403` if the request was denied

**Errors:**
- `400 Bad Request` — malformed CSR or POP verification failure
- `401 Unauthorized` — no client certificate presented
- `403 Forbidden` — principal not authorized for this profile
- `415 Unsupported Media Type` — wrong Content-Type
- `429 Too Many Requests` — rate limit exceeded
- `500 Internal Server Error` — signing failure

---

### 4.3 POST `/simplereenroll`

**Purpose:** Renew or re-key an existing certificate. The client presents its current
certificate via mTLS and submits a new CSR (possibly with a new key pair).

**Authentication:** Same as `/simpleenroll`. Additionally:
- The TLS peer certificate MUST be the currently-valid certificate being renewed, OR
- An explicitly authorized administrator principal may reenroll on behalf of an entity.

**Request:** Same structure as `/simpleenroll`.

**Additional validation:**
1. Extract the subject DN and SANs from the existing TLS peer certificate.
2. The new CSR MUST NOT request a subject or SANs materially different from the
   existing certificate unless the profile explicitly permits subject change on renewal.
   "Materially different" is defined per profile configuration (`subjectChangePolicy`).
3. If the CSR presents a new key pair, POP verification applies to the new key.
4. If the CSR presents the same public key as the current certificate, the server
   accepts it (re-issue without re-key — useful for validity extension only).

**Response:** Same as `/simpleenroll`.

---

### 4.4 GET `/csrattrs`

**Purpose:** Returns server-suggested CSR attributes that the client should include
in its PKCS#10 request. Clients SHOULD include all mandatory attributes.

**Authentication:** None required (RFC 7030 §4.5.2 permits unauthenticated access).

**Request:**
- Method: `GET`
- No request body

**Response:**
- Status: `200 OK`
- Content-Type: `application/csrattrs` (RFC 7030 §4.5.2)
- Body: DER-encoded `CsrAttrs` ASN.1 structure (sequence of OIDs and
  `AttrOrOID` entries as defined in RFC 7030 Appendix B)

**Content generated from profile:**
The server derives `CsrAttrs` from the issuance profile bound to the label:
- Subject DN component OIDs (e.g., `id-at-commonName`, `id-at-organizationName`)
- Required SAN types
- Preferred signature algorithm OID (e.g., `sha256WithRSAEncryption`, `ecdsa-with-SHA256`)

**Implementation:** `EstCmsCodec.encodeCsrAttrs(EstEndpoint endpoint, IssuanceProfile profile) → byte[]`

---

### 4.5 POST `/serverkeygen`

**Purpose:** The server generates a key pair on behalf of the client, issues a
certificate, and returns both the private key and the certificate in a single
`multipart/mixed` response. This is a HIGH-RISK operation.

#### Security constraints

- The `/serverkeygen` endpoint MUST be explicitly enabled per label in `KeygenPolicy.enabled`.
- The server-generated private key MUST be encrypted for the client before transmission.
  Encryption uses the client's encryption certificate (the TLS peer certificate's
  public key, or a separate encryption certificate if the client provides one in the
  CSR's `SubjectPublicKeyInfo`).
- The encrypted key is wrapped in a PKCS#7 `EnvelopedData` structure targeting the
  client's certificate.
- Generated private keys are **ephemeral by default** (`KeygenPolicy.storeGeneratedKeys = false`):
  the server never retains a copy after the response is delivered. If
  `storeGeneratedKeys = true`, the key is written to the authority's `KeyringStore`
  under a client-specific alias (for escrow scenarios).
- This operation MUST require an approval step unless the profile explicitly waives it.
  The default approval category is `HIGH_RISK`.

#### Request

- Method: `POST`
- Content-Type: `application/pkcs10` (a CSR with the desired subject/SANs, but the
  `SubjectPublicKeyInfo` MAY contain a placeholder key — the server ignores it and
  generates the actual key)
- Alternatively, the body may be empty (`Content-Length: 0`) if the label's profile
  defines default subject attributes.

#### Processing

1. Authenticate the mTLS client principal (§6).
2. Authorize: principal must have `credential.serverkeygen` grant (separate from `credential.issue`).
3. Generate key pair: algorithm and size from `KeygenPolicy.permittedAlgorithms` and
   the CSR (or profile default). Use `java.security.KeyPairGenerator` via JCA.
4. Build and sign a CSR internally using the generated private key.
5. Issue the certificate via the normal issuance pipeline with the internal CSR.
6. Encrypt the private key using the client's TLS peer certificate public key:
   ```
   PKCS#7 EnvelopedData {
     recipientInfos: KeyTransRecipientInfo targeting peer cert
     encryptedContentInfo: AES-256-GCM wrapping PKCS#8 private key DER
   }
   ```
7. Construct `multipart/mixed` response:
   - Part 1: `application/pkcs8` — the encrypted private key (`EnvelopedData` DER, base64-encoded)
   - Part 2: `application/pkcs7-mime; smime-type=certs-only` — the issued certificate

8. Zero the private key bytes immediately after encryption.

#### Response

- Status: `200 OK`
- Content-Type: `multipart/mixed; boundary=<server-generated-boundary>`

```
--<boundary>
Content-Type: application/pkcs8
Content-Transfer-Encoding: base64

<base64 EnvelopedData>
--<boundary>
Content-Type: application/pkcs7-mime; smime-type=certs-only
Content-Transfer-Encoding: base64

<base64 CMS certs-only>
--<boundary>--
```

**Errors:** Same as `/simpleenroll` plus `403 Forbidden` if `KeygenPolicy.enabled = false`.

---

## 5. CMS / PKCS#7 Handling

### 5.1 BouncyCastle Confinement

All CMS encoding and decoding MUST go through the `zeroecho.pkix` facade in the `lib`
module. Direct use of `org.bouncycastle.cms.*` in `pki-server` violates the BC
confinement gate.

### 5.2 New `Pkix` Facade Methods

Add to `Pkix.java` (delegated to `BcPkixProvider`):

```java
// Parse a PKCS#10 CSR from raw DER (or base64-wrapped DER)
public static zeroecho.pkix.csr.CertificationRequest parseCsr(byte[] derOrBase64)
    throws CertificationRequestException

// Encode a list of certificates as CMS certs-only (id-data, no signer)
public static byte[] encodeCertsOnly(List<X509Certificate> chain)

// Encode CSR attributes as RFC 7030 CsrAttrs DER
public static byte[] encodeCsrAttrs(List<CsrAttribute> attributes)

// Encrypt a PKCS#8 private key in a PKCS#7 EnvelopedData for one recipient
public static byte[] encryptPrivateKeyForRecipient(
    byte[] pkcs8PrivateKeyDer,
    X509Certificate recipientCertificate)

// Parse a MIME multipart body (no external library; simple boundary parser)
// Returns the raw byte[] for each part body, keyed by Content-Type
public static List<MimePart> parseMultipart(byte[] body, String boundary)
```

The `CsrAttribute` record in `zeroecho.pkix.csr`:
```java
public record CsrAttribute(String oid, Optional<String> value) { }
```

### 5.3 `EstCmsCodec`

`EstCmsCodec` (package `zeroecho.pki.server.est`) wraps `Pkix` calls with
EST-specific logic:
- `parsePkcs10(byte[] body)` — decodes, optionally un-base64s, calls `Pkix.parseCsr`
- `encodeCertsOnly(List<X509Certificate>)` — calls `Pkix.encodeCertsOnly` then base64-wraps
- `encodeCsrAttrs(EstEndpoint, IssuanceProfile)` — derives attributes from profile, calls `Pkix.encodeCsrAttrs`
- `encryptPrivateKey(byte[] pkcs8, X509Certificate)` — calls `Pkix.encryptPrivateKeyForRecipient`
- `buildServerKeygenResponse(byte[] encryptedKey, byte[] certsCms)` — builds `multipart/mixed` body

---

## 6. Security Model

### 6.1 Client Principal Mapping

The mTLS peer certificate is the sole authentication token. The certificate's Subject
DN is mapped to an existing ZeroEcho principal using the same `MutualTlsAuthenticator`
already used by the admin API:

```
X509Certificate (TLS peer)
  → MutualTlsAuthenticator.authenticate(...)
  → PkiServerAuthenticationResult.Authenticated
  → principal (existing type: "mtls-cert")
```

An EST principal MUST be pre-registered in the ZeroEcho principal store before
enrollment. There is no implicit self-registration (no anonymous enrollment). This
differs from ACME where accounts are created on first request.

**Rationale:** Anonymous enrollment would allow any client with a valid CA-signed
certificate to request certificates, undermining the authorization model. Enterprises
must explicitly onboard devices or users before they can enroll.

### 6.2 Required Grants

| Grant | Required for |
|-------|-------------|
| `credential.issue` | `/simpleenroll`, `/simplereenroll` |
| `credential.serverkeygen` | `/serverkeygen` |
| `est.endpoint.read` (resource: the label) | implicit in any enrollment |

Grants are scoped to the specific profile bound to the EST label. A principal
authorized for label `device-label` cannot enroll against label `user-label` even if
both map to the same CA.

### 6.3 Implicit vs. Explicit Enrollment Mode

**Default: Explicit (required)** — the principal must be registered before enrollment.

Optional **implicit mode** per endpoint (`KeygenPolicy` or a new `EnrollmentPolicy`):
when enabled, any client presenting a certificate issued by a configured trust anchor
is automatically mapped to a new or existing principal. Implicit mode is opt-in and
must be explicitly set in the `EstEndpoint` configuration.

### 6.4 Re-enrollment Chain Validation

For `/simplereenroll`, the new certificate's subject MUST match the renewing
certificate's subject unless the profile's `subjectChangePolicy` is set to `ALLOW_CHANGE`.
The server uses the TLS peer certificate's subject (not the CSR's subject) as the
authoritative current identity.

---

## 7. Integration with Approval Workflow

EST enrollment flows through the existing `IssuanceApprovalGateway`:

| Operation | Approval category | Default behavior |
|-----------|------------------|-----------------|
| `/simpleenroll` | Profile-defined (`standard`, `elevated`, `high-risk`) | Same as ACME finalize |
| `/simplereenroll` | `standard` unless profile overrides | Typically auto-approved |
| `/serverkeygen` | Always at least `elevated`; configurable to `high-risk` | Pending until approved |

When a request enters pending state:
1. The EST handler returns `202 Accepted` with a `Location` header pointing to
   `/.well-known/est/{label}/pending/{requestId}`.
2. The `EstService` registers a pending request in the existing `ApprovalRequestStore`.
3. Approvers act via the existing admin API (`approval.review` operation).
4. The client polls the pending URL (with valid mTLS) until the response transitions
   to `200` (approved) or `403` (denied).

---

## 8. Error Handling

EST uses `application/problem+json` (RFC 9457) for structured errors, matching the
server's existing practice:

```json
{
  "type": "urn:ietf:params:est:error:badCSR",
  "title": "CSR rejected",
  "detail": "Proof of possession verification failed",
  "status": 400
}
```

EST-specific error types:

| Type suffix | HTTP status | Meaning |
|---|---|---|
| `badCSR` | 400 | Malformed or signature-invalid CSR |
| `badContentType` | 415 | Wrong Content-Type header |
| `notAuthorized` | 403 | Principal lacks required grant |
| `labelNotFound` | 404 | Label is not registered |
| `serverKeygenDisabled` | 403 | Keygen not enabled for this label |
| `pendingApproval` | 202 | Enrollment awaiting approval |
| `requestDenied` | 403 | Enrollment request was denied by approver |
| `rateLimited` | 429 | Admission limit reached |
| `serverInternal` | 500 | Internal server error |

---

## 9. Test Strategy

### 9.1 Unit Tests (`pki-server/src/test/`)

| Test class | Scope |
|---|---|
| `EstCmsCodecTest` | Round-trip PKCS#10 parse, certs-only encoding, CSR attrs encoding, private key encryption |
| `EstHttpHandlerTest` | Route dispatch: correct operations dispatched, unknown paths return 404, wrong methods return 405 |
| `EstEndpointTest` | Label validation, authority/profile resolution |
| `ServerKeygenPolicyTest` | Policy enforcement: disabled keygen returns 403, algorithm restriction |

### 9.2 Integration Tests (`pki-server/src/test/`)

Use Java's built-in HTTPS client (`java.net.http.HttpClient`) with mTLS:

| Scenario | Expected |
|---|---|
| GET `/cacerts` without client cert | 200 OK with cert chain |
| POST `/simpleenroll` with valid CSR and authorized cert | 200 OK with issued cert |
| POST `/simpleenroll` with unregistered cert | 403 Forbidden |
| POST `/simpleenroll` with invalid POP | 400 Bad Request |
| POST `/simplereenroll` with current cert, same key | 200 OK |
| POST `/simplereenroll` with mismatched subject | 403 Forbidden |
| GET `/csrattrs` | 200 OK with DER-encoded attributes |
| POST `/serverkeygen` with disabled endpoint | 403 Forbidden |
| POST `/serverkeygen` with authorized cert | 200 OK multipart response, key decryptable with peer private key |
| GET pending URL while pending | 202 |
| GET pending URL after approval | 200 OK with cert |

### 9.3 Interoperability

The reference EST client for manual verification is:
- **OpenSSL `s_mime`** or **`curl`** with `--cert`/`--key` flags
- **BouncyCastle EST client** (`org.bouncycastle.est.jcajce.JsseESTServiceBuilder`) for automated integration tests (test-scope dependency only; never in production code)

---

## 10. Implementation Plan

| Step | Class / change | Complexity | Notes |
|------|---------------|------------|-------|
| 1 | `Pkix.parseCsr`, `Pkix.encodeCertsOnly` | S | Add to existing `Pkix` + `BcPkixProvider` |
| 2 | `Pkix.encodeCsrAttrs` | S | New ASN.1 sequence builder |
| 3 | `Pkix.encryptPrivateKeyForRecipient` | M | BouncyCastle `CMSEnvelopedDataGenerator`, AES-256-GCM |
| 4 | `EstCmsCodec` | S | Thin adapter; delegates entirely to Pkix |
| 5 | `EstEndpoint` + `KeygenPolicy` records | S | Pure value types |
| 6 | `EstService` — endpoint registry + `/cacerts`, `/csrattrs` | M | Concurrent endpoint map, profile integration |
| 7 | `EstHttpHandler` — route adapter | M | Mirrors `AcmeHttpHandler` structure |
| 8 | `PkiServerConfiguration.EstListener` + constructor guards | S | Parallel to `AcmeListener` |
| 9 | `ServerRuntime.Lane.EST` + thread naming | S | One enum value + constants |
| 10 | `/simpleenroll` + POP verification | M | CSR parse → issuance pipeline integration |
| 11 | `/simplereenroll` + subject chain validation | M | Subject match policy |
| 12 | Pending enrollment + polling endpoint | M | Approval gateway integration + `202` handling |
| 13 | `/serverkeygen` key generation + encryption | L | Key generation, EnvelopedData, multipart response, key zeroing |
| 14 | Admin API operations (4 new descriptors) | S | Descriptor additions + handler cases |
| 15 | `MutualTlsAuthenticator` reuse for EST principal mapping | S | No change needed; reuse existing class |
| 16 | Unit tests (`EstCmsCodecTest`, `EstHttpHandlerTest`) | M | — |
| 17 | Integration tests (mTLS HttpClient) | M | — |

**Total estimate:** approximately 6–8 weeks of focused engineering effort.

---

## 11. Configuration Reference

Minimal YAML configuration for an EST listener (extends `PkiServerConfiguration`):

```yaml
est:
  address: "0.0.0.0"
  port: 8443
  externalBaseUri: "https://pki.example.com:8443"
  transportMode: DIRECT_TLS
  maximumBodyBytes: 65536
  maximumHeaderBytes: 16384
  execution:
    operationWorkers: 8
    operationQueueCapacity: 64
    gracefulShutdown: PT5S
    forcedShutdown: PT10S

estEndpoints:
  - label: "device-enrollment"
    authorityId: "urn:example:ca:device"
    profileId: "urn:example:profile:device-client"
    keygen:
      enabled: false
  - label: "server-enrollment"
    authorityId: "urn:example:ca:server"
    profileId: "urn:example:profile:tls-server"
    keygen:
      enabled: true
      permittedAlgorithms: ["RSA", "EC"]
      maximumKeySizeBytes: 512
      storeGeneratedKeys: false
```
