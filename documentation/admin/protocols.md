# Protocols and automated enrolment

ZeroEcho supports automated certificate enrolment over ACME, EST (RFC 7030),
SCEP (RFC 8894), and CMP (RFC 4210 / RFC 9480 Lightweight Profile). This page
covers the administrative side of each protocol: registering and governing the
endpoints that expose them, and understanding how each protocol authenticates
enrolling clients.

Protocol endpoints are managed via the administrative API. ACME is managed under
the **ACME** area (Directories and Accounts tabs); EST, SCEP, and CMP endpoints
are managed via API operations in their respective namespaces.

## ACME directories

An ACME directory is a named enrolment endpoint bound to one authority and profile,
with an enforced policy over the names, algorithms, and challenge types it will
accept. The **ACME** area lists directories (`acme.directory.list`).

### Registering a directory

**Register ACME directory** (`acme.directory.register`) is high-risk and requires
an [approval](access-control.md#approvals). It binds a directory to an authority
and profile and sets its enrolment policy:

| Field | Meaning |
|---|---|
| `alias` | The directory's stable alias. |
| `authorityId` | The issuing authority — also the operation's target authority. |
| `profileId` | The profile enrolled certificates are issued under. |
| `dnsNamespaces` | The DNS namespaces the directory will issue within. |
| `maximumValidityMillis` | The maximum validity of issued certificates. |
| `publicKeyAlgorithms` | The accepted subject public-key algorithms. |
| `x509BindingPolicies` | The applicable X.509 binding policies. |
| `challengeTypes` | The accepted challenge types — `HTTP_01`, `DNS_01`. |
| `challengeProviderIds` | The challenge-provider identifiers to use. |
| `eabProviderId`, `eabRequired` | *(Optional)* External Account Binding provider, and whether EAB is mandatory. |

!!! note "Enabling automated enrolment"
    Registering a directory binds it to a specific, activated
    [profile](profiles-and-issuance.md) on an `ACTIVE`
    [authority](authorities.md). Ensure both exist and are in service before you
    register, and require EAB where you need to control which accounts may enrol.

### Activating and deactivating

A directory must be activated before clients can enrol against it:

- **Activate ACME directory** (`acme.directory.activate`) — high-risk; put a
  directory into service.
- **Deactivate ACME directory** (`acme.directory.deactivate`) — withdraw a
  directory from service.
- **Inspect ACME directory** (`acme.directory.inspect`) — show a directory's
  configuration.

=== "Enable enrolment"

    Register the directory, have the registration approved, then *Activate ACME
    directory*. Clients can now discover and enrol against it.

=== "Suspend enrolment"

    *Deactivate ACME directory* to stop new enrolment without removing the
    directory's configuration or its accounts.

## ACME accounts

Each enrolling client holds an ACME account against a directory. The **Accounts**
tab lists accounts (`acme.account.list`).

- **Inspect ACME account** (`acme.account.inspect`) — show one account by
  `accountId`, including its contact and state.
- **Deactivate ACME account** (`acme.account.deactivate`) — deactivate an account
  so it can no longer enrol.

Accounts are created by clients during enrolment rather than by an administrator;
your administrative role is to inspect them and to deactivate any that should no
longer be able to enrol.

## Challenge providers

The `challengeProviderIds` field in a directory configuration names one or more
challenge-provider instances. Each directory uses the listed providers in the order
given; the first provider whose challenge type matches the order is used.

ZeroEcho ships two built-in providers.

### HTTP-01 provider (`zeroecho.http-01.v1`)

Validates HTTP-01 challenges by connecting directly to port 80 on each address
returned by DNS for the authorised identifier, retrieving the key-authorisation
token, and comparing it against the expected value.

| Configuration key | Required | Type | Range | Description |
|---|---|---|---|---|
| `allowPrivate` | Yes | `"true"` or `"false"` | — | Whether to probe private-range IP addresses. |
| `timeoutMillis` | Yes | integer | 100–60 000 | Socket connect and read timeout in milliseconds. |
| `maximumBodyBytes` | Yes | integer | 64–65 536 | Maximum response body size. |
| `maximumAddresses` | Yes | integer | 1–32 | Maximum number of DNS addresses to probe. |
| `targetPort` | No | integer | 1–65 535 | Target port; defaults to 80. Non-standard ports require `allowPrivate=true`. |

### DNS-01 provider (`zeroecho.dns-01.jndi.v1`)

Validates DNS-01 challenges by querying a specified recursive DNS resolver for
`_acme-challenge.<identifier>.` TXT records and comparing the SHA-256 key-authorisation
digest. CNAME redelegation is followed up to the configured depth.

| Configuration key | Required | Type | Range | Description |
|---|---|---|---|---|
| `providerUrl` | Yes | string | `dns://IP(:port)?/` | The recursive resolver to query. |
| `timeoutMillis` | Yes | integer | 100–60 000 | DNS query timeout in milliseconds. |
| `maximumRecords` | Yes | integer | 1–64 | Maximum TXT records to accept per name. |
| `maximumRecordBytes` | Yes | integer | 43–4 096 | Maximum bytes per TXT record value. |
| `maximumCnameDepth` | Yes | integer | 0–8 | Maximum CNAME redelegation depth. Set to 0 to disable CNAME following. |

## EST (RFC 7030)

EST provides certificate enrolment over HTTPS using mTLS client authentication.
Endpoints are exposed under `/.well-known/est/{label}/`.

### Registering an EST endpoint

`est.endpoint.register` binds a URL-safe label to one CA authority and issuance profile.

| Field | Meaning |
|---|---|
| `label` | URL-safe identifier (1–64 chars, `[A-Za-z0-9._-]+`) |
| `authorityId` | The CA authority to issue from |
| `profileId` | The issuance profile to apply |

The endpoint is immediately active upon registration.

### EST operations

| HTTP path | Description |
|---|---|
| `GET /.well-known/est/{label}/cacerts` | Retrieve CA certificate chain |
| `POST /.well-known/est/{label}/simpleenroll` | Enrol a new certificate |
| `POST /.well-known/est/{label}/simplereenroll` | Renew an existing certificate |
| `POST /.well-known/est/{label}/serverkeygen` | Server-side key generation |
| `GET /.well-known/est/{label}/csrattrs` | Retrieve CSR attribute hints |

### Authentication

EST uses mutual TLS: the client presents its certificate over the TLS connection.
The server authenticates the client using the client certificate chain.

---

## SCEP (RFC 8894)

SCEP provides certificate enrolment for network devices using CMS-wrapped
ASN.1 messages over HTTP(S). Endpoints are exposed under `/scep/{label}`.

### Registering a SCEP endpoint

`scep.endpoint.register` binds a URL-safe label to one CA authority, issuance
profile, and hashed challenge password.

| Field | Meaning |
|---|---|
| `label` | URL-safe identifier (1–64 chars, `[A-Za-z0-9._-]+`) |
| `authorityId` | The CA authority to issue from |
| `profileId` | The issuance profile to apply |
| `challengePasswordHash` | SHA-256 hex digest of the SCEP challenge password (64 lower-case hex chars) |

!!! note "Challenge password security"
    The plaintext challenge password is never stored. Only its SHA-256 hex digest
    is retained and compared against the hash of the password embedded in each
    PKCSReq message. Rotate the endpoint to change the password.

### SCEP operations

| Operation | HTTP method | Description |
|---|---|---|
| `GetCACert` | `GET /scep/{label}?operation=GetCACert` | Returns the issuing CA certificate (DER) |
| `GetCACertChain` | `GET /scep/{label}?operation=GetCACertChain` | Returns RA + CA chain (CMS certs-only) |
| `PKIOperation` | `GET` or `POST /scep/{label}?operation=PKIOperation` | Enrolment (PKCSReq), polling (GetCertInitial), CRL fetch (GetCRL) |

### Authentication

SCEP authenticates using the challenge password embedded in the PKCS#10 CSR
attribute `challengePassword` (OID 1.2.840.113549.1.9.7). The server verifies
the SHA-256 digest of the submitted password against the stored hash.

### RA key

Each SCEP service generates an ephemeral RSA-2048 signing key pair at startup.
The RA certificate is self-signed and returned in `GetCACertChain`. It is not
persisted across server restarts; SCEP clients should re-fetch the CA chain after
a server restart.

### Pending enrolment

When a PKCSReq cannot be processed synchronously (e.g., capacity pressure), the
server returns `pkiStatus=PENDING`. The client should poll using `GetCertInitial`
with the same `transactionID`. Pending state is tracked in memory; it is not
durable across server restarts.

---

## CMP (RFC 4210 / RFC 9480)

CMP provides certificate lifecycle management (enrolment, renewal, revocation)
using ASN.1/DER-encoded PKIMessage objects over HTTP(S). Endpoints are exposed
under `/pkix/{label}` per RFC 6712.

### Registering a CMP endpoint

`cmp.endpoint.register` binds a URL-safe label to one CA authority, issuance
profile, and protection policy.

| Field | Meaning |
|---|---|
| `label` | URL-safe identifier (1–64 chars, `[A-Za-z0-9._-]+`) |
| `authorityId` | The CA authority to issue from |
| `profileId` | The issuance profile to apply |
| `protectionPolicy` | `SIGNATURE_BASED` or `SHARED_SECRET_MAC` |

### CMP body types

| Body type | Description |
|---|---|
| ir (0) | Initialization Request — server-side key generation; returns ip |
| cr (2) | Certification Request — server-side key generation; returns cp |
| kur (7) | Key Update Request — treated as cr (server-keygen); returns kup |
| rr (11) | Revocation Request — permanently revokes by issuer+serial; returns rp |
| genm (21) | General Message — returns CA chain in genp |

!!! note "Server-side key generation"
    CMP ir and cr use server-side EC P-256 key generation because the CertTemplate
    body is not a self-signed PKCS#10 CSR and cannot satisfy the server's
    proof-of-possession check. The generated private key is currently NOT returned
    to the client in the response (a future phase will add CMS EnvelopedData key
    transport). Clients requiring client-side keys should use EST serverkeygen
    or SCEP.

### CMP transport

All CMP messages use `Content-Type: application/pkixcmp` over HTTP POST.

---

## Enrollment profiles

An enrollment profile is a named policy envelope that sits between an enrollment endpoint (SCEP,
CMP, EST, or ACME) and the certificate issuance engine. Where an endpoint determines *how* a
client communicates, a profile determines *what* the server will accept and issue.

Profiles are created once and referenced by enrollment endpoints and protocol adapters. When a
request arrives, the server resolves the active profile and enforces:

- **Allowed authorities** — the request may only issue from the listed CA authorities (empty means no restriction).
- **Certificate profile** — the issuance profile applied to every certificate issued under this enrollment profile.
- **Subject DN pattern** — an optional regular expression the requested subject DN must satisfy.
- **Required SAN domains** — DNS names that must appear in the certificate's Subject Alternative Name.
- **Approval requirement** — whether a durable human approval must be granted before the certificate is issued.

A profile has two states: `ACTIVE` (accepts new requests) and `SUSPENDED` (rejections only; no new
issuance). Existing in-flight requests are unaffected by suspension.

### Managing enrollment profiles

| Operation | Description |
|---|---|
| `enrollment.profile.register` | Create a new profile |
| `enrollment.profile.update` | Replace the mutable fields of an existing profile |
| `enrollment.profile.inspect` | Show one profile by `id` |
| `enrollment.profile.list` | Page through all registered profiles |
| `enrollment.profile.activate` | Transition a profile from `SUSPENDED` to `ACTIVE` |
| `enrollment.profile.suspend` | Transition a profile from `ACTIVE` to `SUSPENDED` |

### Enrollment profile fields

| Field | Required | Description |
|---|---|---|
| `id` | Yes | Canonical identifier (`[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}`) |
| `displayName` | Yes | Human-readable name |
| `certificateProfileId` | Yes | The certificate profile applied at issuance |
| `allowedAuthorityIds` | No | Set of CA authority IDs permitted to issue; empty means any |
| `subjectDnPattern` | No | Regular expression the subject DN must match |
| `requiredSanDomains` | No | DNS names that must appear in the SAN |
| `requireApproval` | No | `true` if a durable approval is required before issuance (default `false`) |

---

## Related tasks

- The profile and authority a directory issues from: [Profiles and issuance](profiles-and-issuance.md) and [Certificate authorities](authorities.md).
- The client-side enrolment flow: [ACME enrolment](../user/acme-enrollment.md).
