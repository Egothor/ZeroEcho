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
| `enrollmentProfileId` | Required active enrollment profile; it must select the same certificate profile and permit the authority. |
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

## Enrollment profiles and endpoint persistence

ACME directory and EST, SCEP and CMP endpoint registration requires an explicit
`enrollmentProfileId`, distinct from the certificate issuance `profileId`.
Create and activate the enrollment profile before registering its endpoints.
The enrollment profile must select the same certificate profile and permit the
endpoint's authority. A suspended profile prevents enrollment admission.

Enrollment profiles and endpoint bindings are persisted in the server-control
store and validated on startup. Profile registration is create-only; use
`enrollment.profile.update` to replace an existing profile. Deregistering an
endpoint writes a tombstone and preserves the monotonic revision counter.
Registering that label again receives a new revision and commitment; the endpoint
record is not a history of previous bindings. These records are outside the PKI
backup archive; preserve the server-control authority separately.

An active endpoint prevents changes to its enrollment profile that would select
a different certificate profile or exclude its authority. Deregister the affected
endpoints before making such a change, then register their new bindings. Suspending
and reactivating a profile remains possible while endpoints reference it.

Profile subject patterns match the whole subject string using literal text and
`.*` wildcards, with optional outer `^`/`$` anchors and escaped regex punctuation.
General regular expressions, groups, character classes and backreferences are
rejected. Required DNS suffixes are normalized to sorted lowercase ASCII values;
duplicates are rejected. Each configured suffix declares a requirement for a
matching DNS SAN on a label boundary, distinct from an allowlist of every permitted
name. The shared enrollment coordinator checks the subject pattern and every
required DNS suffix before durably admitting a request through the enrollment
protocol adapters.

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
| `enrollmentProfileId` | Required active enrollment profile governing this endpoint |

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

### Enrollment approval and retries

`simpleenroll` and `simplereenroll` use the durable enrollment coordinator. While
approval or issuance is pending, the response is HTTP `202` with the configured
`Retry-After` interval in seconds. Retry the same CSR using the same authenticated
client certificate; the server resumes the retained transaction after restart.
Successful retries return the same issued certificate in a certificates-only CMS
response (HTTP `200`). Rejected requests return `403`, expired requests return
`410`, and a failed issuance returns `500`; these outcomes do not restart issuance.

Renewal checks the supplied CSR against the stored predecessor's identity and
public key and verifies its proof against the frozen certificate profile. A new
request cannot change those values through the renewal endpoint.

### Server-generated keys

`serverkeygen` requires configured `keygenArtifacts` storage and an explicitly
selected EST generator signing credential. The authenticated client's CSR template
must identify that client's TLS certificate encryption key with
`AsymmetricDecryptKeyIdentifier` and offer a supported algorithm in
`SMIMECapabilities`. Recipient key usage must permit the selected RSA key transport
or EC key agreement. Another recipient cannot be substituted.

The server preserves the authorized subject and SANs, ignores the template's
original public-key and signature values, and verifies the newly generated CSR.
It stores only the client-encrypted key package before admitting the request to
approval and signing. Pending requests return `202` with `Retry-After`; retry the
same template with the same authenticated certificate. Retries and restarts retain
the original generated key, generator credential and issuance transaction.

Successful delivery is `multipart/mixed`: a base64
`application/pkcs7-mime; smime-type=server-generated-key` part contains a
generator-signed RFC 5958 key package inside CMS EnvelopedData; the other part is
the certificates-only response. Verify the generator signature and the delivered
key's correspondence with the issued certificate. The configured delivery window
is also bounded by recipient and generator-chain validity. Expired delivery returns
`410`; it does not generate a replacement key. Interrupted generation before
durable attachment leaves a terminal retry record instead of silently regenerating.

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
| `enrollmentProfileId` | Required active enrollment profile governing this endpoint |
| `challengePasswordHash` | SHA-256 hex digest of the SCEP challenge password (64 lower-case hex chars) |

!!! note "Challenge password security"
    Endpoint and control metadata retain only the SHA-256 digest, which is
    compared with the submitted challenge password. Durable enrollment retains
    the exact signed CSR, including its challenge password attribute, in the
    protected PKI request store and its backups. Protect access to those files
    accordingly. Ordinary request inspection and listing omit the raw CSR;
    backup export requires separate permission. Removing that attribute would
    invalidate the original signature.
    Update the endpoint's challenge digest to rotate the password.

### SCEP operations

| Operation | HTTP method | Description |
|---|---|---|
| `GetCACaps` | `GET /scep/{label}?operation=GetCACaps` | Advertises `POSTPKIOperation`, `SHA-256` and `AES` |
| `GetCACert` | `GET /scep/{label}?operation=GetCACert` | Returns the provisioned RA and its issuing CA chain (CMS certs-only) |
| `GetCACertChain` | `GET /scep/{label}?operation=GetCACertChain` | Returns RA + CA chain (CMS certs-only) |
| `PKIOperation` | `GET` or `POST /scep/{label}?operation=PKIOperation` | Enrolment (PKCSReq) and polling (GetCertInitial) |

### Authentication

The server verifies the request's single CMS signature before decrypting it with
the selected RA key. New enrollment also requires the challenge password embedded
in the PKCS#10 CSR attribute `challengePassword` (OID 1.2.840.113549.1.9.7); its
SHA-256 digest must match the endpoint configuration. The CSR proof of possession
and bound enrollment policy must pass before admission. A self-signed requester
certificate proves control of its key, not an independently trusted device identity.

### RA key

Configure an authority-specific SCEP credential set in the enrollment companion
configuration. `GetCACert` and `GetCACertChain` return that RA certificate and its
validated issuing chain with media type `application/x-x509-ca-ra-cert`. Requests
use RSA/SHA-256 signatures and AES-128-CBC encryption addressed to that RA.
Each admitted transaction retains its credential selection across restart and
rollover. Keep every referenced credential set available, including for completed
transactions with retained delivery obligations. Issuance completion alone does
not permit retirement; the current configuration has no credential-retirement
mechanism.

### Pending enrolment

While approval or issuance is pending, the server returns a signed
`pkiStatus=PENDING`. Poll using `GetCertInitial` with the same `transactionID`,
original signer certificate, issuing CA and requested subject. The coordinator
retains the request, decisions and signing correlation across restart. Retrying
the original PKCSReq must preserve the exact CSR. A successful response encrypts
the issued certificate for the original requester; repeated delivery does not
issue another certificate. Rejected, expired and failed transactions return a
signed failure. Each reply echoes the current request's sender nonce; SCEP polls
do not chain response nonces.

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
| `enrollmentProfileId` | Required active enrollment profile governing this endpoint |
| `protectionPolicy` | `SIGNATURE_BASED` or `SHARED_SECRET_MAC` |

### CMP body types

| Body type | Description |
|---|---|
| ir (0) | Initialization Request — verifies the original client CRMF and proof; returns ip |
| cr (2) | Certification Request — verifies the original client CRMF and proof; returns cp |
| kur (7) | Key Update Request — replaces the identified predecessor with the proven new key; returns kup |
| rr (11) | Revocation Request — permanently revokes by issuer+serial; returns rp |
| genm (21) | General Message — returns CA certificates for id-it-caCerts in genp |
| certConf (24) | Confirms the issued certificate hash; returns pkiConf |
| pollReq (25) | Continues the retained enrollment transaction after waiting |

Requests and responses use the endpoint's provisioned signature or PBM protection.
Key update and revocation require the exact certificate owner's signature or an
explicitly authorized, authority-scoped RA. PBM authenticates enrollment and its
continuation; knowledge of its secret grants no ownership of existing certificates.

Approval, polling, certificate delivery and confirmation use durable transaction
state with the original requester, CRMF and credential selection. Exact authenticated
retransmissions of the most recently retained request receive its stored response,
including after restart or active credential rollover. Earlier requests cannot be
replayed after a continuation replaces that response. Continuations must preserve
transaction/request identifiers
and nonce linkage. Explicit confirmation checks the actual issued certificate;
signatures without an implied digest require CMP version 3 with a supported
explicit `hashAlg`. Implicit confirmation is honored when requested and accepted.

### CMP transport

All CMP messages use `Content-Type: application/pkixcmp` over HTTP POST.

---

## Enrollment profiles

An enrollment profile stores policy for an enrollment endpoint separately from
its certificate issuance profile. Durable bindings cover EST, SCEP and CMP
endpoints and ACME directories.

Profiles are created and referenced by enrollment endpoints. The current endpoint
admission checks enforce active state, certificate-profile binding and permitted
authority. The shared enrollment coordinator additionally enforces subject and
DNS SAN requirements before durable request admission. EST enrollment, renewal and
server-keygen, SCEP enrollment, CMP enrollment/key update and ACME finalization use
this coordinator and its durable approval workflow.

- **Allowed authorities** — the request may only issue from the listed CA authorities (empty means no restriction).
- **Certificate profile** — the issuance profile applied to every certificate issued under this enrollment profile.
- **Subject DN pattern** — an optional whole-subject policy pattern using the restricted syntax described above.
- **Required SAN domains** — each configured DNS suffix requires a matching DNS SAN on a label boundary.
- **Approval requirement** — policy selection for the durable human-approval workflow.

A profile has two states: `ACTIVE` permits new admissions and `SUSPENDED` blocks
them. For coordinated requests, the durable dispatch claim is the admission
boundary: suspension blocks later claims, while already claimed work may finish.
Recovery first reconciles the original signing receipt; if signing was definitely
not accepted, a new attempt must pass current policy checks.

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
| `subjectDnPattern` | No | Whole-subject pattern with literal text and `.*` wildcards |
| `requiredSanDomains` | No | Required DNS suffixes, normalized to lowercase ASCII |
| `requireApproval` | No | Requires human approval even when the certificate profile does not (default `false`) |

### Reviewing enrollment requests

The shared workflow exposes separate operations for protocol requests:

| Operation | Purpose |
|---|---|
| `enrollment.request.list` | Read a page of retained requests (nonnegative `offset`, `limit` from 1 to 256) |
| `enrollment.request.inspect` | Inspect the request identified by `id` and obtain its current commitment |
| `enrollment.request.approve` | Approve the inspected `id` with its exact `expectedCommitment` and a `justification` |
| `enrollment.request.reject` | Reject the inspected `id` with its exact `expectedCommitment` and a `justification` |

The server derives the authority and profile from the stored request and checks
the administrator's permissions and eligibility. A stale commitment is rejected;
inspect the request again before making another decision. Provide a reason when
the frozen approval policy requires one, and never include credentials or secrets.
Decisions are persisted before acknowledgement and survive restart.

The requester cannot approve their own enrollment: the server excludes the same
certificate, the same mathematical public key and known administrative aliases.
One key cannot supply multiple votes under different administrator identities.
This separation is mandatory for enrollment even if the generic administrative
approval policy disables requester separation.

Approval permits the protocol workflow to continue; it is not evidence that a
certificate has already been issued. Protocol clients must continue their retry
or polling flow to obtain the retained issuance result.

---

## Related tasks

- The profile and authority a directory issues from: [Profiles and issuance](profiles-and-issuance.md) and [Certificate authorities](authorities.md).
- The client-side enrolment flow: [ACME enrolment](../user/acme-enrollment.md).
