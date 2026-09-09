# Administrative HTTP API

The ZeroEcho PKI server exposes a small, strict, JSON-over-mutual-TLS API for all
administrative work. Every certificate-authority action — creating authorities,
issuing and revoking certificates, generating status objects, managing
principals, roles, grants, approvals, and publication — is expressed as a single
*operation* invoked through one uniform request/response envelope.

This page is the wire reference for that API. For the command-line client that
speaks it, see the [CLI reference](cli-reference.md); for the file that
configures the listeners, see the [configuration reference](configuration-reference.md);
for the authorization rules that every request is subject to, see the
[security model](security-model.md).

!!! info "Transport is always mutual TLS"
    The administrative listener requires a client certificate on every
    connection. There are no cookies, sessions, tokens, or login endpoints — the
    server authenticates and authorizes each request on its own merits. See
    [Authentication](#authentication) below and the
    [security model](security-model.md).

## Base conventions

| Property | Value |
| --- | --- |
| Scheme | `https` only, with client-certificate authentication |
| Request media type (POST) | `application/json` |
| Response media type | `application/json; charset=utf-8` |
| Correlation header | `X-ZeroEcho-Request-Id` (optional on request, always echoed on response) |
| Caching | Responses are sent with `Cache-Control: no-store` |
| API prefix | `/admin/v1/` |

If you supply `X-ZeroEcho-Request-Id`, it must be 16–128 characters from the set
`[A-Za-z0-9_-]`; otherwise the server generates one. The same value is returned
on the response and recorded in the audit trail, so it is the recommended way to
correlate a client action with server-side events.

## The operation-execution model

Every mutating or read operation is addressed the same way:

```
POST /admin/v1/operations/{operationId}
Content-Type: application/json
```

The `{operationId}` is a stable dotted identifier (for example
`certificate.issue` or `authority.create`); it must match the pattern
`[a-z][a-z0-9.]{2,127}`. Discover the exact identifiers your principal may use
with [`GET /admin/v1/operations`](#discovery).

### Request envelope

```json
{
  "version": 1,
  "authorityId": "issuing-ca-1",
  "approvalId": "apr-7f3a9c21",
  "deadline": "PT30S",
  "arguments": { }
}
```

| Field | Required | Description |
| --- | --- | --- |
| `version` | yes | Envelope version. Must be `1`. |
| `authorityId` | conditional | The logical authority the operation is scoped to. Required for authority-scoped operations and **must be omitted** for realm-wide operations (for example `authority.list`, `request.import`). |
| `approvalId` | no | A prior approval record identity, supplied when re-submitting an operation that required dual control (see [Dual control](#dual-control-409-approval_required)). |
| `deadline` | no | An ISO-8601 *duration* (for example `PT30S`) bounding server-side execution. The server caps it at its configured maximum and applies its default when omitted. |
| `arguments` | yes | A JSON object holding the operation's typed arguments. The accepted keys depend on the operation. |

!!! warning "Strict decoding"
    The server rejects unknown envelope fields, unknown argument keys, wrong
    value types, and non-canonical values. A malformed body yields
    `400` with code `INVALID_OPERATION_REQUEST` (or `MALFORMED_REQUEST`); an
    oversized body yields `413`; a missing or wrong `Content-Type` yields `415`.

### Response envelope

Every response — success or failure — is the same shape:

```json
{
  "version": 1,
  "requestId": "V5v9k2v0t1n3...",
  "operation": "certificate.issue",
  "status": "SUCCEEDED",
  "result": { },
  "failure": null
}
```

| Field | Description |
| --- | --- |
| `version` | Always `1`. |
| `requestId` | The correlation identity for this exchange (see above). |
| `operation` | The operation identifier this response belongs to. |
| `status` | One of `SUCCEEDED`, `PENDING`, `FAILED`, `APPROVAL_REQUIRED`. |
| `result` | The operation's structured result object on success, or a small object on `PENDING`/`APPROVAL_REQUIRED`; `null` on `FAILED`. |
| `failure` | A failure detail object when `status` is `FAILED` (and on `APPROVAL_REQUIRED`); otherwise `null`. |

The `failure` object carries a safe, stable classification that never leaks the
existence of protected objects:

```json
{
  "classification": "POLICY_REJECTION",
  "code": "POLICY_REJECTION",
  "messageKey": "POLICY_REJECTION",
  "recoveryRequired": false,
  "reconciliationRequired": false
}
```

### Status values

| `status` | Meaning | Typical HTTP status |
| --- | --- | --- |
| `SUCCEEDED` | The operation completed and `result` holds its output. | `200` |
| `PENDING` | The operation was accepted but its outcome (a signature) is not yet known. See [the pending hand-off](#the-pending-hand-off-202). | `202` |
| `APPROVAL_REQUIRED` | The operation needs dual-control approval before it can run. See [Dual control](#dual-control-409-approval_required). | `409` |
| `FAILED` | The operation did not complete; `failure` explains why. | `4xx`/`5xx` |

### Failure classification to HTTP status

For a `FAILED` outcome the HTTP status is derived from the failure
classification:

| Classification | HTTP status |
| --- | --- |
| `VALIDATION_FAILURE` | `400` |
| `POLICY_REJECTION` | `422` |
| `NOT_FOUND` | `404` |
| `CONFLICT` | `409` |
| `EXTERNAL_OUTCOME_UNKNOWN` | `409` |
| `OVERLOADED` | `429` |
| `RECOVERY_REQUIRED`, `RESOURCE_FAILURE` | `503` |
| `CANCELLED` (deadline) | `504` |
| `INTERNAL_FAILURE` | `500` |

Transport-level rejections that happen before or around execution use their own
codes: `401 CLIENT_AUTHENTICATION_FAILED`, `403 AUTHORIZATION_DENIED`,
`404 OPERATION_NOT_FOUND`, `405 METHOD_NOT_ALLOWED`,
`413 REQUEST_BODY_REJECTED`, `415 UNSUPPORTED_MEDIA_TYPE`,
`429 ADMISSION_REJECTED` / `OPERATION_QUEUE_FULL`, and
`504 DEADLINE_EXCEEDED`.

!!! note "Denied looks like not-found where it must"
    Where revealing a decision would disclose the existence of an object the
    caller may not see, the server returns `404 OPERATION_NOT_FOUND` rather than
    `403`. Discovery (`GET /admin/v1/operations/{id}`) likewise returns `404` for
    operations the caller cannot use.

## The pending hand-off (202)

Some operations require a signature that is produced asynchronously (for example
by a remote or rate-limited signing service). When the signature is not
immediately available the server responds:

```
HTTP/1.1 202 Accepted
Location: /admin/v1/signing-operations/{id}
```

```json
{
  "version": 1,
  "requestId": "…",
  "operation": "certificate.issue",
  "status": "PENDING",
  "result": { "operationId": "sig-000987" },
  "failure": null
}
```

Poll the signing operation until it terminalizes:

```
GET /admin/v1/signing-operations/{id}
```

The poll returns the same response envelope. It resolves to `SUCCEEDED` (with the
final result), to a `FAILED` classification, or continues to report `PENDING`.
Access to a signing operation is authorized against the same action and resource
as the operation that created it, so a caller can only observe a hand-off they
were entitled to start.

## Dual control (409, `APPROVAL_REQUIRED`)

When an operation is subject to an approval policy (for example authority
creation, or a revocation whose authorizing grant is conditioned on approval),
the first submission — made without an `approvalId` — is answered:

```
HTTP/1.1 409 Conflict
```

```json
{
  "version": 1,
  "requestId": "…",
  "operation": "authority.create",
  "status": "APPROVAL_REQUIRED",
  "result": { "operationCommitment": "9f2c…" },
  "failure": { "classification": "APPROVAL_REQUIRED", "code": "APPROVAL_REQUIRED", "…": "…" }
}
```

The `operationCommitment` is a deterministic digest that binds the exact
operation, its arguments, and its scope. Use it to raise an approval request
(`approval.request`), have the required approvers decide it (`approval.decide`),
and then re-submit the **identical** operation with the resulting `approvalId` in
the envelope. The server re-verifies that the approval binds precisely the
operation being executed before it runs. See
[Approvals and separation of duties](security-model.md#approvals-and-separation-of-duties).

## Discovery

Operations and their security metadata are self-describing.

`GET /admin/v1/operations` lists every operation the calling principal may
discover:

```json
{
  "version": 1,
  "requestId": "…",
  "operation": "operation.list",
  "status": "SUCCEEDED",
  "result": {
    "count": 2,
    "operations": [
      {
        "operation": "certificate.issue",
        "family": "PKI_OPERATION",
        "mutating": true,
        "resourceType": "CERTIFICATE",
        "approval": "NONE",
        "dataView": "METADATA_REDACTED"
      }
    ]
  }
}
```

`GET /admin/v1/operations/{id}` returns the single descriptor for one operation,
or `404` if the caller cannot use it. The `family` is `PKI_OPERATION` or
`SERVER_CONTROL_OPERATION`; `approval` is `NONE`, `HIGH_RISK`,
`ISSUANCE_SINGLE`, or `ISSUANCE_THRESHOLD`; `dataView` is one of the
[data-view levels](security-model.md#data-view-redaction).

## Realm information

`GET /admin/v1/realm` returns the identity and exposure policy of the realm this
server instance serves:

```json
{
  "version": 1,
  "requestId": "…",
  "operation": "realm.inspect",
  "status": "SUCCEEDED",
  "result": {
    "realmId": "production",
    "displayName": "ZeroEcho Production",
    "authorityExposure": "ALL_REALM_AUTHORITIES",
    "authorityCreationPermitted": false
  }
}
```

## Health endpoints

Two unauthenticated-shape probes live outside the operation model (they are still
served over the same TLS listener):

| Route | Method | Success | Body |
| --- | --- | --- | --- |
| `/health/live` | `GET` | `200` | `{ "state": "LIVE" }` |
| `/health/ready` | `GET` | `200` / `503` | `{ "state": "READY" }` / `{ "state": "NOT_READY" }` |

`/health/live` reports that the process is running; `/health/ready` reports
whether the realm has finished starting and is accepting operations.

## Main administrative routes

| Route | Method(s) | Purpose |
| --- | --- | --- |
| `/health/live` | `GET` | Liveness probe |
| `/health/ready` | `GET` | Readiness probe |
| `/admin/v1/realm` | `GET` | Realm identity and exposure policy |
| `/admin/v1/operations` | `GET` | List discoverable operations |
| `/admin/v1/operations/{id}` | `GET` | Inspect one operation descriptor |
| `/admin/v1/operations/{id}` | `POST` | Execute one operation |
| `/admin/v1/signing-operations/{id}` | `GET` | Poll a pending signing hand-off |

## Authentication

The administrative listener accepts a client certificate on every request and
maps it to a server principal. Two deployment modes are supported, selected in
[configuration](configuration-reference.md#administrative-authentication):

- **`DIRECT_MTLS`** — the server terminates TLS and maps the TLS peer
  certificate directly. Forwarded-identity headers are refused
  (`400 FORWARDED_IDENTITY_FORBIDDEN`).
- **`TRUSTED_REVERSE_PROXY`** — an authenticated proxy terminates the browser or
  client TLS and forwards the validated client certificate to the server in a
  configured header, using the RFC 9440 (`Client-Cert` / `Client-Cert-Chain`) or
  an NGINX escaped-PEM representation. The proxy's own transport certificate is
  independently authenticated and must belong to the trusted-proxy principal set.

In both modes the mapped principal is subject to the full authorization engine on
every request; see the [security model](security-model.md).

## Public repository endpoints

The read-only public repository is served on a **separate listener** with its own
bounds and its own optional-client authentication. Its routes live under
`/public/v1/` and support `GET` and `HEAD` only. Responses carry `ETag` and honor
`If-None-Match` (`304 Not Modified`), and use `Cache-Control` classes appropriate
to whether the object is immutable content, a stable alias, or private.

| Route | Purpose |
| --- | --- |
| `/public/v1/authorities` | List exposed authorities (when enabled) |
| `/public/v1/authorities/{authorityId}` | Authority metadata |
| `/public/v1/authorities/{authorityId}/chain` | Current issuer chain |
| `/public/v1/authorities/{authorityId}/crl` | Current CRL |
| `/public/v1/authorities/{authorityId}/delta-crl` | Current delta CRL |
| `/public/v1/authorities/{authorityId}/issuers/{issuerId}/certificate` | An issuer certificate |
| `/public/v1/authorities/{authorityId}/issuers/{issuerId}/paths/{pathId}` | A specific chain path |
| `/public/v1/certificates/{credentialId}` | An issued certificate |
| `/public/v1/status/{statusObjectId}` | A status object |

Non-public objects may be retrieved with a bearer *capability* credential
(`Authorization: Bearer cap-…`) issued through the admin API; cookies are refused
outright. Objects the caller may not see return `404 RESOURCE_UNAVAILABLE`, never
a disclosure of existence.

## Validation and revocation protocol listeners

Two standards-based protocol listeners are exposed at a high level for relying
parties and enrollment clients. They are not part of the JSON operation API.

=== "OCSP (RFC 6960)"

    Served per responder alias on the public listener:

    - `POST /ocsp/{alias}` with `Content-Type: application/ocsp-request`
    - `GET /ocsp/{alias}/{base64url-request}`

    Responses use `application/ocsp-response`. Nonce, request-signature, and
    requester-authorization policy are configured per responder; unsuccessful
    responses use the standard OCSP response-status values (for example
    *malformedRequest*, *tryLater*, *sigRequired*, *unauthorized*). Cacheable
    responses carry `ETag`, `Expires`, and `Cache-Control`.

=== "ACME (RFC 8555)"

    Served per directory alias on the ACME listener, under `/acme/{alias}/`:

    - `GET /acme/{alias}/directory`
    - `GET`/`HEAD /acme/{alias}/new-nonce`
    - `POST /acme/{alias}/new-account`, `new-order`, `key-change`, `revoke-cert`
    - `POST /acme/{alias}/account/{id}`, `order/{id}`, `authz/{id}`,
      `challenge/{id}`, `finalize/{id}`, `certificate/{id}`

    All non-directory, non-nonce requests are JWS-signed (`application/jose+json`)
    and answered with `application/json` or, on error, `application/problem+json`;
    the issued chain is returned as `application/pem-certificate-chain`. Every
    response carries a fresh `Replay-Nonce`.

See the administrator guide for enabling and configuring these listeners.
