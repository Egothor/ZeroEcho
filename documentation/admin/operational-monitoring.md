# Operational monitoring

This page describes the dashboard metrics that ZeroEcho exposes for operational
monitoring: which operations to call, what each counter means, how permissions
control access, and what to watch for in production.

Metrics are computed on demand from the live store and server runtime. There is
no separate scraping agent; the same administrative HTTPS transport and RBAC
model that governs every other operation governs metric reads. Each of the five
dashboard operations is independently authorisable so that a CA-level operator
who should see certificate counts does not automatically gain server-health
visibility, and vice versa.

## Operations at a glance

| Operation | Stable name | Required action | Scope |
|---|---|---|---|
| [Authority inventory](#authority-inventory) | `dashboard.authority` | `AUTHORITY_READ` | per-CA |
| [Certificate lifecycle](#certificate-lifecycle) | `dashboard.certificate` | `CERTIFICATE_SEARCH` | per-CA |
| [Revocation and CRL health](#revocation-and-crl-health) | `dashboard.revocation` | `REVOCATION_HISTORY_READ` | per-CA |
| [Publication health](#publication-health) | `dashboard.publication` | `PUBLICATION_READ` | per-CA |
| [Server health](#server-health) | `dashboard.server` | `SERVER_HEALTH_READ` | realm-wide |

A dashboard that combines all five calls each operation separately and displays
whichever sections the authenticated caller is authorised to read.

---

## Authority inventory

**Operation:** `dashboard.authority`  
**Required permission:** `AUTHORITY_READ` on `AUTHORITY` in the target CA's scope

Returns the operational posture of one certificate authority.

| Field | Type | Description |
|---|---|---|
| `caId` | string | CA identifier, echoed from the request |
| `caState` | string | Current persisted authority state |
| `issuerGenerationsTotal` | integer | Total issuer generations ever created for this CA |
| `issuerGenerationsActive` | integer | Issuer generations currently in `ACTIVE` state |
| `issuanceChainDepth` | integer | Number of certificates in the current active chain path (leaf to anchor); `0` if no path is selected |
| `computedAt` | string | ISO-8601 instant at which this snapshot was taken |

**Alerting guidance.** A CA outside its permitted issuing state will not issue
credentials. `issuerGenerationsActive` below one means no generation is
active for signing. `issuanceChainDepth` of zero means no chain path is selected and
issuance will fail.

---

## Certificate lifecycle

**Operation:** `dashboard.certificate`  
**Required permission:** `CERTIFICATE_SEARCH` on `CERTIFICATE` in the target CA's scope

Counts credentials issued by one CA across their full lifecycle. The full
credential population is scanned on each call; the scan is capped at
100 000 entries and `countCapped: true` is returned if the cap is hit.

| Field | Type | Description |
|---|---|---|
| `caId` | string | CA identifier, echoed from the request |
| `certificatesTotal` | integer | Credentials scanned across all lifecycle states |
| `activeTotal` | integer | Credentials with status `ISSUED` and `notAfter` in the future at `computedAt` |
| `expiring7dTotal` | integer | Active credentials whose `notAfter` falls within the next 7 days |
| `expiring30dTotal` | integer | Active credentials whose `notAfter` falls within the next 30 days |
| `expiring90dTotal` | integer | Active credentials whose `notAfter` falls within the next 90 days |
| `revokedTotal` | integer | Credentials with persisted `REVOKED` status |
| `expiredTotal` | integer | Credentials marked `EXPIRED`, or `ISSUED` with `notAfter` at or before `computedAt` |
| `metricStates.pendingRequestsTotal` | object | `UNAVAILABLE`, reason `CA_REQUEST_LIFECYCLE_UNAVAILABLE`; no numeric count is emitted because requests have no authoritative CA lifecycle binding |
| `countCapped` | boolean | `true` when the scan stopped at the 100 000-entry cap; counts are partial |
| `computedAt` | string | ISO-8601 instant at which this snapshot was taken |

**Alerting guidance.** Watch `expiring7dTotal` for imminent expirations that have not
been renewed or rekeyed. When `countCapped` is
`true`, the absolute counts are a lower bound; investigate whether the CA has
grown beyond the designed scale.

---

## Revocation and CRL health

**Operation:** `dashboard.revocation`  
**Required permission:** `REVOCATION_HISTORY_READ` on `REVOCATION` in the target CA's scope

Provides revocation counts and the health of the most recently generated CRL.

| Field | Type | Description |
|---|---|---|
| `caId` | string | CA identifier, echoed from the request |
| `revokedTotal` | integer | Credentials with a permanent revocation record (REVOKED state) |
| `crlLastGeneratedEpoch` | integer or absent | Unix epoch seconds of the most recent successful CRL generation; absent if no CRL has ever been generated |
| `crlNextUpdateEpoch` | integer or absent | Unix epoch seconds of the `nextUpdate` field in the current CRL |
| `crlFreshnessSeconds` | integer or absent | Age of the most recent CRL (`now − thisUpdate`); absent when no CRL exists |
| `crlSizeBytes` | integer or absent | Byte length of the current CRL object |
| `computedAt` | string | ISO-8601 instant at which this snapshot was taken |

**Alerting guidance.** Compare `crlNextUpdateEpoch` with the current time to detect
expiry. Alert before that deadline; `crlFreshnessSeconds` measures age, not remaining validity. `revokedTotal`
growing faster than issuance can indicate a policy or key-compromise event.

---

## Publication health

**Operation:** `dashboard.publication`  
**Required permission:** `PUBLICATION_READ` on `PUBLICATION` in the target CA's scope

Reports the state of the publication pipeline for one CA: CRL freshness
(from the perspective of the most recent *generated* CRL, not its published
copies) and the count of publication operations in pending or failed states.

| Field | Type | Description |
|---|---|---|
| `caId` | string | CA identifier, echoed from the request |
| `crlLastGeneratedEpoch` | integer or absent | Unix epoch seconds of the most recent CRL generation |
| `crlNextUpdateEpoch` | integer or absent | Unix epoch seconds of the current CRL's `nextUpdate` |
| `publicationsPendingTotal` | integer | Publication operations for this CA in `PENDING` state |
| `publicationsTerminalFailureTotal` | integer | Publication operations for this CA in `TERMINAL_FAILURE` state |
| `computedAt` | string | ISO-8601 instant at which this snapshot was taken |

Counts are scoped through the authoritative source object: a status object's issuer
CA, or a credential's issuer reference. Missing source objects are excluded.
These counts do not include retryable or uncertain outcomes; inspect publication
records for those states.

**Alerting guidance.** A non-zero `publicationsTerminalFailureTotal` requires operator
attention: terminal failures will not retry automatically. Use
`publication.list` to identify the affected operations and
`publication.reconcile` or `publication.retry` to recover them.

---

## Server health

**Operation:** `dashboard.server`  
**Required permission:** `SERVER_HEALTH_READ` on `SERVER_CONFIGURATION` (realm-scoped)

Returns realm-wide server runtime indicators. This operation carries no
`caId` argument.

| Field | Type | Description |
|---|---|---|
| `approvalPendingTotal` | integer | Unexpired approval requests currently in `PENDING` state across all CAs |
| `auditProjectionFailureTotal` | integer | Consecutive projection-worker failures summed across all active audit projectors; a persistent non-zero value means audit delivery is degraded |
| `jvmHeapUsedBytes` | integer | JVM heap memory in use at the sampling instant |
| `statusScheduleFailureTotal` | integer or absent | Process-local failed scheduling attempts and newly observed failed execution transitions; repeated observation of one durable failure does not increment it |
| `statusScheduleWorkerRunning` | integer or absent | `1` while the configured scheduling worker is running, otherwise `0` |
| `metricStates` | object | Per-measurement `AVAILABLE`, `UNAVAILABLE`, or `FAILED` state, with a safe reason code when no value is available |
| `adminRequestsTotal` | integer | Monotonic count on entry to the `/admin/` HTTP handler, including authentication, validation, and admission rejections; excludes health endpoints and failures before HTTP handler entry; resets on restart |
| `computedAt` | string | ISO-8601 instant at which this snapshot was taken |

Numeric server measurements are present only when available. A measured zero is
valid; an unavailable or failed measurement has no numeric field. The library's
unconfigured live source reports `UNAVAILABLE/NOT_CONFIGURED`. Collection failure
is isolated per measurement and reports `FAILED/COLLECTION_FAILED`. Existing
four-getter live-source implementations remain supported.

**Alerting guidance.** A non-zero `auditProjectionFailureTotal` that does not
return to zero between polls indicates that the audit feed is not being
projected; investigate the server log for the root cause. A sustained high
`approvalPendingTotal` may mean approvers are unresponsive or the approval
notification path is broken. Monitor `jvmHeapUsedBytes` relative to the
configured heap ceiling; if it approaches saturation, the server will begin
GC-pausing and eventually fail.

---

## Using dashboard operations from the command line

All five operations are available through remote `zeroecho pki`. These examples
require the named client identity, server trust anchor and a permitted principal:

```sh
# Authority inventory for CA "root-ca"
zeroecho pki dashboard.authority --authority-id root-ca --ca-id root-ca \
  --url https://pki.example.com:8443 --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem

# Certificate lifecycle counts
zeroecho pki dashboard.certificate --authority-id root-ca --ca-id root-ca \
  --url https://pki.example.com:8443 --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem

# Revocation and CRL health
zeroecho pki dashboard.revocation --authority-id root-ca --ca-id root-ca \
  --url https://pki.example.com:8443 --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem

# Publication pipeline health
zeroecho pki dashboard.publication --authority-id root-ca --ca-id root-ca \
  --url https://pki.example.com:8443 --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem

# Server health (no authority argument)
zeroecho pki dashboard.server \
  --url https://pki.example.com:8443 --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem
```

See [Administering from the command line](command-line.md) for connection and
authentication setup.

---

## Authorization design

Each dashboard operation is an independent read and enforces its own minimum
permission. A principal that holds only `CERTIFICATE_SEARCH` can read
certificate lifecycle counts but cannot read revocation history or server
health. Assign permissions at the lowest granularity that satisfies the
monitoring role:

| Role pattern | Suggested actions |
|---|---|
| CA-level certificate operator | `AUTHORITY_READ`, `CERTIFICATE_SEARCH` |
| CA-level revocation operator | `REVOCATION_HISTORY_READ`, `PUBLICATION_READ` |
| Server operator | `SERVER_HEALTH_READ` |
| Full monitoring (read-only) | all five actions above |

The `CERTIFICATE_READ_PII` action is not required by any dashboard operation;
metrics expose counts and timestamps only, never subject identity data.
