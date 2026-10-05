# Publication

Publication distributes PKI artefacts — issued certificates and status objects
(CRLs and delta CRLs) — to external repositories, and maintains stable
**repository aliases** that always resolve to an authority's current CRL, delta
CRL, or chain. This page covers registering and driving publications through their
lifecycle and managing aliases.

Publications are managed under **Publication**; aliases under **Repository
Aliases**.

## The publications table

The **Publication** area lists publication records in the realm
(`publication.list`), showing each record's source type and state. Each row offers
the process, retry, and reconcile actions below, plus **Inspect publication**
(`publication.inspect`). Register new publications with the create flow.

## Registering a publication

**Register publication** (`publication.register`) records the intent to publish one
source artefact to one target. Complete:

| Field | Meaning |
|---|---|
| `publicationId` | The identifier for this publication record. |
| `sourceType` | What is being published — `CREDENTIAL` or `STATUS_OBJECT`. |
| `sourceId` | The identifier of the credential or status object. |
| `targetType` | Where it goes — `FILESYSTEM`, `LDAP`, `HTTP`, or `OBJECT_STORE`. |
| `targetId` | The target-specific location within that repository. |

Registering does not itself deliver the artefact; it creates a record you then
process.

## Driving a publication through its lifecycle

Three operations move a publication record toward a delivered state. Each takes
the `publicationId` and acts within the owning authority.

| Operation | Id | When to use |
|---|---|---|
| **Process publication** | `publication.process` | Deliver a pending publication to its target. |
| **Retry publication** | `publication.retry` | Retry a publication that previously failed. |
| **Reconcile publication** | `publication.reconcile` | Reconcile a record whose delivered state may have drifted from what the target actually holds. |

=== "Process"

    Select *Process publication* on a pending row. The artefact is delivered to
    the configured target.

=== "Retry"

    If a publication failed (the outcome carried a failure classification, and
    possibly a *reconciliation required* flag), select *Retry publication* to
    attempt delivery again.

=== "Reconcile"

    Select *Reconcile publication* to bring the record back into agreement with
    the target — for example after an out-of-band change or a partial failure.

!!! note "Failures tell you what is needed"
    A failed operation's outcome indicates whether **recovery** or
    **reconciliation** is required. Use retry for transient delivery failures and
    reconcile when the record and the target may disagree.

## Repository aliases

A repository alias is a stable, named route that always resolves to an authority's
*current* artefact, so relying parties can fetch a fixed location and always
receive the latest object. There are three alias types:

| Alias type | Resolves to |
|---|---|
| `CURRENT_CRL` | The authority's current full CRL. |
| `CURRENT_DELTA_CRL` | The authority's current delta CRL. |
| `CURRENT_CHAIN` | The authority's current certificate chain. |

Aliases are managed under **Repository Aliases**, which lists aliases across the
realm (`repository.alias.list`).

- **Set repository alias** (`repository.alias.set`) — point an alias at a target
  object. Complete the `authorityId`, the alias `type`, the `targetObjectId`, and
  optionally the `issuerId`. To guard against a lost update you may supply
  `expectedCurrentCommitment`, which the server checks against the alias's current
  value before changing it. This operation is high-risk and requires approval.
- **Remove repository alias** (`repository.alias.remove`) — remove an alias.
  Supply the `authorityId`, the `type`, and the `expectedCurrentCommitment`.
  High-risk; requires approval.
- **Inspect repository alias** (`repository.alias.inspect`) — show the current
  target of an alias for an `authorityId` and `type`.

!!! tip "Update aliases after every rollover and CRL generation"
    Whenever you [roll over or rotate](authorities.md#certificate-rollover-and-key-rotation)
    an authority, or generate a fresh [CRL or delta](revocation-and-status.md#crls-and-delta-crls),
    update the corresponding alias so downstream consumers pick up the new object
    without reconfiguration. The optimistic `expectedCurrentCommitment` check lets
    you do this safely under concurrent administration.

## Publisher endpoint configuration

Publisher endpoints are deployment configuration — they are defined in the server
configuration file and require a restart to change. There is no lifecycle API for
endpoints.

### Filesystem publisher

The built-in filesystem publisher (`id: "filesystem"`) writes artefacts as
files under an administrator-controlled directory:

```json
{
  "id": "filesystem",
  "properties": {
    "root": "/var/lib/zeroecho/artifacts",
    "targetId": "crl-distribution"
  }
}
```

### HTTPS publisher

The HTTPS publisher (`id: "https"`) delivers artefacts to a remote HTTPS
endpoint using HTTP PUT (default) or POST. It is the standard publisher for
network-attached distribution points.

```json
{
  "id": "https",
  "properties": {
    "url": "https://crl.example.com/update",
    "targetId": "crl-distribution",
    "credentials": "keyring:crl-endpoint-token",
    "method": "PUT"
  }
}
```

These JSON objects are provider fragments for the server configuration's
`realm.pkiSession.publishers` list. The separate local CLI wrapper uses `provider`
instead of `id`. The `credentials` value is the verbatim HTTP `Authorization` header sent with each
request (e.g. `Bearer <token>` or `Basic <base64>`). Use a secret reference
prefix — never a plaintext value — in the configuration file:

| Prefix | Resolution |
|---|---|
| `keyring:<id>` | Looks up `<id>` in the encrypted publisher secrets store. |
| `env:<VAR>` | Reads the named environment variable at startup. |
| `dev-plaintext:<val>` | Uses the literal value. **UNSAFE — development only.** |

### Publisher secrets store

When `keyring:` references are used, the server needs a secrets store configured in
`runtime`:

```json
"runtime": {
  "publisherSecretsStore": "/var/lib/zeroecho/publisher-secrets.pss",
  "publisherSecretsEnvironmentVariable": "ZEROECHO_PUBLISHER_SECRETS_PASSWORD"
}
```

The store is an AES-256-GCM encrypted JSON file with three available protection
profiles:

| Profile | Recipients | When to use |
|---|---|---|
| `CLASSIC` | PBKDF2-HMAC-SHA256 password only | Password-based creation and unlocking. |
| `PQC` | BIKE-256 KEM only | KEM-based decryption via BIKE private key. |
| `HYBRID` | Password + BIKE-256 KEM | Create with both recipients; unlock independently with either. |

The HYBRID envelope has independent password and BIKE recipients; it does not
require both to decrypt, so the password also determines its protection. Password
recipients retain 600,000 PBKDF2 iterations. Creation and password unlocking use
that same upper bound, with the library's minimum enforced on decoded counts.
No iteration override is exposed. Use `--password-env VAR` when writing CLASSIC
or HYBRID and when verifying with a password. HYBRID writing also requires
`--bike-pub`; BIKE verification uses `--bike-priv` without a password option.
The PQC example below does not establish automatic server startup support for a
BIKE-only secrets store; server startup uses its configured password source.

**Creating and managing the store** — use `zeroecho-pki-publisher-secrets`:

```bash
# 1. Generate a BIKE-256 key pair for the PQC profile.
zeroecho-pki-publisher-secrets generate-bike-key \
  --pub /secure/bike-pub.der \
  --priv /secure/bike-priv.der

# 2. Prepare a plaintext secrets JSON (keep on secure storage; delete after use).
umask 077
echo '{"crl-endpoint-token": "replace-with-endpoint-credential"}' > /secure/secrets.json

# 3. Write the encrypted store with the PQC recipient path.
zeroecho-pki-publisher-secrets write-store \
  --store /var/lib/zeroecho/publisher-secrets.pss \
  --secrets /secure/secrets.json \
  --protection PQC \
  --bike-pub /secure/bike-pub.der

# 4. Verify the store decrypts correctly.
zeroecho-pki-publisher-secrets verify-store \
  --store /var/lib/zeroecho/publisher-secrets.pss \
  --bike-priv /secure/bike-priv.der

# 5. Remove the plaintext through your protected storage's cleanup procedure.
```

!!! danger "Protect the BIKE private key"
    The BIKE private key unlocks the encrypted store independently of the password.
    Store it on HSM or filesystem paths accessible only to the PKI operator account.
    Never commit it to version control.

!!! warning "Development and debug use only"
    The `--publisher-secrets-dev-password` flag exposes the store password in the
    process argument list and system logs. It is visible to all users on the system
    and **must never be used in production**.

## Related tasks

- Generate the status objects you publish: [Revocation and status](revocation-and-status.md).
- Control who may see a published object: [Audit and disclosure](audit-and-disclosure.md#disclosure-policies).
- The public-facing view of published artefacts is the **Public Repository** area
  and is described for end users in [Accessing the platform](../user/accessing.md).
