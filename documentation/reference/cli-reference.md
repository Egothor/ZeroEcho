# Command-line reference

Examples use `zeroecho` as a shell shorthand for the built CLI. From the repository
root, build and define it before running commands:

```bash
./gradlew :app:installDist
zeroecho() { ./app/build/install/app/bin/app "$@"; }
```

An installation may provide its own wrapper; the Gradle launcher is named `app`.
The server distribution instead provides `zeroecho-pki-server` under
`pki-server/build/install/zeroecho-pki-server/bin/`.

The `zeroecho pki` utility runs certificate-authority operations from the command
line. It has two modes, selected purely by the parameters you pass:

- **Local mode** runs operations *in-process* against a local store described by a
  configuration file (`--config`). No server is involved.
- **Remote mode** runs a single operation against a running server's
  [administrative API](admin-api.md) over mutual TLS, selected when you supply a
  server URL together with client-connection certificate material.

Both modes map to the same stable process [exit codes](#exit-codes), so a caller
cannot observe a difference in exit semantics between them.

!!! info "Mode selection in one sentence"
    Supplying `--url` **together with** client-certificate material selects remote
    mode; otherwise the utility runs local, in-process mode against `--config`.

## Synopsis

```text
zeroecho pki <operation> --config <file> [--output human|json] [arguments]
zeroecho pki run <plan-file> --config <file> [--output human|json]

zeroecho pki <operation.id> --url <https-base-url>
    ( --client-keystore <p12> [--client-keystore-password-env <ENV>]
    | --client-cert <pem> --client-key <pem> )
    [--trust <p12|pem> [--trust-password-env <ENV>]]
    [--authority-id <id>] [--approval-id <id>] [--deadline <ISO-8601>]
    [--output human|json] [--pending-wait <seconds>]
    [--arg name=value | --arg-int name=value | --arg-bool name=true|false | --option value]...
```

## Common options

| Option | Applies to | Description |
| --- | --- | --- |
| `--output human\|json` | both | Output rendering. Defaults to `human`. |
| `--pending-wait <seconds>` | remote submission only | Bounded wait (default `3`, range `0`–`3600`) for an asynchronously-signed operation to finish before a pending exit (code `7`). Invalid locally and for explicit remote inspection. |
| `--help`, `-h` | both | Print usage and the local operation catalog. |

## Local mode

Local mode opens the backend described by `--config` and executes either one
operation or a sequential plan.

- `zeroecho pki <operation> --config <file> [arguments]` runs one typed operation.
  Arguments are given as `--option value` pairs (for example
  `--credential-id …`). Numeric arguments such as `--limit` and
  `--profile-version` are parsed as integers.
- `zeroecho pki run <plan-file> --config <file>` runs a sequential plan of steps
  from a plan file.

The `--config` file is a strict versioned JSON document describing the local
store, audit sink, and (optionally) signing, publishers, and binding providers.
It is distinct from the server configuration; see the
[configuration reference](configuration-reference.md) for the server file.

```json
{
  "version": 1,
  "mode": "local",
  "operatorId": "local-admin",
  "store":  { "provider": "fs",     "properties": { "root": "state/pki" } },
  "audit":  { "provider": "memory", "properties": { "size": "512" } },
  "publishers": [],
  "bindingProviders": []
}
```

!!! note
    In the local CLI configuration each provider block uses the key `provider`
    (the server configuration file uses `id`). The audit provider may not be
    `stdout`. This example uses an in-memory audit sink. The CLI wrapper is version
    1; the backend session contract is version 6 and server configuration is version 8.

Run `zeroecho pki --help` for the full catalog of local typed operations, which
includes `ca.*`, `credential.*`, `profile.*`, `request.*`, `revocation.*`,
`status.*`, `publication.*`, `issuer.*`, and `algorithm.binding.*` families.

## Remote mode

Remote mode connects to a running server's admin API and executes exactly **one**
operation (the `run` batch form is not available remotely). It presents the
client TLS certificate directly (the server uses `DIRECT_MTLS` for this client);
no forwarded-identity headers are involved.

The client identity is supplied **either** as a PKCS#12 keystore **or** as a PEM
certificate-and-key pair — never both:

| Option | Description |
| --- | --- |
| `--url <https-base-url>` | Absolute `https` base URL of the server admin API. Required for remote mode. |
| `--client-keystore <p12>` | PKCS#12 holding the client certificate and private key. |
| `--client-keystore-password-env <ENV>` | Name of the environment variable holding the keystore password. |
| `--client-cert <pem>` | PEM client certificate chain (used with `--client-key`). |
| `--client-key <pem>` | Unencrypted PKCS#8 PEM private key (used with `--client-cert`). |
| `--trust <p12\|pem>` | PKCS#12 or PEM CA bundle that verifies the server certificate. When omitted, the platform default trust store is used. |
| `--trust-password-env <ENV>` | Name of the environment variable holding the truststore password. |
| `--authority-id <id>` | Authority scope for the operation (omit for realm-wide operations). |
| `--approval-id <id>` | A prior approval identity, for re-submitting a dual-control operation. |
| `--deadline <ISO-8601>` | ISO-8601 duration bounding server-side execution (for example `PT30S`). |

!!! warning "Passwords come only from the environment"
    Keystore and truststore passwords are read **only** from the named
    environment variables — never from the command line. This keeps secrets out
    of process listings, shell history, and audit logs.

Remote mode accepts any dotted operation identifier the server exposes (including
`security.*`, `acme.*`, `ocsp.*`, and `repository.*` families), because it speaks
directly to the [operation API](admin-api.md). Operation arguments are given with
`--arg name=value` (string), `--arg-int name=value` (integer), or
`--arg-bool name=true|false` (boolean), in addition to the known `--option`
spellings.

Remote mode rejects `--config`; no local backend providers are opened. Supplying
`--url` with missing or partial client material, or client material without
`--url`, is an invalid invocation (exit `2`).

### The pending and approval flows

A `202 PENDING` signing hand-off is resolved by polling the server's
[signing-operation endpoint](admin-api.md#the-pending-hand-off-202) until it
terminalizes or the `--pending-wait` deadline elapses; a still-pending operation
exits `7` so you can resume it later. A `409 APPROVAL_REQUIRED` outcome reports
the operation commitment and exits `4`; obtain an approval and re-run the
identical operation with `--approval-id`.

## Examples

=== "Local mode"

    ```bash
    # Inspect a certificate in the local store
    zeroecho pki credential.inspect \
        --config ./cli-config.json \
        --credential-id cred-000123 \
        --output json

    # Register and activate a profile
    zeroecho pki profile.register --config ./cli-config.json --profile-file ./server-tls.json
    zeroecho pki profile.activate --config ./cli-config.json --profile-id server-tls --profile-version 1

    # Run a sequential plan
    zeroecho pki run ./bootstrap-plan.json --config ./cli-config.json --output json
    ```

=== "Remote mode"

    ```bash
    # Passwords are supplied via the environment, never on the command line
    export ZEROECHO_CLIENT_P12_PW=…
    export ZEROECHO_TRUST_P12_PW=…

    # List authorities this client may inspect
    zeroecho pki ca.list \
        --url https://pki.example.com:8443 \
        --client-keystore ./admin-client.p12 \
        --client-keystore-password-env ZEROECHO_CLIENT_P12_PW \
        --trust ./server-ca.p12 \
        --trust-password-env ZEROECHO_TRUST_P12_PW \
        --limit 100 \
        --output json

    # Issue a certificate against a specific authority (PEM client identity)
    zeroecho pki credential.issue \
        --url https://pki.example.com:8443 \
        --client-cert ./admin-client.pem \
        --client-key ./admin-client-key.pem \
        --trust ./server-ca.pem \
        --authority-id issuing-ca-1 \
        --deadline PT30S \
        --arg issuerCaId=issuing-ca-1 --arg requestId=req-000045 --arg profileId=server-tls
    ```

## Exit codes

The process exit code encodes the outcome class. It is identical in local and
remote mode.

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | Success | The operation (or every plan step) succeeded. |
| `2` | Invalid invocation | Arguments or mode selection were invalid. |
| `3` | Configuration failure | The configuration (or, remotely, TLS/authentication setup) was invalid. |
| `4` | Validation or policy | A validation failure, policy rejection, authorization denial, or an unresolved approval requirement. |
| `5` | Not found or conflict | The target was not found, or the request conflicted with current state. |
| `6` | Recovery required | The operation must be recovered before it can complete. |
| `7` | Outcome not yet known | The outcome is not yet known (a pending signing hand-off that outlasted `--pending-wait`, or an external outcome to reconcile). **Resumable.** |
| `8` | Resource failure | A resource failure or overload; the connection or backend was unavailable. |
| `9` | Internal failure | An unexpected internal failure. |
| `130` | Cancelled | The operation was cancelled. |

!!! tip "Exit code 7 is a clean, resumable state"
    Code `7` means the outcome is not yet known; it does not prove that an uncertain
    submission was accepted. Never blindly resubmit a mutation. When a signing
    operation ID is available, use `signing.operation.inspect --operation-id ID`
    with the same remote TLS connection options. Inspection uses GET and rejects
    `--pending-wait`, `--authority-id`, `--approval-id` and `--deadline`.

## `zeroecho-pki-publisher-secrets`

The `zeroecho-pki-publisher-secrets` utility manages the encrypted publisher
secrets store. The store holds credentials — for example HTTP `Authorization`
header values — that publisher providers reference by alias using a `keyring:`
prefix in their configuration. The store is separate from the CA signing keyring
and is unlocked independently at server start-up.

Three protection profiles are supported: `CLASSIC` (password recipient), `PQC`
(BIKE-256 recipient), and `HYBRID` (both recipients). HYBRID encryption needs both
recipient inputs, but decryption accepts either independently; it is not a
two-factor unlocking requirement.

Password recipients use PBKDF2-HMAC-SHA256 with 600,000 iterations. The helper
configures the same 600,000-iteration ceiling for creation and password unlocking;
decoded counts below the library minimum or above that ceiling are rejected.
CLASSIC, PQC and both independent HYBRID unlocking paths pass command smoke tests. See
[publisher setup](../admin/publication.md#publisher-secrets-store) before deployment.

### Commands

#### `generate-bike-key`

```text
zeroecho-pki-publisher-secrets generate-bike-key --pub bike-public.der --priv bike-private.der
```

Generates a BIKE-256 key pair, writing X.509 DER public and PKCS#8 DER private
files. Protect the private file independently of the encrypted secrets store.

#### `write-store`

```text
zeroecho-pki-publisher-secrets write-store \
    --store FILE --secrets secrets.json \
    --protection CLASSIC|PQC|HYBRID \
    [ --password-env VAR ] [ --bike-pub bike-public.der ]
```

Creates or rewrites the encrypted store from a flat JSON object mapping secret
identifiers to values. There is no interactive prompt or standard-input mode.
Keep plaintext input in protected operator storage and remove it using the
storage platform's appropriate procedure after verification.

| Option | Description |
| --- | --- |
| `--store FILE` | Path to the secrets store file to create or rewrite. |
| `--secrets FILE` | Protected flat JSON input. |
| `--protection CLASSIC\|PQC\|HYBRID` | Recipient selection. |
| `--password-env VAR` | Password environment variable for CLASSIC/HYBRID writing. |
| `--bike-pub FILE` | X.509 DER public key for PQC/HYBRID writing. |

The publisher manager has no inline password option. The server's separate
`--publisher-secrets-dev-password` switch is development-only and must never be
used for production secrets.

#### `verify-store`

```text
zeroecho-pki-publisher-secrets verify-store \
    --store FILE \
    [ --password-env VAR ] [ --bike-priv bike-private.der ]
```

Opens the store and prints the list of alias names it contains. Secret values are
never printed. Exits non-zero if the store cannot be opened (wrong password, wrong
key, or a corrupt file).

| Option | Description |
| --- | --- |
| `--store FILE` | Path to the secrets store file to verify. |
| `--password-env VAR` | Password environment variable for password unlocking. |
| `--bike-priv FILE` | PKCS#8 DER private key for BIKE unlocking. |
