# Command-line reference

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
zeroecho pki <operation> --config <file> [--output human|json] [--pending-wait <seconds>] [arguments]
zeroecho pki run <plan-file> --config <file> [--output human|json] [--pending-wait <seconds>]

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
| `--pending-wait <seconds>` | both | Bounded wait (default `3`, range `0`–`3600`) for an asynchronously-signed operation to finish before a clean pending exit (code `7`). |
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
  "version": 2,
  "store":  { "provider": "fs",     "properties": { "root": "state/pki" } },
  "audit":  { "provider": "file",   "properties": { "root": "state/audit" } },
  "publishers": []
}
```

!!! note
    In the local CLI configuration each provider block uses the key `provider`
    (the server configuration file uses `id`). The audit provider may not be
    `stdout`.

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

Remote mode ignores `--config`; no local backend providers are opened. Supplying
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

    # List the operations this client may use
    zeroecho pki operation.list \
        --url https://pki.example.com:8443 \
        --client-keystore ./admin-client.p12 \
        --client-keystore-password-env ZEROECHO_CLIENT_P12_PW \
        --trust ./server-ca.p12 \
        --trust-password-env ZEROECHO_TRUST_P12_PW \
        --output json

    # Issue a certificate against a specific authority (PEM client identity)
    zeroecho pki certificate.issue \
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
    Code `7` does not mean the operation failed. It means the utility completed
    its bounded wait without a terminal answer. Re-run the same command (remotely,
    with the pending signing identifier the server reported) to resume it.
