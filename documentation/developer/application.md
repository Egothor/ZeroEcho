# The application

The `app` module (`module zeroecho.app`) is the single-process `zeroecho`
command-line application. This page explains its structure, the `zeroecho pki`
utility and its two execution modes, batch plan execution with step output
references, output modes, and exit codes — with an emphasis on embedding and
automation. For the exhaustive list of operations and options, see the
[CLI reference](../reference/cli-reference.md).

## Subcommand dispatch

The process entry point is `zeroecho.ZeroEcho`. It inspects the first argument
and dispatches to one of two families:

- If the first argument is `pki`, the remaining arguments are handed to the PKI
  command family (`zeroecho.pki.cli.PkiCli`), which owns its own exit-code
  contract.
- Otherwise the top-level parser selects one of the keyring / cryptography
  subcommands via mutually exclusive option flags: `-E`/`--kem`, `-G`/`--guard`,
  `-K`/`--ksm` (key store management), `-C`/`--covert`, and `-T`/`--tag`.

```text
zeroecho pki <...>          # PKI command family (this page)
zeroecho -K <...>           # key store management
zeroecho -T <...>           # tag (signature / digest)
zeroecho -E | -G | -C <...> # KEM, guard, covert
```

This page focuses on the `pki` family, which is the surface most integrations
build on.

## The `zeroecho pki` utility

`PkiCli.execute(String[] arguments, OutputStream output)` is the composition root
for the synchronous PKI command family. It parses the invocation, selects an
execution mode, runs exactly one operation or one plan, renders the result, and
returns a stable process exit code. It is an openssl-style utility: each run does
one unit of work and exits with a code the caller can branch on.

Two modes are selected purely by which options are present.

=== "Local (in-process)"

    Supplying `--config <file>` (and no remote client material) runs against a
    local backend opened in-process from that configuration — the store, keyring,
    and other providers are constructed for the life of the command and closed
    when it returns.

    ```console
    $ zeroecho pki ca.inspect --config /etc/zeroecho/pki.json --ca-id example-root
    ```

    Local mode can run a single operation or a batch plan (`run <plan-file>`).

=== "Remote (admin API over mutual TLS)"

    Supplying `--url <https-base-url>` together with client certificate material
    (`--client-keystore`, or `--client-cert` and `--client-key`) selects remote
    mode. The command speaks the `pki-server` administrative API over mutual TLS;
    `--config` is rejected because it conflicts with remote mode.

    ```console
    $ zeroecho pki ca.inspect \
        --url https://pki.example.internal:8443 \
        --client-keystore admin.p12 --client-keystore-password-env ADMIN_P12_PW \
        --ca-id example-root
    ```

    Remote mode runs a **single** operation, never a batch plan, and accepts any
    dotted operation id the server exposes. Passwords are read only from the named
    environment variables, never from the command line.

!!! warning "Mode selection is strict"

    `--url` with missing or partial client material — or client material without
    `--url` — is an invalid invocation (exit code `2`). This prevents accidentally
    falling back to a local run when a remote one was intended.

## Batch plans

In local mode, `zeroecho pki run <plan-file> --config <file>` executes an ordered
sequence of operations from a JSON plan. A plan is validated strictly before any
step runs.

### Plan format

```json
{
  "version": 1,
  "failurePolicy": "FAIL_FAST",
  "operations": [
    {
      "id": "import-request",
      "operation": "request.import",
      "arguments": { "formatId": "x509", "encoding": "DER", "requestFile": "req.der" }
    },
    {
      "id": "issue",
      "operation": "credential.issue",
      "arguments": {
        "issuerCaId": "example-root",
        "profileId": "tls-server",
        "requestId": "${import-request.requestId}"
      }
    }
  ]
}
```

- `version` must be `1`.
- `failurePolicy` is `FAIL_FAST` (stop and skip the rest on the first failed
  step) or `CONTINUE_INDEPENDENT` (run every step whose dependencies are
  available).
- `operations` is an ordered, non-empty list (up to 1000 steps). Each step has a
  unique `id`, an `operation` name that must be a known operation, and an
  `arguments` object.

### Step output references

An argument value of the form `${stepId.field}` is a reference to a field of an
**earlier** step's successful output. References are validated at parse time —
they must target a step that appears earlier in the list — and resolved at run
time:

- If the referenced step succeeded, the named output field is substituted. If
  that step succeeded but has no such output field, the referencing step fails
  validation.
- If the referenced step did not succeed (failed or skipped), the referencing
  step is **skipped** with a dependency-unavailable reason rather than run with a
  missing value.

Only whole-value references are supported; string interpolation such as
`prefix-${a.b}` is rejected. This keeps data flow between steps explicit and
auditable.

### Failure and cancellation semantics

Under `FAIL_FAST`, the first failed step marks the remainder skipped. Under
`CONTINUE_INDEPENDENT`, independent steps still run; only those whose referenced
inputs are unavailable are skipped. Cooperative cancellation stops the plan and
marks not-yet-run steps skipped.

## Bounded wait for asynchronous signing

Remote submission may return a pending signing receipt. Remote-only
`--pending-wait <seconds>` (default `3`, range `0`–`3600`) bounds polling after
that submission. A still-pending or uncertain outcome exits `7` without
fabricating a result. Inspect an available receipt using
`signing.operation.inspect --operation-id ID` and the TLS connection options;
do not blindly resubmit the mutation. Explicit inspection rejects the wait
option. Local commands and plans execute synchronously and reject
`--pending-wait` before opening the session.

## Output modes

`--output human|json` selects the rendering. `human` is a readable summary;
`json` is a structured document suitable for machine parsing in automation. The
same result data drives both, and batch plans report per-step status in either
mode.

## Exit codes

The PKI command family maps outcomes to a stable set of process exit codes. For a
plan, the process code is the most severe step outcome (with a plan-level failure
taking precedence).

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `2` | Invalid invocation (bad arguments or mode selection). |
| `3` | Configuration failure (unreadable/invalid config, or remote client setup). |
| `4` | Validation or policy rejection. |
| `5` | Not found or conflict. |
| `6` | Recovery required. |
| `7` | External outcome unknown (for example, an asynchronously-signed operation still pending after the bounded wait). |
| `8` | Resource failure (backend/session/transport). |
| `9` | Internal failure. |
| `130` | Cancelled. |

## Embedding and automation

Because `PkiCli.execute(String[], OutputStream)` returns an `int` exit code and
writes its result to a supplied `OutputStream`, the command family can be driven
in-process as well as from a shell. For automation:

- Prefer `--output json` and branch on the exit code rather than parsing human
  text.
- Treat exit code `7` as "resume later", not as a hard failure.
- Use batch plans with step references to compose multi-step workflows (for
  example import a request, then issue against its id) in a single validated run.
- Keep secrets in environment variables; the remote mode reads keystore and trust
  passwords only from the named environment variables.

See the [CLI reference](../reference/cli-reference.md) for the full operation
catalogue and every option, and the [Admin API reference](../reference/admin-api.md)
for the remote wire contract.
