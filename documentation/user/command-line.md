# Using the command line

The `zeroecho pki` utility can talk to a running realm over its administrative API.
In this **remote mode** it connects to the server with **mutual TLS**, submits a
single operation, and prints the result — with a JSON output mode designed for
scripting and automation. It is the natural way for automation accounts to submit
and inspect requests and credentials.

!!! info "Remote mode versus local mode"
    `zeroecho pki` also has a *local* mode that opens an on-disk realm directly;
    that is an administrator/operator tool and needs `--config`. As a
    non-administrative user you use **remote mode**, which is selected whenever you
    pass `--url` together with client-certificate material. Remote mode rejects
    `--config` and runs exactly one operation.

## Connecting with a client certificate

Remote mode requires two things: the server's base URL, and your client
certificate. Provide the certificate either as a PKCS#12 keystore or as a
PEM certificate/key pair.

=== "PKCS#12 keystore"

    ```bash
    zeroecho pki credential.inspect \
      --url https://pki.example.com:8443 \
      --client-keystore me.p12 \
      --client-keystore-password-env PKI_P12_PASSWORD \
      --credential-id <credential-id> \
      --output json
    ```

=== "PEM certificate and key"

    ```bash
    zeroecho pki credential.inspect \
      --url https://pki.example.com:8443 \
      --client-cert me.crt --client-key me.key \
      --credential-id <credential-id> \
      --output json
    ```

To verify the server's certificate against a specific trust anchor, add
`--trust <p12|pem>` (with `--trust-password-env <ENV>` for a password-protected
PKCS#12 trust store).

!!! warning "Passwords come from the environment, never the command line"
    Keystore and trust-store passwords are read **only** from the environment
    variable you name with `--client-keystore-password-env` /
    `--trust-password-env`. Passwords are never accepted as command-line
    arguments, so they do not leak into your shell history or process listings.

    ```bash
    export PKI_P12_PASSWORD='…'   # set once, referenced by name
    ```

## Submitting and inspecting requests and credentials

Remote mode accepts any dotted operation identifier. The operations you will use
most as a non-administrative user are:

| Operation | What it does |
|---|---|
| `request.import` | Submit a DER CSR (`--format-id x509 --arg encoded=BASE64_DER`). |
| `request.verify` | Verify a request's proof of possession (`--request-id`). |
| `request.inspect` | Look up a request (`--request-id`). |
| `credential.inspect` | Inspect an issued credential (`--credential-id`). |
| `revocation.inspect` | Read a credential's revocation state (`--credential-id`). |
| `credential.revoke` | Request revocation (`--credential-id`, `--reason`, `--justification`). |

Arguments can be given with these known option spellings, or generically with
`--arg name=value` (text), `--arg-int name=value` (integer), and
`--arg-bool name=true|false` (boolean) — useful for any operation or field not in
the shortlist above.

```bash
# Supply the base64 DER CSR in CSR_B64, then submit it.
zeroecho pki request.import \
  --url https://pki.example.com:8443 \
  --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
  --format-id x509 --arg "encoded=$CSR_B64" \
  --output json

# Set REQ to the returned request object's identifier after checking exit 0.
zeroecho pki request.verify \
  --url https://pki.example.com:8443 \
  --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
  --request-id "$REQ" \
  --output json
```

If an operation is authority-scoped, name the authority with `--authority-id`. If
it is gated behind an existing approval, reference it with `--approval-id`. A
per-operation time budget can be set with `--deadline <ISO-8601>`.

## JSON output for scripting

Add `--output json` to get a stable, machine-readable result you can parse with
tools like `jq`. The default, `--output human`, is easier to read at a terminal.
Combine JSON output with the **process exit code** (below) to drive automation
reliably.

Successful remote results are under `.result` (for example `.result.requestId`
after CSR import). A pending CLI receipt exposes `.operationId` at the top level.
Raw HTTP responses have a separate top-level correlation `requestId`; do not
confuse that request correlation with a persisted CSR identifier.

## Exit codes and the "outcome not yet known" result { #outcome-not-yet-known }

`zeroecho pki` returns a stable exit code so scripts can branch without parsing
text. Local and remote modes use the **same** codes:

| Exit code | Meaning |
|---|---|
| `0` | Success. |
| `2` | Invalid invocation (bad arguments). |
| `3` | Configuration/connection setup failure. |
| `4` | Validation failure, policy rejection, approval required, or authorization denied. |
| `5` | Not found, or a conflict. |
| `6` | Recovery required. |
| `7` | **Outcome not yet known — resume later.** |
| `8` | Resource failure or the server is overloaded. |
| `9` | Internal failure. |
| `130` | Cancelled. |

### What exit code 7 means

Some operations — notably issuance that is signed asynchronously or that requires
approval — may not have a *final* answer by the time the command returns. When that
happens, the command exits cleanly with code **`7`** ("outcome not yet known").

This is **not** proof of failure or acceptance. A pending receipt can be inspected
by its signing operation ID; an uncertain submission without a receipt requires
reconciliation. Never blindly resubmit the mutation.

```bash
zeroecho pki credential.issue \
  --url https://pki.example.com:8443 \
  --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
  --issuer-ca-id <ca-id> --request-id <request-id> --profile-id <profile> \
  --pending-wait 10 \
  --output json
case $? in
  0) echo "issued" ;;
  7) echo "still pending — inspect again later" ;;
  *) echo "failed" ;;
esac
```

!!! tip "Bounded wait with `--pending-wait`"
    `--pending-wait <seconds>` (default 3) tells the command how long to wait for a
    still-processing operation to settle before it returns code `7`. Raising it
    trades a longer wait for a better chance of a final answer in one call; either
    way, code `7` means the outcome is not yet known. Use
    `signing.operation.inspect --operation-id ID` with the remote TLS options when
    a receipt supplies an ID. The wait option is invalid locally and on explicit
    inspection; inspection never advances signing work.

## Full reference

This page covers the user-facing essentials. For the complete option and operation
listing — every flag, every operation identifier, and the exact argument
schema — see the [CLI reference](../reference/cli-reference.md).

## Next steps

- Prepare a CSR to submit: [Requesting certificates](requesting-certificates.md).
- Retrieve and check issued certificates: [Managing certificates](managing-certificates.md).
- Fully automated issuance and renewal: [ACME enrolment](acme-enrollment.md).
