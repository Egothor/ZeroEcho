# Administering from the command line

`zeroecho pki` provides local synchronous administration and remote submit/poll
administration. Remote calls use the same authorization, approval and operation
catalog as the console. Local mode opens its configured store directly and does
not establish a server-authenticated principal.

## Connect over mutual TLS

Use the administrative HTTPS listener, a client certificate mapped to a principal,
its unencrypted PKCS#8 PEM key, and the server trust anchor:

```bash
zeroecho pki ca.list \
  --url https://pki.internal.example:8443 \
  --client-cert /path/to/admin.crt --client-key /path/to/admin.key \
  --trust /path/to/server-ca.crt --limit 100 --output json
```

Alternatively use `--client-keystore` with `--client-keystore-password-env`.
Passwords come from the named environment variable. Protect the private key as an
administrative credential. `--config` cannot be combined with `--url`.

## Run operations

These examples require the named TLS files, existing CA/credential IDs and a
principal authorized for the operation. Authority scope is explicit.

```bash
zeroecho pki status.generate \
  --url https://pki.internal.example:8443 \
  --client-cert admin.crt --client-key admin.key --trust server-ca.crt \
  --authority-id CA-123 --issuer-ca-id CA-123 --type CRL --format-id x509

zeroecho pki credential.revoke \
  --url https://pki.internal.example:8443 \
  --client-cert admin.crt --client-key admin.key --trust server-ca.crt \
  --authority-id CA-123 --credential-id CRED-456 \
  --reason KEY_COMPROMISE --justification "reported key exposure"
```

Remote request import accepts `--format-id x509 --arg encoded=BASE64_DER`.
Only local typed import reads `--request-file` with `--encoding DER`.
There is no direct `--encoded` switch.
Known CLI switches are kebab-case. Generic arguments use canonical schema names
through `--arg name=value`, `--arg-int name=value` or `--arg-bool name=true|false`.

## Outcomes and approvals

Exit `0` means success; `4` includes authorization denial and approval required;
`7` means the outcome is not yet known. A pending receipt supplies the signing
operation ID. Inspect that receipt with the same TLS identity:

```bash
zeroecho pki signing.operation.inspect \
  --url https://pki.internal.example:8443 \
  --client-cert admin.crt --client-key admin.key --trust server-ca.crt \
  --operation-id signing-operation-123 --output json
```

`--pending-wait` bounds automatic polling after remote submission only. Explicit
inspection uses GET, never advances signing, and rejects wait/authority/approval/
deadline switches. An uncertain submission without a receipt requires
reconciliation; never blindly resubmit a mutation. Local explicit completion is
available through `signing.operation.complete`; remote completion is unavailable.

High-risk operations require a durable approval binding their exact target and
arguments. Request it with `security.approval.request`, have a separate eligible
principal approve it, then submit the identical operation with `--approval-id`.
See [access control](access-control.md) and the [CLI reference](../reference/cli-reference.md).

## Operation parameter schema

`GET /admin/v1/schema` exposes available operation descriptors, argument fields,
permissions and presentation metadata. Authentication is required; visibility
does not grant execution permission. The CLI's bundled schema performs argument
validation before submission. The server remains authoritative.

`OperationDescriptorCatalog` generates the complete JSON, CLI, OpenAPI and
TypeScript identity set, retaining unavailable entries as `available: false`;
the live endpoint omits unavailable entries. See the
[API reference](../reference/admin-api.md) for generated reference commands.
