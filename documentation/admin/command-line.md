# Administering from the command line

Everything in the [console](console.md) can also be driven from the command line
against a running server. The command line and the console invoke the *same*
operations over the same administrative HTTPS listener and are subject to the same
authorisation, approval, and bounded-wait rules — the command line is simply a
scriptable client. This page explains when to use it, how to connect with a client
certificate, and how to run and script operations; the exhaustive option and
exit-code detail is in the [CLI reference](../reference/cli-reference.md).

## When to use it

Reach for the command line when you want to:

- **Automate** repeatable administration — bulk registration, scheduled CRL
  generation, publication processing, or reconciliation.
- **Integrate** PKI actions into pipelines and change-management tooling.
- **Operate headless**, on a host with no browser or where presenting a browser
  client certificate is impractical.
- **Reproduce and script** an action you first performed interactively in the
  console.

For exploratory, one-off, and review work the console is usually faster; for
anything repeatable or unattended, the command line is preferable.

## Connecting over mutual TLS

The server's administrative listener requires mutual TLS: the client must present
an X.509 certificate that maps to an administrative principal, exactly as the
browser does through the edge. Point the client at the server and supply your
client certificate, its private key, and the trust anchor for the server:

```bash
zeroecho admin \
  --server https://pki.internal.example:8443 \
  --client-cert /path/to/admin.crt \
  --client-key  /path/to/admin.key \
  --trust       /path/to/server-ca.crt \
  <operation> [arguments…]
```

The identity in the client certificate determines your permissions. The server
authorises every call independently and fails closed, so the command line can only
run operations your principal is permitted to invoke.

!!! warning "Protect the client key"
    The client private key is an administrative credential. Store it with strict
    permissions, prefer a per-operator key, and never embed it in shared scripts
    or images. See [security hardening](../deployment/security-hardening.md).

## Running an administrative operation

Any operation in the catalogue can be invoked by its id, with the same typed
arguments the console form collects. For example, listing authorities, generating
a CRL, and revoking a credential:

```bash
# List authorities
zeroecho admin ... ca.list --limit 100

# Generate a full CRL for an issuer
zeroecho admin ... status.generate \
  --issuerCaId CA-123 --type CRL --formatId x509

# Revoke a credential with an RFC 5280 reason
zeroecho admin ... credential.revoke \
  --credentialId CRED-456 --reason KEY_COMPROMISE \
  --justification "reported key exposure"
```

Authority-scoped operations carry the target authority (typically the same
identifier as the operation's authority argument). Operations that take an encoded
document — an imported CSR or a profile — accept it base64-encoded, as in the
console.

### Outcomes and the bounded wait

The command line surfaces the same [outcomes](index.md#the-operation-model) as the
console:

| Outcome | Command-line behaviour |
|---|---|
| **Succeeded** | The result is returned; success exit status. |
| **Failed** | The failure classification is reported; error exit status. |
| **Approval required** | The operation is high-risk or grant-conditioned; the operation commitment is reported so you can request and cite an approval. |
| **Pending** | A signing hand-off did not complete within the wait budget; the still-pending operation is reported with a distinct exit code so a script can resume it later. |

The exact exit codes — including the dedicated code for a still-pending signing
operation — are listed in the [CLI reference](../reference/cli-reference.md).

## High-risk operations from the command line

High-risk operations follow the same dual-control flow as the console:

1. Run the operation; it returns **approval required** with an operation
   commitment.
2. Create a durable approval (`security.approval.request`) binding the exact
   target operation and arguments.
3. A separate, eligible principal approves it (`security.approval.approve`).
4. Re-run the original operation citing the approval id.

Because the approval binds the exact arguments, the re-run must use identical
arguments to the request.

## Scripting

The command line is designed for composition. Typical patterns:

- **Chain steps** — import a CSR, capture the returned request id, verify it, then
  issue against it.
- **Check exit codes** — branch on success, failure, approval-required, and
  pending so unattended jobs behave correctly (in particular, treat *pending* as
  "resume later", not "failed").
- **Iterate over lists** — drive a list operation and act per record, for example
  processing every pending publication.

```bash
# Import a CSR and issue against it
req=$(zeroecho admin ... request.import --formatId x509 --encoded "$CSR_B64")
zeroecho admin ... request.verify --requestId "$req"
zeroecho admin ... credential.issue \
  --issuerCaId CA-123 --requestId "$req" --profileId tls-server
```

!!! note "Same model, different surface"
    Nothing about the command line changes the operation model. Discoverability,
    scope rules, approvals, and the synchronous bounded wait behave identically to
    the console, so an action verified in one surface behaves the same in the
    other.

## Related pages

- Full command, option, and exit-code detail: [CLI reference](../reference/cli-reference.md).
- The operations you can run: this guide's area pages, starting from
  [the index](index.md#where-to-go-next).
- The HTTP contract underneath both surfaces: [Admin API reference](../reference/admin-api.md).
