# Host PKI operator client

`deploy/pki-operator.sh` is the reusable Python 3 host client for the administrative
HTTPS API. It shares bounded mTLS transport with `exercise-pki.sh` but does not run
qualification scenarios. It never deploys, invokes Podman, reads server files or
restarts a server. Java local/offline commands and sequential plans remain available.
Use a fresh version-18 installation; no migration procedure is provided.

Supply the exact HTTPS origin, expected realm, local trust file and operator-owned
PKCS#12 identity. Discovery and every operation check the authenticated realm.
Checkpoints are bound to origin, realm and the extracted client certificate bytes.
Use an owned mode-0700 checkpoint directory; JSON inputs and PKCS#12 files must
be owned mode-0600 regular files. Do not share a checkpoint across identities or
run concurrent sessions against it. Checkpoints contain exact requests and may
contain sensitive application data. Retain and protect them for recovery.

```sh
chmod 600 "$HOME/zeroecho-client/admin.p12" "$HOME/zeroecho-client/request.json"
./deploy/pki-operator.sh \
  --url https://localhost:8443 --realm example \
  --trust "$HOME/zeroecho-client/trust.pem" \
  --p12 "$HOME/zeroecho-client/admin.p12" \
  --checkpoint "$HOME/zeroecho-client/operator-state" discover
```

The password is prompted on a terminal. For automation pass an inherited file
descriptor containing one UTF-8 line (maximum 4096 bytes), never a password value
on the command line or in an environment variable. For example, after placing the
password in your own protected local credential file:

```sh
./deploy/pki-operator.sh \
  --url https://localhost:8443 --realm example \
  --trust "$HOME/zeroecho-client/trust.pem" \
  --p12 "$HOME/zeroecho-client/admin.p12" \
  --password-fd 3 --checkpoint "$HOME/zeroecho-client/operator-state" \
  submit "$HOME/zeroecho-client/request.json" \
  3< "$HOME/zeroecho-client/p12-password"
```

The client extracts temporary local PEM credentials using OpenSSL stdin and removes
them on exit. There is no server private-key export. Protect stdout too: explicit
results can include sensitive or one-time response values. Dedicated one-time
capability secrets are redacted from saved receipts and cannot be recovered by
replaying an action.

## Structured requests and recovery

`discover` returns the actual operation descriptors and typed schema available to
the identity. `read FILE` accepts `{ "operation": "...", "arguments": { ... },
"authorityId": "..." }` (authority is optional) and refuses discovered mutations.
Nested objects/lists are preserved. The server validates input semantics and
permissions; discovery does not grant authority.

`submit FILE` accepts an existing durable operation, for example:

```json
{
  "version": 1,
  "requestId": "operator-root-create-20261115-01",
  "operation": "ca.create",
  "arguments": {
    "formatId": "x509",
    "subjectRef": "CN=Example Root",
    "profileId": "root-profile",
    "keyRef": "existing-managed-key",
    "signatureAlgorithmId": "use-the-exact-discovered-supported-identity"
  }
}
```

Use existing compatible key/profile references and exact algorithm identities from
your approved configuration. This example is a request shape, not a ready-to-run
CA recipe. Protected FIRST-administrator key generation remains a separate operation.

The complete intent is persisted **before** the first POST. Reusing its requestId
with a changed operation, arguments or authority fails. Reusing the same intent
only observes the request with GET. Once approval/signing identities are returned,
subsequent receipts must preserve them. After lost acknowledgement, absence/transport
failure produces exit 4; keep the checkpoint and use `observe REQUEST_ID`. Do not
invent a new ID as a retry. A crash between local attempt persistence and sending
may leave an unaccepted request; the client deliberately cannot guess that no
mutation occurred. An operator must reconcile it before starting new work.

`observe REQUEST_ID --wait 60` polls GET only for up to 60 seconds. Pending approval
and approval alone are incomplete. The request retains its approvalId and exact
target; approving does not require re-entering that target. The client never
automatically approves. An eligible approver can use `action FILE` for the existing
non-durable dedicated approval operation:

```json
{
  "version": 1,
  "requestId": "local-approval-once-01",
  "operation": "security.approval.approve",
  "arguments": {
    "approvalId": "the-retained-approval-id",
    "justification": "Reviewed the retained exact target"
  }
}
```

For `action`, requestId is a **local once-only identity**, not server idempotency.
A lost response is unknown, never retried. Reuse returns the retained envelope;
a pending dedicated action stays incomplete. Approval/rejection actions return exit 3 even
when the decision itself succeeded; observe the original request for execution. Observe the original durable request
after approval. No client can bypass approval eligibility or server authorization.

After argument parsing, commands print a JSON object containing `exit` and `result`
or a safe `error`. Command-line usage errors print usage on stderr and exit 2.
A signal can terminate the process before a result is printed (SIGINT normally
exits 130); retain the checkpoint and observe any attempted mutation rather than
repeating it. Temporary files and session locks are cleaned on Python interruption.

| Exit | Meaning |
| --- | --- |
| 0 | Completed read/download or validated terminal SUCCEEDED result |
| 2 | Invalid input, refused/failed operation, local I/O or verification failure |
| 3 | Accepted/pending/approval-only; execution has not succeeded |
| 4 | Unknown acknowledgement; retain identity and reconcile without mutation replay |

## Certificate, current CA, CRL and chain files

Use the same common connection arguments before these command suffixes:

```sh
certificate CREDENTIAL_ID --representation original --output client.der
certificate CREDENTIAL_ID --representation pem --output client.pem
ca AUTHORITY_ID --representation pem --output ca.pem
crl STATUS_OBJECT_ID --representation original --output full.crl.der
crl STATUS_OBJECT_ID --representation pem --output full.crl.pem
chain PATH_ID --output issuer-chain.pem
```

All outputs must be new files. Existing files and symlinks are never overwritten.
The client uses authenticated metadata and the exact advertised same-origin binary
route, with no redirect or anonymous fallback. Missing content permissions fail.
Each original object is parsed and round-tripped as X.509 DER with local OpenSSL;
malformed/noncanonical objects fail before publication. This parse does not verify
a signature. Transfers have a 64-MiB byte bound and a 180-second time bound, require an exact
Content-Length and check Content-Digest when supplied. Temporary private files
are atomically published only after validation. Interrupted downloads leave no
accepted partial file. Certificate/CRL PEM downloads also fetch original DER and
compare decoded bytes. Their JSON hashes identify the actual objects; download
alone is not a signature/trust assertion. `ca` additionally matches the immutable
selected generation's certificate digest.

`chain` resolves authenticated `issuer.path.inspect`, downloads each ordered
credential with its own permissions, verifies PEM/DER equivalence and creates a
leaf-issuer-to-anchor PEM bundle. It does not need a public listener. Build the
client-local Java crypto helper with:

```sh
./gradlew :app:installDist --no-parallel
```

The default helper classpath is `app/build/install/app/lib/*` under this checkout.
Use global `--crypto-classpath '/your/client/app/lib/*'` for a separate local
installation. The helper supports the approved P-384, RSA-4096, ML-DSA-87 and
AltSignature algorithms. It checks validity, CA constraints/path length, keyCertSign,
ordered issuer names, primary signatures, root self-signature and complete
alternative-signature extensions/signatures where present before publishing.
The last downloaded certificate is the explicitly selected anchor; this does not
assert distribution to external trust stores or universal TLS interoperability.
A missing helper or unsupported algorithm fails without publishing a bundle.

These commands are a client interface, not deployment qualification. Real Podman
qualification and final representation/algorithm coverage belong to C08, with
F06 closure tracked through C07/C08. SDK OCSP evidence remains separately signed
ZeroEcho evidence and is not standard AltSignature OCSP.

## Library use and rollback

Import `pki_operator.Operator` with a shared `pki_http.Api` and use it as a context
manager. `submit`/`observe` return raw durable records, `action` returns its exact
operation envelope, `read` returns result fields, and download methods return
byte/identity evidence. Use `result_exit` to distinguish completion from pending.
The future TUI can consume this layer directly without spawning Java to forward
requests; Java is used only for local chain cryptography.

Removing this client change requires no server migration. Preserve retained
checkpoints and reconcile any submitted requests before replacing client files.
Removing a checkpoint does not cancel server work. No automatic cleanup/reset,
server restart, certificate revocation or trust-store change is performed.
