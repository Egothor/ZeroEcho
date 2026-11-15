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

For `ocsp.responder.issue-certificate`, the server returns its canonical
`ocsp-prov:<slot>:r<revision>` request ID. The client preserves the original local
request ID and complete intent, and retains that validated canonical ID separately.
Continue using the original local ID with `observe`; the client resolves it to the
retained canonical ID and sends GET only. The canonical ID and linked approval/signing
identities cannot change. This exception applies only to managed OCSP issuance;
other operations must return the exact submitted request ID. If the canonical
acknowledgement was lost, the local ID is not a server alias: exit 4 requires manual
reconciliation of the existing server request through authorized inspection.
The client neither guesses a canonical ID nor repeats the mutation.

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
The TUI consumes this layer directly without spawning Java to forward
requests; Java is used only for local chain cryptography.

Removing this client change requires no server migration. Preserve retained
checkpoints and reconcile any submitted requests before replacing client files.
Removing a checkpoint does not cancel server work. No automatic cleanup/reset,
server restart, certificate revocation or trust-store change is performed.

## Interactive curses operator

The Python 3/curses host interface uses the same `Api` and `Operator` as the
commands above. Run it in a normal terminal, using the same connection and private
checkpoint requirements. It does not invoke the Java CLI for HTTP requests.
Java is needed only for the existing local chain cryptographic verifier.

```sh
./deploy/pki-tui.sh \
  --url https://localhost:8443 --realm example \
  --trust "$HOME/zeroecho-client/trust.pem" \
  --p12 "$HOME/zeroecho-client/admin.p12" \
  --checkpoint "$HOME/zeroecho-client/operator-state"
```

The password is prompted before opening curses. `--password-fd FD` is available
for an inherited descriptor; password values are never command-line arguments
or preferences. Keep the terminal private: result inspection may display sensitive
or one-time response values. The program does not write a terminal transcript.

The initial catalog groups operations by their discovered operation type.
Use arrows (or `j`/`k`), Enter to select, and `a` to switch between the type tree
and the same IDs in A–Z order. The highlighted operation survives switching.
Unavailable operations remain visible and cannot be submitted. Discovery does
not assert that every offered operation is authorized for the current principal;
the server checks current permission and policy for every request.

At the catalog, `s` opens session settings, `w` opens retained work, `d` opens
artifact downloads and `q` exits. Escape returns one level. **F2 returns to the
catalog** from forms, nested controls, review, results and settings. These keys
never send a mutation. The active endpoint and expected realm remain visible.
In text controls, Enter accepts, Backspace erases and Ctrl-U clears the value;
Escape cancels the edit. Menu shortcuts do not interpret typed field values.

Forms provide scalar, Boolean, enum, unique-set, nested-object and list controls.
Enter an attribute, choose Edit, then accept its value; optional attributes can
be omitted. Related nested attributes open their own subform. Lists support Add,
Edit and Remove, with a maximum of 128 entries. Configuration metadata supplies
format, managed-key and algorithm suggestions; active profile choices are loaded
when their listing permission is available. Explicit values remain possible.
Press `h` in an operation form for selected format/profile guidance and authorized
profile metadata. X.509 DN guidance applies only when X.509 is selected.

`profile.register` and `profile.validate` open a typed X.509 version-5 profile
editor, starting from one of the shipped root, intermediate, TLS or VPN templates.
Edit the profile identity/version and policy fields for the intended use. Nested
subject and SAN rules, certificate policy, algorithm bindings, confirmation and
hybrid fields use controls, never a JSON text editor. All six confirmation disclosure
policies are available. The confirmation policy commitment is derived automatically
from the selected disclosure, exact duration and proof-suite reference; it is not
a manually editable hash. Profile registration calls
the existing server `profile.validate` before allowing its reviewed mutation.
Validation remains subject to the selected server's installed bindings and policy.
A provider/format extension without a known structured contract reports a missing
form capability and cannot be sent through a raw JSON fallback.

CSR and backup fields select an owned private local file. Exact binary input is
Base64 encoded for the existing API; X.509 CSR input also offers PEM-to-DER
decoding. This file control has an 8-MiB limit. Select a DER certification request
for exact binary CSR input and the existing backup payload format for backup
input. The client never obtains a managed private key from the server.

Choose **Review exact request** to inspect endpoint, realm, request ID, authority
and the complete typed target. Exact request values wrap to terminal width and
scroll vertically (arrows, Page Up/Down, Home/End). Encoded profile documents also
show their decoded typed content beside the unchanged wire request. A separate
menu defaults to Cancel; only choosing
**CONFIRM SEND** sends. Navigation from a form or review does not submit. The
result screen replaces the completed submission form and explicitly labels
pending/approval-only and uncertain outcomes. Approval alone never means the
original operation executed successfully.

Worklist entries use the existing C05 checkpoint identities. Reopen a retained
entry, inspect its intent/result, or select **Observe GET only**. Lost
acknowledgements are reconciled by observation; the TUI does not resend them.
Dedicated actions have no durable observation route and are never replayed.
A retained definitive HTTP refusal is shown as FAILED/exit 2 with its exact intent
and refusal status; it is not an uncertain acknowledgement or an instruction to
observe a request that was refused.
Approve/Reject on a retained request opens a decision form prefilled with its
approval ID. Supply an explicit justification, review, and confirm that decision;
then observe the original request for terminal execution. Eligibility and own
request approval capabilities remain server decisions. Another approver may use
the normal approval-list/inspect forms and their own identity-bound checkpoint.

Result objects expose metadata and download actions for retained certificate,
CA, status and issuer-path IDs. Metadata reads preserve applicable authority from
the retained exact request; CA reads use the selected CA identity. If an
authority-scoped metadata read has no retained or explicit session context, the
TUI asks for it rather than inventing one. Realm-scoped reads receive no authority
parameter. Downloads use the authenticated C05 routes,
explicit representation/output, reviewed confirmation, and new files only.
A downloaded certificate, possession of its private key, server signing-key
custody, disclosure policy and public access are distinct facts. Individual
certificate/CRL downloads validate transport and object representation; inspect
`signatureVerified` before inferring cryptographic trust. Chain verification uses
the explicitly selected downloaded anchor under the C05 rules above.

Common context defaults apply only to fields present in the selected operation;
explicit draft overrides remain unchanged. Connection settings contain only
session values and local file references. Changing connection coordinates clears
discovery, choices, drafts, review, results and target context before reconnecting
and checking the new realm. Select a separate checkpoint for a different endpoint,
realm or identity; C05 rejects binding reuse. If reconnection fails, the UI exits
with status 2 and leaves accepted work in its original checkpoint for observation.
Preferences and passwords are not persisted. Exiting the UI normally returns 0;
this process exit is not a claim that pending operations succeeded. Per-request
screens retain the documented 0/2/3/4 result meanings.

Rollback removes the TUI files and guide additions only. Preserve checkpoints and
observe attempted work with the host client; removing a TUI draft or checkpoint
does not cancel work on the server. This interface is C06 client functionality,
not actual Podman qualification or final F01–F06 closure.
