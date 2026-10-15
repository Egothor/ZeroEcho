# PKI CLI configuration and remote execution

For opt-in remote backups, the JSON CLI supports reservation, export preparation,
verification, restore staging, status and acknowledgement. Archive upload/download
requires the administration console or the dedicated binary HTTP routes described
in [backup and restore](../documentation/admin/backup-restore.md#opt-in-http-transfer).
The CLI rejects `backup.stream.upload` and `backup.stream.download` locally with
`BACKUP_BINARY_ROUTE_USE_WEB_CONSOLE_OR_HTTP`; it never posts archive bytes into
an ordinary JSON operation envelope. The bundled schema remains complete.

The CLI distinguishes local commands from remote administrative API requests.
It uses the current PKI operation catalog and rejects obsolete configuration
documents. The [deployment and CLI contracts](pki-deployment-cli-contracts.md) define
execution, identity, recovery and result semantics.

## Current availability

Local commands and sequential plans execute through `PkiSession.openLocal`.
Signing runs synchronously on the caller thread through the shared local facade.
The CLI opens no reactor or HTTP listener. `signing.operation.inspect` reads one
operation without advancing it; `signing.operation.complete` explicitly advances
only the selected operation. Unsupported server-only command names are rejected
before opening a local session, including in a sequential plan.

Remote URL/mTLS selection and API request arguments remain separate. The CLI submits
commands once and observes accepted signing operations through GET requests.
Explicit remote inspection by ID is available. Remote explicit completion and
remote plans are invalid.

## Local configuration

Use a version-1 document with the explicit local discriminator and audit identity:

```json
{
  "version": 1,
  "mode": "local",
  "operatorId": "local-admin",
  "store": { "provider": "fs", "properties": { "root": "./pki-store" } },
  "audit": { "provider": "memory", "properties": { "size": "512" } },
  "publishers": [],
  "bindingProviders": []
}
```

The example uses an in-memory audit sink. `operatorId` is a trusted local audit
declaration, not a server-authenticated principal. Only `signing` may be omitted
from the documented root fields. Empty provider lists are explicit. Unknown or
duplicate keys, wrong types, undiscriminated legacy versions 1–4, and backend
version-6 documents are rejected with configuration exit 3. The backend keeps its
own topology parser. An audit provider that writes to stdout is rejected so it
cannot corrupt machine output.

Optional local signing configuration uses the existing local signer types:

```json
"signing": {
  "provider": {
    "provider": "zeroecho-lib",
    "properties": { "keyringPath": "./signing.zek" }
  },
  "signatureAlgorithm": "SHA256withRSA",
  "signingTtlSeconds": 30,
  "unlockEnvironmentVariable": "PKI_KEYRING_PASSWORD",
  "claimLeaseMillis": 5000,
  "providerCallTimeoutMillis": 1000
}
```

This is a root-field fragment. Only `zeroecho-lib` is permitted for local signing.
Durations are positive exact integers; claim/call durations are at most one day
and the lease must exceed the call timeout. The environment reference and
`pureEdDsaMaximumTbsBytes` are optional. An omitted EdDSA bound uses the existing
single-signer calculation. No lane, queue or reactor topology is accepted.
The public CLI supplies the configured environment reference to the existing
keyring unlock provider. The variable must contain the keyring password; its value
is never printed. No console or default-password fallback is used. A missing
reference, unset/empty variable, wrong password or inaccessible keyring fails
session opening with exit 8. Embedded callers may instead supply an unlock
capability through their session opener.

## Invocation and output

```bash
zeroecho pki profile.list-all --config local.json --limit 25 --output json
zeroecho pki run plan.json --config local.json --output json
zeroecho pki profile.list-all --url https://localhost:8443 \
  --client-keystore client.p12 --client-keystore-password-env PKI_CLIENT_PASSWORD \
  --arg-int limit=25 --output json
```

`--config` and `--url` are mutually exclusive. Existing PKCS#12 or PEM mTLS choices,
trust configuration and environment password references remain available.
`--pending-wait` is remote-only and defaults to three seconds; local use is invalid.
Duplicate/conflicting options and incomplete credential choices fail before a
session or HTTP client is opened. Values resembling option names remain values.
Remote operation IDs are dotted labels with optional interior hyphens, including
`profile.list-all`, within the backend's 128-character limit.

Local inventories support their existing pagination fields. Authority-scoped
commands use `--authority-id`; confirmation completion carries the exact server
CAS revision and commitments plus `--response` as canonical unpadded Base64url.
The `signing.operation.inspect` and local-only `signing.operation.complete` commands
accept only `--operation-id` (or `operationId` in local plans). Remote inspection
rejects `--pending-wait`, authority scope, approval and deadline options.

Plans keep version 1, earlier-step references and existing failure policies.
Core execution calls each operation once; an unexpected `PENDING` result never
causes mutation resubmission. JSON output remains a single version-1 document
followed by a newline, including invocation errors requested as JSON. An optional
step `operationId` retains the available signing receipt or the requested
inspection/completion ID, including on failure. Human output
carries the same identity and failure distinctions. Exceptions and secret values
are not copied into diagnostics. Exit meanings remain in the deployment and CLI contracts.

The [worked demos](examples/pki-cli/README.md) exercise current local configuration,
synchronous signing, publication and explicit recovery. The
[deployment guide](../deploy/README.md) covers distributions and remote operation.

## Remote structured arguments and observation

Keep `--arg name=value`, `--arg-int name=42` and `--arg-bool name=true` for scalar
fields. Use `--arg-json name='<JSON>'` for nested objects and lists, including
approval `targetArguments`, grant conditions and API arrays. For example, an
argument fragment for an approval request can be:

```bash
--arg-json 'targetArguments={"requestId":"request-123","profileId":"profile-123"}'
```

The fragment supplies one field; the selected API operation still requires its
other arguments. JSON also supports text, exact integers and booleans. Null,
floating-point numbers, duplicate properties, trailing data and duplicate argument
names across any argument forms are rejected. JSON argument bounds follow the
server request protocol: 16 MiB per document, depth 16, 65,536 tokens, 4,096 entries
per container, 128-character property names and 21,846-character strings. The
assembled request is also bounded to 16 MiB; a listener may enforce a smaller
limit. Local configuration and plan parsing keep their existing smaller limits.

To check a retained receipt, use the same remote URL and mTLS options as submission:

```bash
zeroecho pki signing.operation.inspect --url https://localhost:8443 \
  --client-keystore client.p12 --client-keystore-password-env PKI_CLIENT_PASSWORD \
  --operation-id SIGNING_OPERATION_ID --output json
```

Inspection sends one GET. Submission trusts the validated response body ID, never
`Location`, and polls only that ID. `--pending-wait 0` returns an accepted receipt
without polling. Expiry returns `PENDING` and exit 7; interrupted observation keeps
the receipt and exits 130. A GET transport or protocol failure keeps `PENDING`,
the ID and a safe `observationFailure`, with exit 8 or 9 respectively. No such
outcome cancels or resubmits backend work. Unknown submission acceptance reports
uncertainty without inventing an ID. A completed response retains its structured
result, and backend failures retain recovery/reconciliation flags and any known ID.

Each HTTP exchange has a bounded full-body wait and a 4 MiB response limit.
Malformed or inconsistent status/body envelopes never become successful results.
The [packaged deployment gate](../pki-frontend/e2e/packaged/README.md) verifies
actual mTLS, approval, scoped authorization and receipt observation.

## Local signing and explicit recovery

An explicit local signing invocation constitutes approval by the configured
trusted root operator. All remaining profile, key, proof, validity and durability
checks still apply. Signing returns success only after domain completion; an
accepted operation or durable signature alone is insufficient. Completed results
can feed later plan steps using the existing references. For example, use the
returned `credentialId` in `credential.inspect`. Its `authorityId` identifies the
certificate's issuer: for an intermediate CA certificate this is its parent CA.
Select the intermediate authority itself from `ca.list` before using its ID for
issuance or CA lifecycle commands.

```bash
zeroecho pki ca.create --config local.json --format-id x509 \
  --subject-ref 'CN=Example Root' --profile-id root-ca \
  --key-ref zeroecho-lib:root.prv --output json
zeroecho pki signing.operation.inspect --config local.json \
  --operation-id SIGNING_OPERATION_ID --output json
zeroecho pki signing.operation.complete --config local.json \
  --operation-id SIGNING_OPERATION_ID --output json
```

Root creation requires the referenced key and an active compatible profile.
Certificate validity is rounded inward to whole seconds. A just-created or rotated
issuer can therefore have `notBefore` slightly in the future; inspect its certificate
and respect that instant before using it to issue certificates or status objects.
The CLI does not retry a policy rejection automatically.
Inspection is a successful read even when `output.state` is nonterminal or failed;
that read success does not claim the underlying signing operation completed.
Inspection and explicit completion retain the requested ID on failure. Completion
preserves the original accepted actor, while its invocation is audited under the
currently configured operator. Ordinary reads and unrelated commands never drive
an earlier signing operation.

Local failures use the existing classifications and exits, including recovery
required (6) and cancellation (130), with any known ID retained. Explicit completion
of a durable signature can finish publication without signing again. A recovered
local dispatch lacking a durable result keeps its unrecoverable outcome rather
than repeating cryptography. Live leases and future retries return immediately;
the CLI does not poll or force them. Existing exclusive store ownership prevents
concurrent writable use by the server and local CLI.

## Validation evidence

The [local process gates](../app/docs/local-validation.md) exercise explicit
recovery through the installed CLI after process termination and record
informational signing/startup measurements. The [PKI validation record](pki-validation.md)
summarizes the completed cross-mode, quality and distribution checks.
