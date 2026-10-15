# Backup and restore

The remote `backup.restore` operation remains unavailable. Runtime discovery and
the live parameter-schema endpoint omit it. Complete generated JSON, TypeScript,
CLI resources and OpenAPI retain its identity with `available: false` (OpenAPI:
`x-zeroecho-available: false`). Legacy remote
requests still require authorization and approval, then fail with
`POLICY_REJECTION` / `BACKUP_RESTORE_UNAVAILABLE`; no archive files are extracted.
Backup export, verification and explicit local staging are available. The offline operator procedure
below assumes a securely protected working directory used exclusively by PKI.

The built-in exporter now creates a version-1 logical backup from one frozen store
state. Store mutations wait while that state is copied to private work storage;
archive creation then proceeds after mutations resume. Export omits keyrings,
locks, incomplete content, derived indexes and unrelated files. It does not inspect
opaque accepted domain payloads for embedded secrets. Back up private keys,
external CT journals and server-owned configuration/audit state separately.

The optional embedded SQL credential-search database is one such derived index.
It is excluded from logical backups and rebuilt from recovered PKI records when
an enabled store opens. Preserve the deployment's search configuration separately
and allow time and disk space for rebuilding after restore.

EST server-keygen delivery ciphertext is also outside the logical PKI backup.
Preserve its configured artifact directory together with the corresponding
server-control state and enrollment credential keyrings during an offline backup
and recovery. Pending delivery cannot be reconstructed by generating another key;
missing ciphertext that is still required for retained delivery causes recovery
to fail. Expired, released replay records do not require deleted ciphertext.

Use `BackupService.createBackupSource` or `PkiStore.createBackupSource` for the
file-backed API and close the returned source after consuming its repeatable
streams. `verifyBackupSource` checks the complete manifest, every entry and normal
offline store recovery. `prepareBackup` returns close-owned verified staging; it
does not activate it. The existing byte-array API is limited to 2 MiB by default.
Large artifacts remain on disk. The separately enabled HTTP streaming workflow
below uses the same verification and cold activation rules. The legacy
`backup.restore` identity remains disabled; the new operation is
`backup.stream.restore`.

## Opt-in HTTP transfer

Remote transfer is disabled unless the server is started with
`--backup-transfer-config /path/to/transfer.json`. The separate version-1
document preserves the main server schema (version 8).
Start from the repository example `docs/pki-backup-transfer-example.json`
and choose every value for the deployment. In the packaged server, set
`ZEROECHO_BACKUP_TRANSFER_CONFIG` to the mounted configuration file.

Provision the artifact directory durably with owner-only access before startup.
It must be exclusively used by this service, outside the PKI root, and preserved
across restart. Server control, audit and signing-keyring paths must also be
outside the replaceable PKI root and artifact directory. Overlapping storage is
rejected. Storage must support atomic replacement and directory fsync.

The example permits 64 MiB archives, 256 MiB retained archive bytes, eight
descriptors and two concurrent jobs. Each verification/restore job reserves the
archive maximum plus two 4 GiB expanded trees. Workspace reservation is admission
accounting, **not** an OS disk quota: provision additional recovery/index headroom
and filesystem limits. The source archive remains charged to retained storage
until closed. Artifact lifetime is one hour; each binary transfer has a
five-minute deadline. All budgets are mandatory.

Use **Backup and restore** in the administration console:

1. Create an export; retain its backup identifier and SHA-256.
2. Download it once. An interrupted download consumes its handle; create a new
   export. The browser streams the attachment to its download destination.
3. Select an archive and enter its backup identifier. The browser hashes fixed
   64 KiB blocks, reserves an upload and sends the file without Base64 encoding.
4. Verify the uploaded archive on the server. Independently establish provenance;
   integrity verification does not authenticate its origin.
5. Stage restoration. Request approval, obtain an independent decision, then
   retry with the approval identifier.
6. Preserve the displayed restore workflow identifier. Restart the server through
   the normal operational procedure and inspect the outcome. Only `ACTIVATED`
   acknowledges activation. Acknowledge `ACTIVATED` or `REJECTED` after review.

`UNCERTAIN` requires reconciliation after restart. Never infer rejection from
a timeout or blindly retry restoration. The server persists exact manifest and
restore identities. A provably unpublished attempt is cleaned by the domain
coordinator before becoming `REJECTED`. Unresolved outcomes keep their metadata
quota until acknowledged, even after the archive expires.

Every action requires authentication, permissions and applicable approval policy.
Handles are principal/realm-bound and grant no authority on their own. Restore
always requires high-risk approval. Browser POSTs must have the exact configured
origin. Nonbrowser clients without `Origin` must send `X-ZeroEcho-Transfer: 1`.
Handles belong in request bodies or headers, never URLs.

Binary routes are `POST /admin/v1/backup/upload` (`application/zip`,
`X-ZeroEcho-Artifact`, optional `X-ZeroEcho-Approval`) and
`POST /admin/v1/backup/download` (URL-encoded `artifactHandle`, optional
`approvalId`). Other steps use the generated `backup.stream.*` catalog.
The remote CLI supports those JSON workflow steps, but has no binary file
transport. Direct CLI upload/download attempts fail locally with
`BACKUP_BINARY_ROUTE_USE_WEB_CONSOLE_OR_HTTP`, before opening a connection;
use the console or these HTTP routes for archive bytes.
Download responses declare exact length, so truncated bodies fail.
nginx disables request/response buffering for these routes and retains
authenticated certificate forwarding.

Cancellation closes network streams; domain work retains quotas until it returns.
Failed, consumed and expired artifacts are cleaned on startup and subsequent
admission/status/download cleanup. Expiry prevents new use immediately; active
leases pin their files. Legacy JSON verification is capped at 2 MiB decoded
archive data and reports `BACKUP_LEGACY_LIMIT_USE_STREAMING` above that bound.
The ordinary HTTP body limit may reject the request earlier. The existing JSON
value limit (21,846 characters, about 16 KiB of Base64 archive data) is also
preserved. Direct legacy backup requests report `BACKUP_LEGACY_LIMIT_USE_STREAMING`
when that parser bound is exceeded; unrelated and approval-envelope parse failures
retain their existing generic validation response. Legacy export uses the same
backup-specific code above 2 MiB.

## Local staged restoration

`BackupService.stageRestore(source)` and `PkiStore.stageRestore(source)` verify
the archive and publish a durable `STAGED` request while the current store remains
open. Close the store and reopen it to activate. Inspect `latestRestoreStatus()`:
only `ACTIVATED` acknowledges completed activation. `FAILED` means the old root
was retained or restored. `UNCERTAIN` means a publication could not be acknowledged;
do not resubmit it. Close and reopen for deterministic reconciliation. The legacy
filesystem-store adapter returns `success=false` plus `RESTORE_RESTART_REQUIRED`
when staged. The legacy service adapter remains disabled so older store plugins
cannot bypass the new protocol.

Restoration rejects any regression of known live safety authority: signing
namespace, metadata values and record revisions, transaction outcomes, revocations,
and retained workflow records must agree. Store revision and signing-time watermark
must not decrease. This conservative comparison also rejects harmless metadata
differences. Missing or corrupt live authority is not evidence that rollback is
safe. Writes after staging are checked again at cold activation. A historical
backup therefore normally cannot replace a PKI that has issued, revoked or
advanced durable workflow state since that backup. Carry-forward merging is not
implemented. Authentication of the archive remains the operator's responsibility.

The comparison also includes immutable certification requests in
`requests/by-id`. A backup predating an imported request is rejected even when
that request has not yet been issued or referenced by an enrollment transaction.
Importing a request after staging can likewise prevent cold activation. This
conservative rule preserves enrollment inputs held outside the server-control
records; it does not merge newer requests into an older backup.

The store parent must be writable on the same filesystem as the store and support
atomic directory moves and directory fsync. The live root must be a normal child
directory, not a volume mount point. The external `.store.restore-control`
directory owns the process lock, journal and recovery intent. Unique stage,
rollback and failed roots are siblings. Rollback roots are retained for operator
inspection; never delete them while reconciliation is pending. Every new-version
open holds the external lock throughout its lifetime and retains compatible root
locks during activation. Existing legacy owners are excluded, but **no legacy
binary may be launched concurrently with cold activation**, including bootstrap
helpers. Colocated keyrings, control logs, audit state and unknown files cause
restore rejection rather than being silently stranded in the rollback root.

Archive streaming uses fixed-size buffers. Safety comparison replays one metadata
recovery graph at a time, capped by the existing checkpoint-entry limit, and hashes
bounded file inventories. It is not constant-memory recovery: logical records and
transaction outcomes require memory proportional to their counts. File inventory
ordering costs O(E log E); replay and hashing scale with retained ledger and file
bytes, including bounded repeated reads of shared transaction frames.
The inherited transaction-outcome map can have quadratic worst-case collision
costs; no constant-heap or throughput claim is made for recovery.

Verification proves internal consistency and detects corruption. It does **not**
authenticate a backup: an attacker can recompute its manifest. Compare the returned
whole-archive SHA-256 with an independently trusted commitment or signature before
trusting its provenance. Old unversioned ZIP backups, including `VERSION`-only
archives, are rejected. See [Backup format and limits](../developer/backup-format.md).

This page is the operator-facing procedure for backing up and restoring the PKI
server. Background on the platform's persistent volumes is in
[Deployment → Operations](../deployment/operations.md#backup-and-restore).

## What to back up

| Volume | In-container path | Priority | Notes |
|---|---|---|---|
| Store | `/var/lib/zeroecho/store-container` | **Critical** | PKI root plus external server-control state; not a complete backup of keys, CT, audit or configuration. |
| Keyring | `/var/lib/zeroecho/keyring` | **Critical** | CA private keys. Back up separately with stricter access control. |
| Audit | `/var/lib/zeroecho/audit` | High | Append-heavy. Retain per your audit-retention policy. |
| Artifacts | `/var/lib/zeroecho/artifacts` | Lower | Reconstructible by republishing from the store after a restore. |

Always back up the **store** and **keyring** together. Restoring a store without a
matching keyring means the CA keys are gone; restoring a keyring without its store
means there is nothing to sign against.

## Before you start

- Record the current value of `ZEROECHO_KEYRING_PASSWORD`. The keyring backup is
  useless without the correct password.
- Store the keyring backup and its unlock password under separate access control —
  but ensure both are retained so you can recover.

## Consistent backup procedure

Use the logical snapshot API described above for a running store. A physical
file-by-file copy requires every writer to be stopped. Storage snapshots need
deployment-specific consistency across all related roots; a snapshot's ability
to recover after a crash does not make rollback safe. Retain independent signing
authority outside the snapshot domain.

## Restore procedure

The supported local path is verification, `stageRestore`, a `STAGED` receipt,
store close, then cold reopen and confirmation of `ACTIVATED`. See
[Local staged restoration](#local-staged-restoration). Preserve the current root,
external control state and rollback roots while reconciling. There is no generic
unpack-and-start procedure that safely replaces those checks.

## Disaster recovery

Recovery after losing the live safety baseline requires an operator-specific
assessment of issuance, revocation, consumed identifiers, signing state and
external effects. Verification of an archive alone does not prove that it is safe
to resume signing. Preserve all surviving authority and retain an offline copy
before changing storage. Do not overwrite the live root or initialize fresh
stateful authority to bypass a restore rejection. Carry-forward merging is a
future extension, not an available recovery mode.

## Verification

After any restore, verify a representative set of operations through the admin
console or CLI before putting the instance back into service:

- `ca.inspect` on each authority — confirm its expected lifecycle state.
- `publication.list` on each authority — confirm artifacts are present.
- Issue a test certificate using the restored authority and verify it with the
  authority's certificate chain.

## Stateful signing authority

Applications using LMS/XMSS durable signing must preserve their local authority
outside every backup/restore and snapshot domain. Never restore or clone it
alongside a keyring. A stale keyring is rejected against the surviving authority;
loss or uncertain history of that authority retires its signing keys. Restoring
key material onto fresh infrastructure does not restore this permission. See
[the stateful-signing contract](../developer/stateful-signing.md).
