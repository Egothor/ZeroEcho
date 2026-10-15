# Backup format and resource contracts

The filesystem store exports format `zeroecho-pki-backup`, version 1, for its
current `v18` store layout. Server configuration version 8 is unrelated. Existing
store/key formats and public record components are unchanged. The additive
`BackupSource`, `BackupSink`, `BackupPreparation` and `BackupLimits` contracts live
in the existing exported `zeroecho.pki.api.backup` package.

The fresh metadata checkpoint preserves the pinned logical revision, each record's
revision and retained transaction results. Physical frame sequences are regenerated;
they do not replace the revisions used by compare-and-set or transaction resolution.

`createBackupSource` returns a file-backed artifact with an ID, exact byte length,
whole-file SHA-256 and independent input streams. Close streams and then the
source; source close also closes remaining streams and deletes its owned file.
Cleanup failures are reported and may be retried. `BackupSink.complete` forces
data, uses a same-directory atomic rename, forces the parent and transfers deletion
ownership to a source. Closing an incomplete sink aborts it. Unsupported atomic
publication has no weaker fallback.

Every untrusted source is copied into bounded owned storage before ZIP parsing.
The verifier compares actual bytes and SHA-256 with the source's claims. It owns
only its opened streams and temporary copies, not the caller's source. Failure
reports use stable `BACKUP_*` codes rather than archive names or local paths.

## Snapshot and inventory

A fair store-wide barrier admits complete operations before their domain/content
locks. Snapshot freezing and store close use exclusive access; close stops new
admission before draining operations. Content streams may cross threads: incomplete
writes remain outside the snapshot, while publication acquires admission per call.

The frozen directory contains a fresh complete metadata checkpoint and WAL,
committed revocation prefix, signing namespace, version marker, recognized request,
policy, profile and workflow records, and referenced committed content. Exact
file-name patterns govern both export and extraction. Referenced-content selection
and recovery expectations use temporary disk indexes rather than retained object
graphs. Files and directories are forced before releasing the freeze barrier.
Only the frozen tree is archived. The live mutable root is never recursively
archived. Modification times are preserved because legacy request queries use them.

Known key storage, locks, temporary files, unowned content, staging, backup storage,
derived indexes and arbitrary adjacent/server roots are excluded. Private keys
must not be persisted in accepted PKI domain records; the exporter does not attempt
to recognize secret material hidden inside opaque caller data.

## Envelope and manifest

The envelope is single-disk ZIP32 containing regular files only. The writer uses
STORED entries; the reader also supports DEFLATED entries. ZIP64, encryption,
extra fields, entry/archive comments, special/link/directory entries and unsupported
methods/flags are rejected. UTF-8 names use canonical forward-slash paths. Path
checks reject traversal, absolute/drive paths, backslashes, empty segments, Windows
aliases, case collisions, duplicate names and file/descendant conflicts.

Central-directory and local-header identities, offsets, extents and optional signed
data descriptors must agree exactly. There may be no gaps, overlaps, orphan local
entries or trailing bytes. Actual inflation is bounded and compared with lengths,
CRC and SHA-256; advertised sizes alone are never trusted.

`BACKUP-MANIFEST` is a bounded Java `DataOutputStream` encoding, in this order:

1. `writeUTF` format ID; 32-bit format version; `writeUTF` store version and backup ID.
2. 64-bit creation epoch seconds and canonical 32-bit nanoseconds.
3. 32-bit number of data files, followed in strict lexical path order by each
   `writeUTF` path, 64-bit nonnegative byte length, 32 SHA-256 bytes, and 64-bit
   last-modification epoch milliseconds.

The manifest does not list itself; its digest is exposed by `BackupPreparation`.
The archive inventory must equal the manifest inventory plus the manifest. Unknown
or trailing manifest data is rejected. Required files are `VERSION`,
`SIGNING_NAMESPACE`, `metadata/FORMAT`, `metadata/manifest.zem` and
`revocations/transitions.log`; referenced metadata/content is checked by normal
store recovery. The required empty `staged-content` directory is recreated by the
format rule, so ZIP directory entries are unnecessary.

The verifier opens a separate disposable extracted store through normal recovery
and validates legacy domain identities. Recovery never modifies the frozen
candidate. `prepareBackup` returns that candidate with explicit cleanup ownership;
it does not return activation success. Explicit local `stageRestore` publishes a
request for cold activation; `latestRestoreStatus` distinguishes staging,
activation, rejection and uncertain publication. Remote restore remains disabled.
See [Local staged restoration](../admin/backup-restore.md#local-staged-restoration)
for safety-authority comparison, lifecycle and deployment requirements.

## Limits and costs

Pass explicit `BackupLimits` to the additive four-argument `FilesystemPkiStore`
constructor to override defaults. Existing constructors retain these defaults:

| Resource | Default |
|---|---:|
| Complete archive | 1 GiB |
| Total expanded data, including manifest | 4 GiB |
| Individual entry | 512 MiB |
| Entry count, including manifest | 60,000 |
| UTF-8 path | 1,024 bytes |
| Manifest | 16 MiB |
| Legacy record decode buffer | 16 MiB |
| Expansion ratio per entry | 1,000 |
| Legacy byte-array adapter | 2 MiB |

The implementation transfers data in 64 KiB buffers. ZIP32 configuration limits
remain below its sentinel capacities; callers cannot enable ZIP64 by increasing a
limit. Legacy record decoding and ordinary recovery additionally use the declared
record limit and existing configured store index budgets. No complete archive or
content-file array is allocated on the primary path.

For B data bytes and E archive entries, transfer work is O(B), inventory sorting is
O(E log E), and retained envelope/manifest metadata is O(E times path length),
bounded by configured entry/path/manifest limits. Metadata validation and disk
indexes add streaming record passes and the existing indexed-store lookup costs.
Freeze time includes logical export, copying and forcing, but not ZIP creation.
No measured latency or throughput claim is made.

Private work lives under the store's excluded `.backup-work` directory. Verification
temporarily owns the bounded input plus two extracted copies (frozen candidate and
recovery copy). Successful cleanup removes each exact owned subtree without following
links. A cleanup failure is explicit; retained incomplete work is never returned as
a consumable backup. Operators may reclaim abandoned work only while the owning
process is stopped. Remote transfer owns a separate durable artifact spool with
explicit quotas and expiry; see [HTTP transfer](../admin/backup-restore.md#opt-in-http-transfer).
Local source/preparation owners must still close their handles. Cold coordinator
startup reclaims only recognized abandoned preparation directories under its own
external work root before admitting new store operations.
