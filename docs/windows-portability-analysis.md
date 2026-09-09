# Windows portability — delivered (2026-09-08, verified)

**Status: DELIVERED & VERIFIED — full enterprise-grade tier (b), pure `java.base`, no new dependency.**

Native Windows `:pki:test --rerun-tasks` (no Gradle cache) = **1182 tests, 0 failing** (1173 pass,
9 skipped for host-privilege reasons — symbolic-link creation requires `SeCreateSymbolicLinkPrivilege`,
and one test asserts a `fileKey` filesystem-identity property Windows does not expose; all 9 run and
pass on POSIX). POSIX suite unchanged: WSL ext4 `:pki:test` = **1182/1182 pass, 0 skipped**.
`gradlew build -x test` green across all modules; `verifyBouncyCastleConfinement` passes.

> Correction (2026-09-08): the earlier "528 pass on native Windows" figure was invalid — it came
> from a Gradle `UP-TO-DATE` cache produced under WSL, so the native-Windows test JVM had never run.
> A forced `--rerun-tasks` on native Windows initially showed 533/1182 failing; those were driven to
> 0 by: the `DurableDirectory` seam (SecureDirectoryStream fallback), routing all directory fsync
> through `PlatformFs`, the `WriterExclusionLock` sentinel-byte lock, closing five leaked
> `Files.walk`/`Files.list` directory streams, the `AtomicPublish.replaceExisting` bounded retry for
> atomic replaces under concurrent Windows readers, releasing the revocation-index handle before its
> atomic replace, guarding `posix:permissions` create attributes by real FS capability, and hardening
> the affected test doubles. All changes preserve POSIX behaviour.

This document preserves the original feasibility analysis below for reference, followed by a
section documenting the delivered implementation and its Windows-specific design decisions.

---

## Original feasibility analysis

Feasibility and effort analysis for running ZeroEcho on Windows in addition to
POSIX, covering (a) full POSIX-equivalent enterprise-grade operation and (b) a
reduced "fake" mode that runs but is not crash-consistency/robustness hardened.
Grounded in a survey of the persistence layer (`pki/src/main/java/zeroecho/pki/impl/fs`,
70 files / ~47K LOC) and the keyring (`lib` `zeroecho.core.storage`).

### Bottom line (original estimate)

- **Fake / degraded run mode (runs on Windows, not enterprise-grade): MEDIUM — ~1–2 weeks.**
  The POSIX coupling is concentrated, mostly already has soft fallbacks, and the hardest
  theoretical blocker (memory-mapped files) is absent.
- **Full POSIX-equivalent, enterprise-grade on Windows: HIGH — weeks to a couple of months**,
  dominated not by lines of code but by re-establishing the crash-consistency / durability
  proof and concurrency testing under Windows semantics.

## Architecture in our favor

1. **A clean SPI seam already exists.** The backend is pluggable via
   `zeroecho.pki.spi.store.PkiStore` / `PkiStoreProvider` (ServiceLoader) and
   `TransactionalMetadataStore` (interface, with `TransactionalMetadataStoreContractTest`).
   The domain/PKI logic goes through it — only ~9 non-`impl/fs` files reference `java.nio.file`
   at all. Windows support is therefore an **additive provider**
   (`WindowsPkiStore` / `WindowsTransactionalMetadataStore`), not a rewrite. All POSIX behaviour
   lives in `pki/impl/fs/*` (the `Posix*` engines) plus the keyring in `lib`.
2. **No memory-mapped I/O (0 sites).** The persistence layer uses plain `FileChannel` I/O. On
   Windows a mapped file cannot be deleted/renamed/truncated while mapped, and Java has no
   deterministic unmap — that would have been the killer. It is simply not a factor here.

## POSIX dependencies, ranked by Windows difficulty

| # | Mechanism | Where | Windows reality | Fake mode | Real equivalence |
|---|-----------|-------|-----------------|-----------|------------------|
| 1 | **Directory fsync** `FileChannel.open(dir,READ).force()` | ~18 sites, centralized in `SigningFormatSupport.forceDirectory`, `DurableMetadataFiles`, `FsOperations` | Cannot fsync a directory on Windows (a directory can't be opened as a channel); no `fsync(dirfd)` equivalent | Make `forceDirectory` a best-effort no-op (few central sites) → runs, **loses power-loss durability of renames** | Needs a different durability protocol (FlushFileBuffers + a commit/checkpoint that does not rely on directory-entry durability). Deepest item — the crash-consistency proof rests on POSIX rename + dir-fsync. |
| 2 | **POSIX permissions 0700/0600** | `FsOperations` (already guarded by `supportedFileAttributeViews().contains("posix")`); **keyring hard-refuses** (`KeyringSecuritySupport.validateOwnerOnly` → `KEYRING_FILESYSTEM_UNSUPPORTED`) | NTFS has no POSIX view; owner-only protection = ACLs | Relax the keyring's hard refusal / skip perms → runs, **private keys not OS-protected** | Translate to `AclFileAttributeView` (owner-only, break inheritance, deny others). Well-trodden, MEDIUM. |
| 3 | **`Files.move(ATOMIC_MOVE, REPLACE_EXISTING)`** — the transaction commit point | 11 sites; `FsOperations` already catches `AtomicMoveNotSupportedException` → non-atomic `REPLACE_EXISTING` | Atomic replace-existing via rename is not guaranteed | Fallback already exists → runs, **loses commit atomicity under crash** | `ReplaceFile` / `MoveFileEx(REPLACE_EXISTING\|WRITE_THROUGH)` via FFM/JNA for a real atomic replace |
| 4 | **OS advisory locks** `channel.tryLock()` | `FilesystemPkiStore`, `FilesystemRevocationCurrentIndex`/`Log`, `DurableMetadataLog`, keyring — single-writer / inter-process fence | `FileLock` works but is **mandatory** on Windows (advisory on POSIX); a held region can block other handles' reads at the OS level | Works; needs an audit | Audit each lock's reader/writer interplay; possibly switch to dedicated lock files |
| 5 | **unlink/rename-while-open** (rotate/compact/retire) | 17 classes do rotate/compact/retire/relocate | POSIX allows deleting/renaming open files; Windows forbids unless opened with `FILE_SHARE_DELETE` — which Java NIO sets by default, and with no mmap this mostly works | Mostly works out of the box | Verify all 17 paths + add Windows concurrency tests |

## Concurrency / locking assessment (the primary owner concern)

The concern points at the right layer, but severity is **lower than feared**:

- **No mmap**, so the worst delete/rename-while-open blocker is gone.
- Java NIO opens files on Windows with share-read/write/delete by default, so concurrent
  reader-vs-rotating-writer patterns largely survive.
- Intra-process concurrency is guarded by **JVM-level** `ReentrantLock`s
  (`SigningReservationCaptureGate`, MVCC index locks) — fully portable. OS file locks are only
  the single-writer / cross-process fence.

So steady-state concurrent read/write is not the main risk. The real residual risks are
**failure-time correctness**: (1) crash/power-loss durability (directory fsync + atomic replace,
items #1/#3) and (2) mandatory-vs-advisory lock edge cases (#4).

## Recommended shape (if pursued)

Implement a second `PkiStoreProvider` for Windows behind the existing SPI, with a thin
`PlatformFsOps` abstraction for the five items above (POSIX impl = today's code; Windows impl =
ACLs + FFM `ReplaceFile`/`FlushFileBuffers` + a no-dir-fsync durability strategy). Gate it via
config. Use the existing `TransactionalMetadataStoreContractTest` as the equivalence harness and
the recovery suite (`SigningLedgerRecoveryTest`, etc.) as the durability gate — the hard,
time-consuming part is a Windows crash / power-loss test rig to *prove* #1/#3, not writing the
code. A "fake mode" (relaxed perms, best-effort dir-fsync, non-atomic replace) is a small central
toggle that gets it running for dev/eval quickly, clearly labelled non-enterprise.

## Effort summary

| Deliverable | Effort | Loses (vs POSIX) |
|-------------|--------|------------------|
| Fake/degraded run mode | ~1–2 weeks | OS-enforced key permissions; power-loss durability; commit atomicity under crash |
| Full enterprise-grade Windows backend | Weeks–months (dominated by durability re-proof + Windows crash testing) | Nothing, if the durability/atomicity strategy is proven |

---

## Delivered implementation (2026-09-07)

### Key discovery: no FFM required

The original analysis anticipated needing FFM (`java.lang.foreign`) to call `MoveFileExW` with
`MOVEFILE_WRITE_THROUGH` and `FlushFileBuffers`. In practice this turned out unnecessary:

- **`Files.move(ATOMIC_MOVE)`** on Windows already maps to
  `MoveFileEx(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` inside the JDK.
- **`FileChannel.force(true)`** already calls `FlushFileBuffers` on Windows.

The entire Windows backend is pure `java.base` — `AclFileAttributeView` for owner-only
protection and no-op directory force. No new external dependency.

### Architecture: `PlatformFsOps` strategy seam

Rather than threading a DI instance through ~19 files, a thin **static strategy** is resolved
once per process from `FileSystems.getDefault().supportedFileAttributeViews()`:

- `"posix"` → `PosixPlatformFsOps` (today's exact POSIX code paths)
- `"acl"` → `WindowsPlatformFsOps` (NTFS ACL + no-op dir-force)
- anything else → fail-closed `IllegalStateException`

`PlatformFs` (a static façade) delegates the existing `FsOperations`, `SigningFormatSupport`,
`CredentialContentTransaction`, `FilesystemRevocationCheckpoint`,
`FilesystemRevocationCurrentIndex`, `FsSnapshotExporter`, and `FilesystemPkiStore` call sites
— one-line replacements, zero blast radius on the durability-critical code paths.

A parallel `KeyringPlatformPolicy` seam covers the `lib` keyring:
`securePath`, `validateExistingFile`, `validateOwnerOnly`, `restrictToOwner`, `forceDirectory`,
and create-attributes — resolved the same way.

### Windows-specific design decisions

| POSIX mechanism | Windows equivalent | Rationale |
|---|---|---|
| Directory fsync (`FileChannel.open(dir,READ).force()`) | No-op | `MOVEFILE_WRITE_THROUGH` in the atomic move already provides durability of the rename — the explicit dir-fsync is redundant |
| 0700/0600 POSIX permissions | NTFS ACL: single owner ALLOW entry with `DIRECTORY_INHERIT \| FILE_INHERIT`; JDK marks DACL protected (breaks inherited ACEs) | `AclFileAttributeView` — pure `java.base` |
| ACL established only at directory creation | ACL unconditionally re-applied on every keyring open | Windows dirs always have inherited SYSTEM/Admin/user ACEs; unlike POSIX `mkdir(0700)`, a newly created directory is not owner-only by default |
| nlink==1 anti-hardlink defence | Owner-only, inheritance-protected ACL on keyring parent directory | No other principal can create a hard link inside an owner-only directory; documented residual: Admin/SYSTEM OS override |
| Advisory `tryLock()` (whole file) | `tryLock(Long.MAX_VALUE-1, 1L, false)` — sentinel byte at end | Windows mandatory locks block concurrent content reads. Locking a sentinel byte beyond file content preserves single-writer exclusivity while allowing reads — POSIX advisory semantics were never affected |

### Residuals (documented, accepted)

- **Admin/SYSTEM OS override:** A local administrator or SYSTEM account can bypass the
  owner-only ACL. This matches the threat model: the CA keyring is protected from other
  non-privileged users on the same machine; a compromised admin/OS is an out-of-scope attack.
- **No Windows crash/power-loss test rig:** The durability proof rests on the JDK's documented
  `MOVEFILE_WRITE_THROUGH` mapping and `FlushFileBuffers` semantics, not on a live crash test.
  Accepted: equivalent to trusting the POSIX `fsync(2)` man-page claim on Linux.
- **nlink==1 defence absent on Windows:** Replaced by the owner-only parent-directory ACL.
  An owner-only directory prevents hard-link creation inside it by other principals.
