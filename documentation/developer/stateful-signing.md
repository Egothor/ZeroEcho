# Durable LMS and XMSS signing

Stateful signing is available through `KeyringStore.generateStatefulKey` and
`StatefulSigner`, using a separately preserved `LocalStatefulSigningAuthority`.
This local authority is the default supported model (Option A). An independent
service or hardware authority (Option B) is deferred as a possible future
administrator-selected alternative; it is not implemented.

## Ownership and enrollment

Create the authority once in a new secured directory, outside the keyring
directory **and every PKI, backup, snapshot and restore domain**. The library
enforces exclusion from the keyring's immediate parent; administrators must
enforce the wider storage separation. Use `open` on subsequent starts. Never
clone, roll back, move, replace or reconstruct the authority. All users of a
key must consult the same surviving authority. Authority loss or unverifiable
history permanently retires affected signing keys; ordinary key backups cannot
restore signing permission.

```java
try (LocalStatefulSigningAuthority authority =
        LocalStatefulSigningAuthority.create(authorityDirectory)) {
    PublicKey publicKey = keyring.generateStatefulKey("signing", "LMS", authority);
    StatefulSigner signer = keyring.statefulSigner("signing", authority);
    byte[] signature = signer.sign(content, cancellation, maximumMessageBytes);
}
```

The example assumes an open caller-owned `KeyringStore`, `RepeatableContent`,
`CancellationSignal` and explicit application input-size policy. The signer
borrows both the store and authority. The caller closes them after use. Content
is borrowed; the opened input stream is always closed.

Enrollment generates a fresh key internally: imported keys cannot be enrolled
or reset. This API currently supports the algorithm defaults: LMS SHA-256 h5/w8
(32 leaves), and XMSS SHA-256 h10 (1024 leaves). `requiresStatefulSigning()` is
algorithm metadata, not permission. Ordinary signature contexts,
`KeyringSignatureExecutor`, hybrid/PKIX helpers and built-in PKI providers still
reject stateful signing; they have no durable authority. Verification and import
remain available. Signature length comes from public parameters without signing
a probe.

## Durable protocol and failure handling

The keyring's write lock and lifetime filesystem ownership fence combine with
the authority's lifetime filesystem lock and monitor. Another process opening
the same authority is rejected, rather than queued. All keys and keyrings using
one open authority serialize, including input I/O and signing. Path, store
identity, alias, public-key fingerprint, algorithm, index, capacity and private
state commitment are authenticated. Moving or copying a keyring does not grant
new signing permission.

Each signature uses the following protocol:

1. Reload and authenticate the current private state and READY authority record.
2. Durably publish RESERVED with the next high-water index.
3. Extract a one-use provider shard and atomically persist the advanced parent.
4. Durably publish READY with the advanced state commitment.
5. Sign with the shard and release the signature.

Both publications use owner-only temporary files, forced contents, atomic
replacement and a forced containing directory. A write failure poisons the
current owner. Reopen can proceed only if disk contains a complete matching
READY state; a pending or mismatched state fails with
`KEYRING_STATEFUL_RECOVERY_REQUIRED`. There is no automatic reset, reconstruction
or leaf retry. If no signature was released, a completely committed transition
may still have burned a leaf. Content failure or cancellation after commitment
also burns its leaf. Temporary files left by abrupt termination are never read
as authoritative records; retain the authority records, including exhausted
ones. Investigate pending state and retire the affected key; this version has
no reconciliation API for reactivating it.

At exhaustion, the final transition durably removes the private entry and
retains the public key plus authenticated terminal authority record. Further
signing fails with `KEYRING_STATEFUL_EXHAUSTED`; private-key retrieval is then
unavailable. This also avoids BC 1.86's inability to import its exhausted
single-tree LMS/HSS encoding. Canonical import validation remains enforced.
Restoring any earlier private entry against the terminal authority is rejected.

## Backup, resources and compatibility

Backups of keyrings may retain old private states. Such states must never be
used independently, re-enrolled or paired with a restored authority snapshot.
The surviving authority rejects stale state, even if the keyring image itself
is authentic. Complete rollback of both keyring and authority at their original
paths is outside Option A's supported contract: software cannot distinguish it
from valid history. Preserve the authority independently or retire the keys.

The encrypted keyring stays at format version 2. Authority files use a separate
version-1 format; missing, corrupt, future or moved authority state fails closed.
The new public APIs are additive. Existing stateless behavior is unchanged.

For S keyring bytes, E entries and M message bytes, signing performs O(S + E + M)
work and O(S + E + M) auxiliary memory for XMSS, in addition to provider
cryptographic costs. BC's unprehashed XMSS signer buffers the message; the
explicit input-size limit is not an exact heap budget. LMS uses an 8 KiB transfer
buffer. An authority record is bounded to 32 KiB, with O(1) directly addressed
record access and O(K) retained records for K enrolled keys.

Each ordinary signature rewrites the whole encrypted keyring. Final exhaustion
also re-encrypts Q entries after the removed private entry because their
authenticated positions change, requiring O(Q) durable nonce publications
(up to 16,383), then one image publication. Final signing can therefore be much
slower. No throughput or latency guarantee is implied.

The caller must provide bounded or interruptible content I/O. Byte limits do
not bound elapsed time: a blocked read holds the shared authority and delays
store/authority closure. Cancellation is cooperative between reads and does
not interrupt lock acquisition. Private byte arrays are wiped and exclusively
owned provider keys receive best-effort destruction; providers that do not
support destruction retain internal objects until garbage collection.
