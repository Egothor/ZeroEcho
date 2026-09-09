# Requirements

The ZeroEcho PKI server keeps its system of record on a local filesystem and
relies on POSIX semantics for durability and access control. Before you deploy,
confirm that the host, the container runtime, and — above all — the storage that
backs the store and keyring meet the requirements below.

## Platform

- **Operating system:** a Linux or POSIX host. The server image is built on a
  Java 25 runtime and runs as a non-root user. The store and keyring components
  require POSIX filesystem behaviour and will not provide their durability or
  permission guarantees elsewhere.
- **Container runtime:** any OCI-compatible runtime — Docker, Podman, or a
  Kubernetes node runtime such as containerd. The reference stack is expressed as
  a Docker Compose file and as Kubernetes manifests.
- **Architecture:** the images are built from a standard JRE base and the stock
  nginx image; build them for the CPU architecture of your target hosts.

## Filesystem guarantees for the store and keyring

The filesystem store and the CA signing keyring depend on four POSIX behaviours.
If any of them is missing, the platform silently loses the guarantee that behaviour
provides.

| Guarantee | Used for | Consequence if absent |
|---|---|---|
| **`0700` / `0600` permission enforcement** | Owner-only access to the store directory and to private-key files in the keyring | Private-key material becomes readable by other users. The keyring **hard-refuses to run** without owner-only permission support. |
| **Atomic rename** | The commit point of every durable write | Partially written state can become visible after a crash; the store loses crash-consistency. |
| **Directory `fsync`** | Flushing directory entries so a rename survives power loss | A committed change can be lost across an unclean shutdown. |
| **Advisory file locking (`flock`)** | The single-writer fence that stops two servers from opening the same store | Two processes could corrupt the store by writing concurrently. |

!!! warning "One writer per store"
    The store takes an exclusive advisory lock on open. Never point two running
    servers at the same store or keyring volume, and never share those volumes
    between replicas. This is why the Kubernetes deployment runs a single replica
    per realm store (see [Kubernetes](kubernetes.md)).

### Why object-store FUSE and Windows bind mounts are unsuitable

The store and keyring must be **local POSIX filesystems** (or block volumes
formatted with one). The following storage types do not satisfy the guarantees
above and must not back the store or keyring:

- **Object-store gateways mounted through FUSE** (for example, an S3-backed FUSE
  filesystem). These typically emulate rename as copy-plus-delete, do not honour
  directory `fsync`, and provide no advisory locking. A crash mid-write can leave
  the store inconsistent.
- **Windows host paths and SMB/CIFS shares** bind-mounted into a container. These
  do not enforce POSIX `0700`/`0600` permissions and do not offer the same rename
  and lock semantics. The keyring will refuse to start; the store will run without
  its durability and permission guarantees.

Published artifacts and the audit sink are more tolerant — the artifacts directory
is reconstructible from the store, and the audit sink is append-heavy — but for
simplicity, back all four volumes with the same class of durable POSIX storage.

!!! tip "Verify before committing to storage"
    On the host filesystem you intend to use, confirm that a file created with
    mode `0600` retains those permissions, that `rename(2)` is atomic, and that
    `flock(2)` is honoured. A quick check now avoids a durability surprise later.

## Sizing guidance

The workload is I/O-bound around signing and durable commits rather than
CPU-bound. Treat the following as starting points and adjust against your issuance
rate and retention policy.

| Resource | Starting point | Notes |
|---|---|---|
| **CPU** | 2–4 cores for the PKI server; 1 core for nginx | The server pools transport and operation workers; signing throughput benefits from more cores under load. |
| **Memory** | 1–2 GiB for the PKI server; 128–256 MiB for nginx | The server is a JVM process; size the heap to your issuance concurrency. |
| **Store storage** | Grows with the number of authorities, requests, credentials, and metadata-log entries | Provision a durable volume with headroom; this is the system of record. |
| **Keyring storage** | Small — private-key material only | Keep it on a separate, more strictly controlled volume. |
| **Artifacts storage** | Grows with published certificates and CRLs | Reconstructible from the store by republishing. |
| **Audit storage** | Append-heavy; grows with activity | Size to your audit-retention policy. |

The reference Kubernetes manifest requests 20 GiB for the store, 1 GiB for the
keyring, 5 GiB for artifacts, and 10 GiB for audit. These are illustrative
defaults, not recommendations for a specific realm.

Continue to [Container images](containers.md) to build or obtain the two images,
or to [Configuration](configuration.md) for the full volume and environment
contract.
