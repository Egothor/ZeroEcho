# Configuration

The store volume mounts at `/var/lib/zeroecho/store-container`, with PKI state
under `store/` and server-control state under `server-control/`. The writable
parent also retains cold-restore journals and rollback roots. Existing volumes
need the explicit [offline layout migration](operations.md#offline-layout-migration);
never point a new child configuration at an unmigrated old root.

The PKI server keeps no secrets and no storage locations baked into its image.
Everything it needs at run time arrives through three channels: persistent data
volumes, read-only configuration mounts, and environment variables for secrets.
This page is the contract for all three. The exact field names come from the strict
versioned server configuration; the [configuration reference](../reference/configuration-reference.md)
documents each field in full.

## Volumes

Four persistent volumes hold the server's state. The store and keyring are kept on
**separate** volumes so the keyring, which holds private-key material, can be
placed on stricter, separately backed storage.

| In-container path | Purpose | Permissions | Persistence guidance |
|---|---|---|---|
| `/var/lib/zeroecho/store-container` | Main PKI store — authorities, requests, credentials, revocations, the metadata log, staged content, and the control log | dir `0700` | The system of record. Back it up consistently. Never share it between two running servers. |
| `/var/lib/zeroecho/keyring` | CA signing keyring (private-key material) | dir `0700`, keys `0600` | A separate, stricter volume from the store. Restrict access and backups; apply separate key management if available. |
| `/var/lib/zeroecho/artifacts` | Published objects written by the filesystem publisher (CA certificates, leaf certificates, CRLs) | dir `0750` | Durable but reconstructible — it can be republished from the store. |
| `/var/lib/zeroecho/audit` | Durable audit sink | dir `0750` | Retain per your audit-retention policy. Append-heavy. |

The image pre-creates these directories owned by uid `10001` (`zeroecho`). A fresh,
empty Docker named volume inherits that ownership on first mount. A bind mount does
not — set ownership and permissions on the host path before the first start. On
Kubernetes, the StatefulSet sets `fsGroup: 10001` so the claims are group-writable
by the runtime user.

!!! warning "Store and keyring must be POSIX filesystems"
    The store and keyring depend on POSIX permission enforcement, atomic rename,
    directory `fsync`, and advisory locking. A non-POSIX bind mount silently drops
    those guarantees, and the keyring refuses to start without owner-only
    permission support. See [Requirements](requirements.md#filesystem-guarantees-for-the-store-and-keyring).

!!! tip "Backup and restore procedures"
    The paths and permissions listed here are the source of truth for volume
    layout. For backup strategies, snapshot guidance, and step-by-step restore
    and disaster-recovery procedures, see [Operations](operations.md#backup-and-restore).

## Read-only configuration mounts

The server's behaviour is driven by files mounted read-only. They are never written
back and can be sourced from host files, Docker secrets, or Kubernetes ConfigMaps
and Secrets.

| Mount | Source | Purpose |
|---|---|---|
| `/etc/zeroecho/server-config.json` | operator file or ConfigMap | The strict versioned server configuration. Validated by `--validate-config` at start-up (fail-fast). |
| `/etc/zeroecho/profiles/` | operator directory or ConfigMap | One certificate-profile document per file. Reconciled at start-up. |
| TLS material directory | operator directory or Secret | The server's own PKCS#12 stores, referenced from the server configuration. Mounted at `/var/lib/zeroecho/tls/` in the Compose stack and `/etc/zeroecho/tls/` on Kubernetes. |
| `/etc/zeroecho/health/` | operator directory or Secret | The health-probe client identity used by the container and probe checks. |

The entrypoint's start-up sequence — validate, reconcile profiles, then start the
server — is described in [Container images](containers.md#the-pki-server-image).

### The server configuration file

The server configuration is a single strict versioned JSON document. It contains
**no secrets** — only the *names* of the environment variables that hold them. In
the reference trusted-reverse-proxy topology, its notable sections are:

- `listener` — the admin mutual-TLS listener on `0.0.0.0:8443`, with a
  `tlsProvider` that names its PKCS#12 key store and trust store and the
  environment variables holding their passwords. `clientCertificateRequired` is
  `true`.
- `authentication` — `mode: TRUSTED_REVERSE_PROXY`, the forwarded-certificate
  format (`RFC9440`) and header name (`Client-Cert`), the mapping from the reverse
  proxy's transport certificate to a trusted-proxy principal, the mapping from the
  forwarded administrator leaf to an administrative principal, and the
  `administrativeClientTrust` that validates the forwarded leaf.
- `realm.pkiSession` — the store, audit sink, signing workflow (including the
  keyring path and its unlock environment variable), and the publishers.
- `runtime.keyUnlockEnvironmentVariable` — the environment variable that unlocks
  the signing keyring.

Point every path in the configuration at an in-container mount. The canonical
mapping used by the reference artifacts is:

| Configuration field | In-container path |
|---|---|
| store `root` | `/var/lib/zeroecho/store-container/store` |
| audit `root` | `/var/lib/zeroecho/audit` |
| publisher `root` | `/var/lib/zeroecho/artifacts` |
| signing `keyringPath` | `/var/lib/zeroecho/keyring/ca-keyring.zek` |
| `controlLog` | `/var/lib/zeroecho/store-container/server-control/server-control.log` |
| TLS PKCS#12 stores | `/var/lib/zeroecho/tls/...` (Compose) or `/etc/zeroecho/tls/...` (Kubernetes) |

!!! tip "Prefer absolute in-container paths"
    The server's working directory is `/var/lib/zeroecho`, so a relative path such
    as `tls/server-identity.p12` resolves under it. Absolute paths remove the
    ambiguity — the Kubernetes ConfigMap uses them throughout.

### Preflight validation

The entrypoint runs a configuration preflight before anything else:

```bash
zeroecho-pki-server --validate-config --config /etc/zeroecho/server-config.json
```

This parses and fully validates the document without opening providers, listeners,
or the store. Run it yourself against a candidate configuration before a deploy to
catch mistakes early; a non-zero exit means the server would refuse to start.

## Secrets: environment variables only

Every password reaches the server **only** through the process environment. The
server configuration names the variable; the value never appears in the image or in
any file on disk. The variable name must match the pattern `[A-Z][A-Z0-9_]{0,127}`.

| Variable | Consumed by | Purpose |
|---|---|---|
| `ZEROECHO_KEYRING_PASSWORD` | `runtime.keyUnlockEnvironmentVariable` and/or signing `unlockEnvironmentVariable` | Unlocks the CA signing keyring. |
| `ZEROECHO_TLS_KEYSTORE_PASSWORD` | listener `tlsProvider.keyStorePasswordEnvironment` | Password for the server's own identity PKCS#12 store. |
| `ZEROECHO_PROXY_TRUSTSTORE_PASSWORD` | listener `tlsProvider.trustStorePasswordEnvironment` | Password for the trust store that admits the reverse proxy's transport certificate. |
| `ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD` | `administrativeClientTrust.trustStorePasswordEnvironment` | Password for the trust store that validates the forwarded administrator leaf. |
| `ZEROECHO_PUBLISHER_SECRETS_PASSWORD` | `runtime.publisherSecretsEnvironmentVariable` | Unlocks the publisher secrets store for CLASSIC and HYBRID protection profiles. |

In Compose these come from `deploy/.env`; on Kubernetes they come from a Secret
projected with `envFrom`. The environment template also carries the host paths and
edge settings:

```bash
# Secrets (passwords-by-env). Never commit a filled-in .env.
ZEROECHO_KEYRING_PASSWORD=change-me-keyring
ZEROECHO_TLS_KEYSTORE_PASSWORD=change-me-tls-keystore
ZEROECHO_PROXY_TRUSTSTORE_PASSWORD=change-me-proxy-truststore
ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD=change-me-admin-truststore

# Host paths mounted read-only into pki-server.
ZEROECHO_SERVER_CONFIG_FILE=./config/server-config.json
ZEROECHO_PROFILES_HOST_DIR=./config/profiles
ZEROECHO_TLS_HOST_DIR=./tls/server
ZEROECHO_HEALTH_HOST_DIR=./tls/health

# nginx edge.
NGINX_SERVER_NAME=pki.example.com
PKI_PROXY_SSL_NAME=zeroecho-admin
NGINX_EDGE_TLS_DIR=./tls/edge
NGINX_ADMIN_TRUST_DIR=./tls/admin-trust
NGINX_UPSTREAM_TLS_DIR=./tls/upstream
```

## TLS and PKCS#12 material

The two containers hold distinct TLS material. Keep the administrators' trust
anchors consistent: the edge's browser-mTLS trust bundle and the server's
`administrativeClientTrust` must share the same anchors.

| Container | Files | Role |
|---|---|---|
| PKI server TLS dir | `server-identity.p12` | Server certificate and key for the admin listener. |
| PKI server TLS dir | `proxy-transport-trust.p12` | Trusts the edge's transport client certificate (listener client trust). |
| PKI server TLS dir | `administrators-trust.p12` | Trusts the administrator client certificates forwarded by the edge. |
| nginx `/etc/nginx/tls/edge/` | `edge.crt`, `edge.key` | The browser-facing server certificate. |
| nginx `/etc/nginx/tls/admin-trust/` | `admin-ca-bundle.pem` | CA bundle that browser client certificates must chain to. Same anchors as `administrators-trust.p12`. |
| nginx `/etc/nginx/tls/upstream/` | `proxy-client.crt`, `proxy-client.key`, `pki-server-ca.pem` | The edge's transport client identity for upstream mutual-TLS, and the CA that verifies the server certificate. |

## Changing a certificate profile

Certificate profiles live in the read-only profiles mount and are reconciled at
start-up. To change one:

1. Edit or add the profile document in the profiles source — a host directory, or
   the profiles ConfigMap on Kubernetes.
2. Restart the server. The entrypoint registers and activates any profile whose
   identifier is not already present in the store.

!!! warning "Editing an existing profile requires changed content"
    The bootstrap skips a profile when its active version already has identical
    content (SHA-256 of the canonical document matches); changed content is always
    re-registered and activated. Restarting with an unmodified profile document
    is a no-op for that profile. To change an active profile, update the document
    content in the profiles source before restarting, or register a new version
    through the console or the [command line](../admin/command-line.md). Set
    `ZEROECHO_PROFILE_RECONCILE=off` to disable the start-up reconcile if a
    separate process owns profile lifecycle.

## Pointing the store at a persistent volume without rebuilding

The store location is configuration plus a mounted volume — never baked into the
image. Because the configuration uses in-container paths, you can repoint the
underlying storage freely without touching the image or the configuration.

=== "Compose"

    The named volume `store` maps to `/var/lib/zeroecho/store-container`. To use a specific
    host path, replace the named volume with a bind mount — after setting its
    ownership to uid `10001` and mode `0700` — or declare the named volume as
    `external: true`. No rebuild is needed; the configuration's store `root`
    already points at `/var/lib/zeroecho/store-container/store`.

    ```yaml
    volumes:
      - type: bind
        source: /data/zeroecho/store
        target: /var/lib/zeroecho/store-container
    ```

=== "Kubernetes"

    The `store` volume-claim template binds a PersistentVolumeClaim to
    `/var/lib/zeroecho/store-container`. Set `storageClassName` to a POSIX class, or
    pre-provision the PersistentVolume. The configuration ConfigMap points the
    store `root` at the same in-container path.

    ```yaml
    volumeClaimTemplates:
      - metadata: {name: store}
        spec:
          accessModes: ["ReadWriteOnce"]
          storageClassName: <posix-fs-class>
          resources: {requests: {storage: 20Gi}}
    ```

The same pattern applies to the keyring, artifacts, and audit volumes.

## Signing provider

The `realm.pkiSession.signing` block selects the provider that performs CA signing
operations. The default provider (`zeroecho-lib`) keeps private keys in the local encrypted
keyring. When keys must stay outside the PKI server process — for HSM integration, a
separate signing node, or an operator-approval flow — use the
[remote signing provider](remote-signing-provider.md) instead.

Continue to [Kubernetes](kubernetes.md) for a full manifest walkthrough, or to
[Security hardening](security-hardening.md) for the trust model these mounts
implement.
