# ZeroEcho PKI — deployment artifacts

Container and orchestration artifacts for the ZeroEcho PKI platform (Task 15).
This directory is self-contained: it only adds files under `deploy/` and does not
modify `pki-frontend/`, `app/`, `pki-server/`, `pki/`, or `lib/`.

> **Authoring caveat.** These artifacts were authored and **statically
> validated** without a container engine (no Docker/Podman was available). They
> have **not** been built or run. `nginx -t` was not executed. YAML was
> parse-checked and the shell scripts were `sh -n` syntax-checked. Do not treat
> "images build/run" as verified — build and run them on a POSIX/Docker host.

## Topology

```
administrator browser  --mTLS-->  nginx (edge)  --mTLS-->  pki-server (admin listener)
        client cert          terminates cert,          TRUSTED_REVERSE_PROXY,
                             forwards RFC 9440          verifies proxy + forwarded
                             Client-Cert header         identity independently
```

* The **browser** presents an administrator client certificate to **nginx**.
* **nginx** terminates that certificate (`ssl_verify_client on`), then
  re-presents the verified leaf to **pki-server** as an RFC 9440 `Client-Cert`
  header while authenticating to pki-server with its **own** transport client
  certificate. pki-server runs in `TRUSTED_REVERSE_PROXY` mode and independently
  validates both identities.
* pki-server serves the static SPA? No — **nginx** serves the SPA bundle; the
  server exposes only the JSON admin/public/health API.

## File tree

```
deploy/
  README.md                      # this file — the data/config contract
  .env.example                   # every env var / secret a deployer sets
  smoke-test.sh                  # container smoke test (curl over mTLS)
  pki-server/
    Dockerfile                   # multi-stage; non-root; installDist of server + CLI
    entrypoint.sh                # validate-config preflight + profile reconcile + exec
  nginx/
    Dockerfile                   # nginx + njs; bakes SPA bundle + config
    nginx.conf                   # main config (loads njs, RFC 9440 forwarding)
    conf.d/
      default.conf.template      # TLS server block (envsubst at start-up)
    njs/
      client_cert.js             # PEM -> RFC 9440 :base64(DER): converter
  compose/
    docker-compose.yml           # pki-server + nginx, volumes, secrets, healthchecks
  k8s/
    00-namespace-config.yaml     # Namespace, ConfigMaps, Secrets
    10-pki-server.yaml           # StatefulSet (PVCs) + headless Service
    20-nginx.yaml                # Deployment + Service
```

## POSIX filesystem requirement (read this first)

ZeroEcho's filesystem store and keyring depend on POSIX semantics: **0700/0600**
permission enforcement, **atomic rename** at the commit point, **directory
fsync** for crash-consistency, and **advisory `flock`** for the single-writer
fence. See [`docs/windows-portability-analysis.md`](../docs/windows-portability-analysis.md).
The `store` and `keyring` volumes **must** be POSIX filesystems. A non-POSIX
bind mount (e.g. an SMB/CIFS share, or a Windows host path) will silently drop
durability and permission guarantees. The keyring additionally **hard-refuses**
to run without owner-only permission support.

## Data / config contract

### Volumes

| Mount (in-container) | Purpose | POSIX perms | Persistence guidance |
|---|---|---|---|
| `/var/lib/zeroecho/store` | Main PKI store (CAs, requests, credentials, revocations, metadata log, staged content) **and** `server-control.log` | dir `0700` | **Stable, durable PV.** This is the system of record. Back it up consistently; never share it between two running servers (single-writer flock). |
| `/var/lib/zeroecho/keyring` | CA signing keyring (`.zek`) — private-key material | dir `0700`, keys `0600` | **Separate, stricter volume** from the store. Restrict backups/access; separate encryption/key-management if available. |
| `/var/lib/zeroecho/artifacts` | Published objects (CA certs, leaf certs, CRLs) written by the filesystem publisher | dir `0750` | Durable but reconstructible; can be republished from the store. |
| `/var/lib/zeroecho/audit` | Durable audit sink (`file` provider `root`) | dir `0750` | Durable; retain per your audit-retention policy. Append-heavy. |

Ownership: the image pre-creates these directories owned by uid **10001**
(`zeroecho`). A fresh, empty **Docker named volume** inherits that ownership on
first mount. A **bind mount** does not — `chown -R 10001:10001` the host path and
`chmod 700` the store/keyring paths before first start. On Kubernetes, the
StatefulSet sets `fsGroup: 10001` so the PVCs are group-writable by the runtime
user.

### Read-only config mounts

| Mount | Source | Notes |
|---|---|---|
| `/etc/zeroecho/server-config.json` | operator file / ConfigMap | Strict versioned JSON, **schema version 7**. Start from [`docs/pki-server-trusted-proxy-rfc9440-example.json`](../docs/pki-server-trusted-proxy-rfc9440-example.json) for this topology. Validated by `--validate-config` at start-up (fail-fast). |
| `/etc/zeroecho/profiles/` | operator dir / ConfigMap | One `*.json` certificate-profile document (**schemaVersion 5**) per file. Reconciled at start-up (see below). |
| `/var/lib/zeroecho/tls/` (compose) or `/etc/zeroecho/tls/` (k8s) | operator dir / Secret | pki-server's own PKCS#12 stores referenced by `server-config.json`. In Compose the server working dir is `/var/lib/zeroecho`, so config paths like `tls/server-identity.p12` resolve there; the k8s ConfigMap uses absolute `/etc/zeroecho/tls/...` paths. |
| `/etc/zeroecho/health/` | operator dir / Secret | Health-probe client identity (`health-client.pem`, `health-client-key.pem`, `health-ca.pem`) for the container/probe HEALTHCHECK. |

### Environment variables / secrets

Secrets are **passwords-by-env only** — `server-config.json` contains just the
*names* of these variables, never the values. See `.env.example` for the full
set. Core ones:

| Variable | Consumed by | Purpose |
|---|---|---|
| `ZEROECHO_KEYRING_PASSWORD` | `runtime.keyUnlockEnvironmentVariable` and/or `signing.unlockEnvironmentVariable` | Unlocks the CA signing keyring. |
| `ZEROECHO_TLS_KEYSTORE_PASSWORD` | listener `tlsProvider.keyStorePasswordEnvironment` | pki-server server-identity PKCS#12 password. |
| `ZEROECHO_PROXY_TRUSTSTORE_PASSWORD` | listener `tlsProvider.trustStorePasswordEnvironment` | Trust for the reverse proxy's transport certificate. |
| `ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD` | `administrativeClientTrust.trustStorePasswordEnvironment` | Trust used to validate the forwarded admin client leaf. |

The env-var name syntax is constrained by the server: `[A-Z][A-Z0-9_]{0,127}`.

> **Align config paths with the mount layout.** The server working directory is
> `/var/lib/zeroecho`. The shipped example configs use illustrative relative
> paths (`state/pki`, `state/audit`, `tls/...`); when adapting one for a
> container, point them at the actual mounts. The canonical mapping used by these
> artifacts is: `store.root` → `/var/lib/zeroecho/store`, `audit.root` →
> `/var/lib/zeroecho/audit`, publisher `root` → `/var/lib/zeroecho/artifacts`,
> signing `keyringPath` → `/var/lib/zeroecho/keyring/ca-keyring.zek`, `controlLog`
> → `/var/lib/zeroecho/store/server-control.log`, and the TLS PKCS#12 stores →
> `/var/lib/zeroecho/tls/...` (Compose) or `/etc/zeroecho/tls/...` (the k8s
> ConfigMap, which already uses absolute paths). Prefer absolute in-container
> paths to avoid ambiguity.

### TLS material

| Where | Files | Role |
|---|---|---|
| pki-server TLS dir | `server-identity.p12` | pki-server's server certificate + key (admin listener). |
| pki-server TLS dir | `proxy-transport-trust.p12` | Trusts the nginx transport client certificate (listener client trust in reverse-proxy mode). |
| pki-server TLS dir | `administrators-trust.p12` | `administrativeClientTrust` — trusts the *administrator* client certificates forwarded by nginx. |
| nginx `/etc/nginx/tls/edge/` | `edge.crt`, `edge.key` | nginx's browser-facing server certificate. |
| nginx `/etc/nginx/tls/admin-trust/` | `admin-ca-bundle.pem` | CA bundle that browser admin client certificates must chain to (`ssl_client_certificate`). Same trust anchors as `administrators-trust.p12`. |
| nginx `/etc/nginx/tls/upstream/` | `proxy-client.crt`, `proxy-client.key`, `pki-server-ca.pem` | nginx's transport client identity for upstream mTLS + the CA to verify pki-server's server cert. |

### Health probes

| Endpoint | Meaning |
|---|---|
| `GET /health/live` | Process is up. |
| `GET /health/ready` | Realm is `READY` (200) or not (503). |

Both are served **before authentication**, but the admin listener sets
`needClientAuth = true`, so the TLS handshake still requires a client
certificate. The container HEALTHCHECK and the Kubernetes exec probes therefore
present a dedicated **health-probe client identity** whose issuer is trusted by
the admin listener's client trust store. nginx has its own loopback plaintext
`/nginx-health` for its container HEALTHCHECK.

## Browser mutual-TLS trust model & enrolling an administrator

1. Administrators authenticate with an X.509 **client certificate** presented by
   the browser to nginx. There is no password/anonymous mode.
2. nginx accepts the handshake only if the client cert chains to
   `admin-ca-bundle.pem`. It forwards the verified leaf to pki-server as
   `Client-Cert` (RFC 9440).
3. pki-server independently (a) validates the leaf against
   `administrativeClientTrust`, and (b) maps it to a **persisted principal** via
   an exact SHA-256 certificate / SPKI / issuer-serial **commitment** in
   `authentication.forwardedClientMappings`. A mapping establishes identity only;
   authority comes from scoped RBAC grants on that principal in the server-control
   store.

To enrol an administrator:

1. Issue (or have the administrator generate) a client key pair + certificate
   from a CA that chains to `admin-ca-bundle.pem` / `administrators-trust.p12`.
2. Compute the commitment (e.g. `openssl x509 -in admin.pem -outform der | sha256sum`
   for `certificateSha256`, or the SPKI SHA-256 for `subjectPublicKeyInfoSha256`).
3. Add a `forwardedClientMappings` entry to `server-config.json` mapping that
   commitment to the principal id, and ensure the principal exists with the
   required grants. Restart pki-server (config is validated on start).
4. Import the client cert (as PKCS#12) into the administrator's browser.

## Changing a certificate profile

Profiles live in the read-only profiles mount and are **reconciled at start-up**
(see below). To change one:

1. Edit or add the profile JSON in the profiles source (host dir, or the
   `pki-server-profiles` ConfigMap on k8s).
2. Restart pki-server. The entrypoint registers+activates any profile whose
   `profileId` is **not already present** in the store.

**Important idempotency limitation:** the entrypoint reconcile is idempotent at
*profile-identity* granularity — it will **not** re-register a `profileId` that
already exists, so **editing an existing profile's content and restarting does
NOT update it**. To change an existing profile today, register a new version via
the admin API / operator tooling (`profile.register` then `profile.activate`),
or use the CLI against a stopped server's store. This gap is by design pending a
backend reconcile primitive — see **Backend gaps** below. Set
`ZEROECHO_PROFILE_RECONCILE=off` to disable the start-up reconcile entirely.

## Pointing the store at a persistent volume without rebuilding

The store location is **configuration + a mounted volume**, never baked into the
image. To move it:

* **Compose:** the named volume `store` maps to `/var/lib/zeroecho/store`. To use
  a specific host path or external volume, replace the `store:` named volume with
  a bind mount (`- type: bind, source: /data/zeroecho/store, target:
  /var/lib/zeroecho/store`) — `chown 10001` and `chmod 700` it first — or declare
  the named volume as `external: true`. No image rebuild is needed; the config's
  `store.properties.root` already points at `/var/lib/zeroecho/store`.
* **Kubernetes:** the `store` `volumeClaimTemplate` binds a PVC to
  `/var/lib/zeroecho/store`. Set `storageClassName` to a POSIX class, or
  pre-provision the PV. `server-config.json` (ConfigMap) points `root` at the
  same in-container path.

The same pattern applies to `keyring`, `artifacts`, and `audit`. Because the
config uses **in-container paths**, you can repoint the underlying storage freely
without touching the image or the config.

## Building & running

```sh
# On a POSIX host with Docker + a JDK 25 toolchain in the build image:
cp deploy/.env.example deploy/.env      # then edit deploy/.env and provision TLS
docker compose -f deploy/compose/docker-compose.yml up -d --build
deploy/smoke-test.sh                    # end-to-end issuance smoke test
```

The pki-server image build stage runs `./gradlew :pki-server:installDist
:app:installDist` (JDK 25, no Node needed). The nginx image build stage runs the
pinned Node/Vite build of `pki-frontend`. If your CI already produced the
`installDist` trees or the SPA `dist/`, use the documented `prebuilt` build
targets / build-args to skip the source build.

## The exact CSP decision (and why)

The Content-Security-Policy served at the UI origin is:

```
default-src 'none';
script-src 'self';
style-src  'self' 'unsafe-inline';
img-src    'self' data:;
font-src   'self';
connect-src 'self';
manifest-src 'self';
worker-src 'self';
form-action 'self';
frame-ancestors 'none';
base-uri 'none';
object-src 'none';
```

* **`script-src 'self'` (no `'unsafe-inline'`).** The Vite production build emits
  only **hashed, external ES module** scripts under `/assets/`; there is no inline
  `<script>` in `index.html`. Scripts get the strict policy.
* **`style-src 'self' 'unsafe-inline'`.** MUI/Emotion inject component styles at
  runtime via the CSSOM; without `'unsafe-inline'` for styles the UI renders
  unstyled/broken. We deliberately relax **style** only. The tradeoff: style
  injection cannot exfiltrate data or execute code the way script can, so
  `'unsafe-inline'` for `style-src` is a well-understood, low residual risk. The
  stricter alternative is a **per-response nonce**: emit `style-src 'self'
  'nonce-<random>'`, add `<meta name="emotion-insertion-point">` and configure the
  Emotion cache with that nonce. That requires nginx to generate a per-request
  nonce (via njs) and rewrite `index.html`, adding moving parts for a
  style-only gain. We chose the pragmatic `'unsafe-inline'` for `style-src` and
  document the nonce path here for teams with a stricter mandate.
* `frame-ancestors 'none'` + `X-Frame-Options: DENY` block clickjacking;
  `default-src 'none'` + `connect-src 'self'` keep all XHR/fetch same-origin
  (the SPA calls only same-origin `/admin`, `/public`, `/health`, `/account`,
  which nginx proxies).

## Backend gaps found (precise)

1. **No clean profile-reconcile primitive.** Profiles are immutable versions plus
   an active pointer; `profile.register` always creates a *new* version and
   `profile.activate` flips the pointer. There is no content-addressed,
   idempotent "make the store match this directory" operation. The container
   entrypoint therefore reconciles best-effort at *profile-identity* granularity
   (skip ids already present) and cannot detect/apply content drift on restart.

   **Proposed fix — a first-class server flag:**
   ```
   zeroecho-pki-server --reconcile-profiles <dir> --config <server-config.json>
   ```
   Semantics: for each `*.json` in `<dir>`, canonicalise and hash the profile
   document; if the store has no active version for that `profileId`, register +
   activate it; if the active version's canonical hash differs, register a new
   version and activate it; if it matches, do nothing. Runs against the same
   store the server owns (before opening the listener), reuses the existing
   `profile.register`/`profile.activate` execution path, is fully idempotent, and
   emits one audit record per change and none per no-op. This removes the CLI
   dependency and the "edit-doesn't-update" limitation above.

2. **The `zeroecho pki` CLI is not a network client.** It is single-process and
   local-store only (documented in `docs/examples/pki-cli/README.md`). There is
   no `--url` remote mode. The smoke test consequently uses **curl over mTLS**
   against the admin HTTPS API — which is the only network client contract — not
   the CLI. (If a remote CLI is desired later, it would wrap the same admin API
   this smoke test exercises.)

3. **Directory permission ownership for bind mounts.** The non-root runtime user
   cannot `chown` a bind-mounted host directory it does not already own; the host
   must pre-own store/keyring paths as uid 10001 (mode 0700). Named volumes and
   k8s `fsGroup` handle this automatically. (Operational note, not a code bug.)

## What was validated vs. not

* **Validated here:** YAML parses (compose + all k8s manifests); shell scripts
  pass `sh -n`; config field/route/provider names and the admin request
  envelope were cross-checked against the server/CLI source and the shipped
  example configs.
* **Not validated here (no container engine):** image builds, `nginx -t`, actual
  container start-up, live mTLS handshakes, the RFC 9440 njs conversion against a
  real handshake, and the end-to-end smoke run. Build and run these on a
  POSIX/Docker host to confirm.
