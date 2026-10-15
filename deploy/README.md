# ZeroEcho PKI — deployment artifacts

Remote backup transfer is opt-in. Mount an administrator-selected
[transfer configuration](../docs/pki-backup-transfer-example.json), provision its
private persistent artifact directory outside the PKI root, and set
`ZEROECHO_BACKUP_TRANSFER_CONFIG` to the in-container configuration path.
See [backup and restore](../documentation/admin/backup-restore.md#opt-in-http-transfer)
for budgets, topology, permissions and restart reconciliation. Existing deployment
examples leave this feature disabled.

Packaging and deployment examples for the permanent backend and asynchronous web
frontend (mode a), remote mTLS CLI (mode b), and synchronous standalone CLI
(mode c). The application, server and web artifacts use the existing Gradle/npm
toolchain. See [CLI configuration and recovery](../docs/pki-cli.md) and
[local worked examples](../docs/examples/pki-cli/README.md).

The [packaged deployment gate](../pki-frontend/e2e/packaged/README.md) verifies
container execution, nginx/mTLS forwarding and the deployed web/remote CLI flow.
Static configuration checks and local CLI tests cover separate boundaries.

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
* **nginx** serves the SPA bundle; pki-server exposes the JSON admin/public/health API.
* The remote CLI authenticates to the same edge using its administrator mTLS
  certificate. The permanent backend owns asynchronous signing operations; the
  CLI submits once and observes the retained operation ID with GET requests.

## File tree

```
deploy/
  README.md                      # this file — the data/config contract
  .env.example                   # every env var / secret a deployer sets
  smoke-test.sh                  # host wrapper for packaged remote CLI smoke
  smoke_test.py                  # bounded readiness + once-only issuance
  pki-server/
    Dockerfile                   # multi-stage; non-root; installDist of server + CLI
    entrypoint.sh                # validate-config + profile bootstrap + exec
    profile-bootstrap.json       # explicit local operator/configuration
    profiles/                    # runnable schema-v5 example policies
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

The durable mount is `/var/lib/zeroecho/store-container`; the replaceable PKI root
is its `store/` child. Server-control authority lives separately at
`server-control/server-control.log`. Keep the parent writable so cold restore can
retain sibling stage/rollback roots and `.store.restore-control`. Do not mount a
volume directly on the replaceable child.

Existing deployments require an **offline layout migration**. Stop every server
and bootstrap process and preserve a complete copy of the old volume first.
Place the former PKI root under `store/`, move its existing `server-control.log`
to `server-control/server-control.log`, and preserve all other external authority
under separately configured stable paths. Update server and bootstrap configs
together, retaining ownership and permissions. The entrypoint rejects a legacy
`VERSION` at the new mount root; it never migrates or initializes over it. This
layout change does not authorize rewinding PKI safety state or external effects.

| Mount (in-container) | Purpose | POSIX perms | Persistence guidance |
|---|---|---|---|
| `/var/lib/zeroecho/store-container` | Main PKI store (CAs, requests, credentials, revocations, metadata log, staged content) **and** `server-control.log` | dir `0700` | **Stable, durable PV.** This is the system of record. Back it up consistently; never share it between two running servers (single-writer flock). |
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
| `/etc/zeroecho/server-config.json` | operator file / ConfigMap | Strict versioned JSON, **schema version 8**. Start from [`docs/pki-server-trusted-proxy-rfc9440-example.json`](../docs/pki-server-trusted-proxy-rfc9440-example.json) for this topology. Validated by `--validate-config` at start-up (fail-fast). |
| `/etc/zeroecho/profile-bootstrap.json` | operator file / ConfigMap | Local schema v1, explicit `operatorId`, matching filesystem store and audit sink; no signer or publishers. |
| `/etc/zeroecho/profiles/` | operator dir / ConfigMap | One `*.json` certificate-profile document (**schemaVersion 5**) per file. Reconciled at start-up (see below). |
| `/var/lib/zeroecho/tls/` (compose) or `/etc/zeroecho/tls/` (k8s) | operator dir / Secret | pki-server's own PKCS#12 stores referenced by `server-config.json`. In Compose the server working dir is `/var/lib/zeroecho`, so config paths like `tls/server-identity.p12` resolve there; the k8s ConfigMap uses absolute `/etc/zeroecho/tls/...` paths. |
| `/etc/zeroecho/health/` | operator dir / Secret | Health-probe client identity (`health-client.pem`, `health-client-key.pem`, `health-ca.pem`) for the container/probe HEALTHCHECK. |

### Environment variables / secrets

Secrets are **passwords-by-env only** — `server-config.json` contains just the
*names* of these variables, never the values. See `.env.example` for the full
set. Core ones:

| Variable | Consumed by | Purpose |
|---|---|---|
| `ZEROECHO_KEYRING_PASSWORD` | `runtime.keyUnlockEnvironmentVariable` | Unlocks the CA signing keyring. |
| `ZEROECHO_TLS_KEYSTORE_PASSWORD` | listener `tlsProvider.keyStorePasswordEnvironment` | pki-server server-identity PKCS#12 password. |
| `ZEROECHO_PROXY_TRUSTSTORE_PASSWORD` | listener `tlsProvider.trustStorePasswordEnvironment` | Trust for the reverse proxy's transport certificate. |
| `ZEROECHO_ADMIN_TRUSTSTORE_PASSWORD` | `administrativeClientTrust.trustStorePasswordEnvironment` | Trust used to validate the forwarded admin client leaf. |

The env-var name syntax is constrained by the server: `[A-Z][A-Z0-9_]{0,127}`.

> **Align config paths with the mount layout.** The server working directory is
> `/var/lib/zeroecho`. The shipped example configs use illustrative relative
> paths (`state/pki`, `state/audit`, `tls/...`); when adapting one for a
> container, point them at the actual mounts. The canonical mapping used by these
> artifacts is: `store.root` → `/var/lib/zeroecho/store-container/store`, `audit.root` →
> `/var/lib/zeroecho/audit`, publisher `root` → `/var/lib/zeroecho/artifacts`,
> signing `keyringPath` → `/var/lib/zeroecho/keyring/ca-keyring.zek`, `controlLog`
> → `/var/lib/zeroecho/store-container/server-control/server-control.log`, and the TLS PKCS#12 stores →
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

## Startup profile bootstrap and profile changes

The entrypoint first validates server schema v8 (backend session schema v6), then
runs the distribution's deployment-only `bin/zeroecho-pki-profile-bootstrap`
launcher, then executes the server as PID 1. The helper uses the existing local
schema-v1 parser and core PKI operations. It opens no signer, HTTP listener or
reactor and closes its session before the server opens the store.

Mount `pki-server/profile-bootstrap.json` as `/etc/zeroecho/profile-bootstrap.json`.
Review its explicit `operatorId: "deployment-profile-bootstrap"`; it is a trusted
local audit identity, not a server-authenticated principal. Align its filesystem
store root with the server configuration and `ZEROECHO_STORE_DIR`; the helper
rejects a mismatch with the latter. The shipped configuration uses the durable
file audit sink shared sequentially with the server. Configuration and profile
files must be trusted, read-only operator inputs. Kubernetes projected file links
are resolved before bounded regular-file reads.

For each `*.json` in filename order, the helper decodes the actual profile ID and
version with the existing codec. It skips an identity with any known version,
otherwise registers and activates the exact imported version, including versions
other than 1. Profile IDs are JSON strings and may contain Unicode, spaces or
punctuation; no shell text extraction is used. Documents retain the existing
256 KiB codec limit. The helper retains O(N) paths for deterministic sorting and
one bounded document at a time; sorting costs O(N log N), plus decoding and the
existing core profile lookup/registration costs.

Malformed input, failed core operations, store contention, missing helper or
missing configuration stop startup. An empty profile directory succeeds without
changes. Earlier successful mutations remain committed after a later failure.
An existing inactive identity is also skipped, including one left registered by
an interrupted previous run: inspect it and activate it explicitly if intended.
There is no automatic content reconciliation or implicit recovery.

To change an existing profile, register its explicit new version and activate it
through the remote CLI/API, or through the local CLI while the server is stopped.
Editing a known identity in the mounted directory and restarting leaves stored
versions and activation unchanged. The five shipped profiles are runnable examples;
review algorithms, subject rules, approval/confirmation policy and validity before
production use. Set `ZEROECHO_PROFILE_RECONCILE=off` to explicitly disable startup
seeding; values other than `on` and `off` are rejected.

## CLI operation and recovery

Use the remote CLI while the permanent backend is running. For example, with
trusted administrator credentials and a PEM server trust bundle:

```sh
app/build/install/app/bin/app pki profile.list-all --url https://pki.example.com:8443 \
  --client-cert /secure/admin.pem --client-key /secure/admin-key.pem \
  --trust /secure/edge-ca.pem --arg-int limit=25 --output json
```

For signing, `--pending-wait` bounds remote observation; exit 7 with `PENDING`
retains the accepted operation ID. Save JSON output even on nonzero exits. Use
`signing.operation.inspect --operation-id ID` with the same remote credentials
to observe it later. A timeout, interruption or failed GET never authorizes a
second submission. Remote explicit completion is unsupported.

Stop the server before opening its store through local mode. Local signing is
synchronous and a trusted local invocation constitutes root-operator approval;
all remaining policy/proof/validity checks apply. Local inspection is read-only.
After interruption, only `signing.operation.complete --operation-id ID --config
local.json` explicitly drives the selected persisted operation. Signing or
publication failures retain their recovery/reconciliation distinctions; durable
signature storage alone does not establish domain completion. Do not start a new
signing operation to recover an earlier one or rerun mutations blindly.

Explicit publication commands execute synchronously. Inspect `output.status` as
well as the command's exit: a completed publication attempt can report a definitive
failure. Use `publication.retry` for a reported retryable failure and
`publication.reconcile` for an unknown external outcome as applicable, after
resolving the underlying problem. Export or downstream use requires confirmed
publication success. The [CLI guide](../docs/pki-cli.md) describes receipt and
exit semantics.

## Pointing the store at a persistent volume without rebuilding

The store location is **configuration + a mounted volume**, never baked into the
image. To move it:

* **Compose:** the named volume `store` maps to `/var/lib/zeroecho/store-container`. To use
  a specific host path or external volume, replace the `store:` named volume with
  a bind mount (`- type: bind, source: /data/zeroecho/store, target:
  /var/lib/zeroecho/store-container`) — `chown 10001` and `chmod 700` it first — or declare
  the named volume as `external: true`. No image rebuild is needed; the config's
  `store.properties.root` already points at `/var/lib/zeroecho/store-container/store`.
* **Kubernetes:** the `store` `volumeClaimTemplate` binds a PVC to
  `/var/lib/zeroecho/store-container`. Set `storageClassName` to a POSIX class, or
  pre-provision the PV. `server-config.json` (ConfigMap) points `root` at the
  same in-container path.

The same pattern applies to `keyring`, `artifacts`, and `audit`. Because the
config uses **in-container paths**, you can repoint the underlying storage freely
without touching the image or the config.

## Building and running

From the repository root, build the packaged launchers and static web artifacts:

```sh
./gradlew :app:installDist :pki-server:installDist :pki-frontend:npmBuild --offline
```

Outputs are `app/build/install/app`,
`pki-server/build/install/zeroecho-pki-server`, and `pki-frontend/dist`.
The app distribution includes both `bin/app` and the deployment-only profile
bootstrap launcher. `installDist` and the standard distribution archives carry
the same runtime dependencies; no additional bootstrap dependency is required.

For source-built containers, provision TLS, server mappings/grants, the keyring
and secrets, then:

```sh
cp deploy/.env.example deploy/.env
# Edit deploy/.env and the mounted configurations before starting.
docker compose --env-file deploy/.env -f deploy/compose/docker-compose.yml up -d --build
```

The explicit `--env-file` is required because Compose otherwise looks for `.env`
in its default project environment. Relative bind-source values in this file
resolve from `deploy/compose/`, not from the `.env` file. The shipped values use
`../config`, `../tls` and `../pki-server` to address directories under `deploy/`;
absolute host paths are also accepted. Keep a filled-in `.env` private and outside
version control. Containers receive only the required secrets via environment
references; private TLS/keyring material is mounted or provisioned in its volumes.

Both Dockerfiles also have actual `prebuilt` targets. Populate a fresh staging
directory at repository-root `context/` with the *contents* of the built artifacts:

```sh
mkdir -p context/app context/pki-server context/frontend
cp -a app/build/install/app/. context/app/
cp -a pki-server/build/install/zeroecho-pki-server/. context/pki-server/
cp -a pki-frontend/dist/. context/frontend/
docker build --target prebuilt -f deploy/pki-server/Dockerfile -t zeroecho/pki-server:latest .
docker build --target prebuilt -f deploy/nginx/Dockerfile -t zeroecho/pki-nginx:latest .
docker compose --env-file deploy/.env -f deploy/compose/docker-compose.yml up -d --no-build
```

`prebuilt` depends only on the shared runtime base, not on the source build stage.
The default final `runtime` target builds from source. There is no `PREBUILT`
build argument. `.dockerignore` excludes local build caches, generated output,
agent support and conventional private deployment directories while retaining the
three explicit prebuilt inputs. Do not put secrets in those input distributions.
Base images and distribution contents still require your normal supply-chain review.

## Remote CLI smoke check

Build the app distribution and provision an issuing CA, active end-entity profile,
valid CSR and administrator identity with the necessary server grants/approval.
Profile seeding alone creates no CA or signing key. The PEM client private key
must be unencrypted PKCS#8, as required by the CLI; keep it on a private filesystem.

Configure the `SMOKE_*` variables in `deploy/.env` or the process environment:
`SMOKE_BASE_URL`, `SMOKE_ADMIN_CERT`, `SMOKE_ADMIN_KEY`, `SMOKE_CA_BUNDLE`,
`SMOKE_CA_ID`, `SMOKE_PROFILE_ID`, and exactly one of `SMOKE_REQUEST_ID` or
`SMOKE_IMPORT_ARGS_FILE`. `SMOKE_CLI` optionally selects another packaged `bin/app`.
Smoke file paths are resolved from `deploy/`; Compose bind paths still resolve
from `deploy/compose/` as described above. Environment values override `.env`.
The smoke helper reads literal `SMOKE_*` assignments only, supporting quoted
whitespace and comments. It performs no shell evaluation or variable expansion.

The optional import file is the existing full realm-scoped API envelope:

```json
{"version":1,"arguments":{"formatId":"x509","encoded":"BASE64_DER_CSR"}}
```

It is bounded to 1 MiB with bounded string fields. Duplicate properties, unknown
fields, wrong types and an authority scope are rejected before submission.
Optional root `approvalId` and ISO-8601 `deadline` are forwarded as CLI flags.
The helper reads the resulting `requestId` from the remote CLI's nested `result`.

```sh
# Check an already-running stack; leave it running.
deploy/smoke-test.sh --no-up --no-down
# Or start the source-built Compose stack and tear it down afterwards.
deploy/smoke-test.sh
# Offline tests of orchestration and exactly-once submission:
python3 -m unittest discover -s deploy -p test_smoke_test.py
```

The host requires Python 3, curl, the installed app and Docker Compose when startup
is enabled. Readiness has a 120-second deadline and bounded curl calls; a realm
read checks the administrator authentication path. Issuance then uses exactly one
packaged `credential.issue` invocation with `--pending-wait 120`. The CLI owns GET
observation of the accepted signing ID; the script never repeats issuance to
recover a receipt. Server policy/approval failures remain failures.

Each run prints a private temporary directory containing JSON receipts and
command diagnostics, retained on success, failure and interruption. A pending
CLI outcome preserves exit 7; cancellation preserves exit 130. Inspect the saved
`credential-issue.json` and its operation ID before continuing. A successful run
requires a remote `SUCCEEDED` envelope with both operation ID and credential ID.
`--no-up` also prevents teardown of an existing stack; `--no-down` preserves a
stack started by this run. JSON receipts may identify certificates and operations;
protect and dispose of them according to your operational policy.

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

## Deployment validation

The [packaged deployment gate](../pki-frontend/e2e/packaged/README.md) runs the
actual server and nginx images, built SPA and CLI with temporary mTLS identities.
It verifies RFC 9440 forwarding, approval, scoped authorization, retained signing
receipts and observation without duplicate submission. The gate uses a private
container network and a loopback-only edge port; it does not publish a deployment.

## Distribution licenses

Existing binary distribution routes include the canonical `LICENSE-binary.txt`:

| Artifact | License location |
| --- | --- |
| First-party JAR | `META-INF/LICENSE-binary.txt` |
| CLI/server install tree, ZIP or TAR | Distribution root |
| SPA directory or ZIP | Bundle root |
| Server container | `/opt/zeroecho/LICENSE-binary.txt` |
| nginx container | `/usr/share/licenses/zeroecho/LICENSE-binary.txt` and `/usr/share/nginx/html/LICENSE-binary.txt` |

Source headers retain the complete `LICENSE-source.txt` terms and existing
copyright notices. Third-party components retain their own licenses. The shared
JAR configuration selects `LICENSE-source.txt` for an existing `sources` classifier;
it does not introduce additional publication variants.
