# Rootless Podman installer

See [production deployment](pki-production.md) for the operating sequence and
[fast-track](pki-fast-track.md) for disposable testing.

`deploy/rootless-pki.sh install` prepares a **fresh** persistent PKI realm and
starts the production server and web console under the current Linux user's
systemd manager. It uses the regular nginx mTLS edge and backend, not frontend
demo mode. One curses form collects all operator inputs before provisioning.

Installation requires a fresh empty version-18 store. An earlier-store migration
path is not supplied. Check host prerequisites before installation and confirm
service health and client access afterwards.

## Requirements

- Linux, a non-root service owner, local rootless Podman with IPv4 networking,
  subordinate UID/GID mappings and a working user systemd manager.
- Python 3 with curses, OpenSSL **3.4+** with `pkcs12 -jdktrust`, curl and systemctl.
  On Debian, install `python3`, `libncursesw6`, `podman`, `uidmap`, `openssl` and
  `curl`; older Debian releases may need a newer OpenSSL package. No dialog,
  Node, Java or Compose installation is needed on the host for installation.
- A POSIX local filesystem for persistent state and keyring. The data directory
  must be new and outside this checkout. SELinux mounts use shared `z` labels
  only on the new installation's own directories.
- Access to container registries and build dependency repositories. The two
  repository Dockerfiles build Java/Node tooling inside build stages. Every
  installation builds the current checkout, using the container build cache,
  and records immutable local image IDs in its service units.
- A hostname resolving to the host, an available unprivileged HTTPS port, and
  firewall rules appropriate for the chosen published address. The installer
  changes neither DNS, firewall rules, system trust nor user lingering.

## Install

Run as the user who will own the service, **without sudo**:

```sh
./deploy/rootless-pki.sh install
```

Add `--hybrid-sdk` only when an administrative SDK listener is intended at fresh
installation. It is default-disabled and is not an update option. The production
install option does not configure a public OCSP SDK listener. The disposable
`test-start --hybrid-sdk` path configures both administrative and public OCSP SDK
for qualification; do not copy its test policy into production implicitly.

The terminal needs at least 78 columns and 22 rows. Tab/arrows move between
fields; typing appends, Backspace deletes, Ctrl-U clears the current field.
Passwords are masked. Escape cancels before provisioning; **F2 prepares and
starts the installation**. Configuration validation errors keep the form open.
The form is in English to remain usable in minimal Linux locales.

| Field | Meaning |
| --- | --- |
| Data directory | New private persistent installation directory; default `~/.local/share/zeroecho-pki`. |
| Web DNS name | Hostname used in browser URL and certificate SAN. |
| Published IP | IPv4 bind address. `127.0.0.1` limits access to this host; choose an interface address or `0.0.0.0` for remote access. |
| HTTPS port | Host port between 1024 and 65535, default 8443. Only HTTPS is published; backend has no published port. |
| Realm ID | Stable realm identifier; also initial display name. |
| Administrator / independent approver | Distinct principal IDs. The reverse-proxy identity is separately created as `trusted-proxy`. |
| Signing keyring password | 16-256 ASCII letters, digits or punctuation; unlocks the encrypted signing keyring. No whitespace, quotes or backslash. |
| Admin / approver PKCS12 password | Distinct passwords of at least 16 characters protecting the two browser identity exports. |
| Existing web PEM chain/key/CA | Either provide all three paths or leave all blank for a generated private deployment CA. The web key must be unencrypted; the chain is leaf first and includes intermediate certificates. The CA bundle must validate that chain. |

The installer checks local rootless Podman and dependencies before provisioning.
It generates a separate transport/login CA, TLS identities, two client PKCS12
exports, random infrastructure secrets, strict server schema-v8 configuration,
local profile configuration, signing keyring entries `root` and `intermediate`,
and the shipped certificate profiles. It validates the server configuration in
the image before bootstrapping any principal.

The offline `zeroecho-pki-admin-bootstrap` launcher persists two USER principals
with realm-scoped catalog permissions and one SERVICE principal whose only grant
allows forwarding authenticated identities. Certificate SHA-256 mappings bind
all three identities. The initial administrator additionally receives the explicit
`APPROVAL_DECIDE_OWN` permission, scoped to their own approvals in this realm.
This root administrator can decide their own requests; the ordinary second
administrator still requires another eligible approver. Both remain subject to
eligibility, approval thresholds, justification and all other server permissions.
The distinction is a persisted permission, not a special username. No HTTP
bootstrap endpoint is exposed.
The bootstrap refuses existing PKI state or a control log; its durable reservation
also prevents retrying a partly completed bootstrap.

The private Podman network and two systemd user services receive installation-
specific names printed in `NEXT-STEPS.txt`. Both containers use fixed addresses
inside the retained private network so nginx's cached backend address survives
backend replacement. The backend runs as uid 10001 with rootless `keep-id`;
nginx's container root is mapped to the unprivileged service owner. No host-root
container, host networking or privileged mode is used. Services pin image IDs,
restart after failure and start at user-manager startup. Backend readiness uses
its actual mTLS health check before edge startup. The health command is supplied
explicitly when creating the container, so it works with OCI images even when
Podman omits Dockerfile `HEALTHCHECK` metadata. Installation also verifies the
published edge with the real administrator certificate and CA/hostname checking.

## First browser login and first issuance

There is **no username/password login**. After startup, read the printed file
`<data-directory>/NEXT-STEPS.txt`:

1. If using the generated web CA, import `logins/web-ca.pem` into the browser's
   trusted authorities. With an existing trusted web certificate, this may already
   be configured. Point DNS or a local hosts entry at the chosen server address.
2. Import `logins/administrator.p12` into the administrator browser using the
   admin export password from the form. The export includes the login CA chain.
3. For an ordinary second administrator, deliver `logins/approver.p12` and its
   distinct password privately. It is optional for the root administrator's own
   workflow; use a separate browser profile when testing the second identity.
4. Open `https://<web-DNS-name>:<port>/` and select the client identity when asked.
   `curl --cert ...` alone does not configure a browser's certificate store.
5. In the console create a root CA with profile `root-ca` and signing reference
   `zeroecho-lib:root.prv`. Review and explicitly submit the retained
   administrative request. Review its linked approval and record a justified
   decision using an eligible identity; the root administrator may decide their
   own request with the explicit capability. Observe that same request through
   execution to terminal success. Do not re-enter or run a second CA operation
   after approval. An ordinary administrator needs another eligible decision
   identity. See [administrative requests](../admin/administrative-requests.md).
6. Create an issuing CA with `intermediate-ca` and
   `zeroecho-lib:intermediate.prv`, then import a CSR and issue a certificate using
   `server-tls`, `vpn-server` or `vpn-client`. See
   [profiles and issuance](../admin/profiles-and-issuance.md) and
   [approval workflow](../admin/access-control.md).

The console/admin API and any explicitly selected administrative SDK are enabled
initially. ACME, EST, SCEP, CMP, public
repository and OCSP setup require their separate documented configurations.
The filesystem publisher target is `local`, writing into `artifacts/`; this is
not an externally reachable certificate repository.

## Secrets, renewal and operations

All state is under the private data directory, with owner-only permissions:

- `secrets.conf`: infrastructure TLS password and keyring unlock password for
  Podman, never sourced as shell code and never copied into an image.
- `keyring/`: encrypted CA signing keys, separate from `store-container/`.
- `store-container/store/`: PKI state; `store-container/server-control/`: principals,
  grants and approval state. The parent layout supports cold restore.
- `audit/`, `artifacts/`: durable audit and published objects.
- `tls/`: per-component runtime identities; backend and nginx mount only their
  required subdirectories.
- `provisioning/`: encrypted deployment CA key, raw generated login/transport
  keys and certificate requests. Treat this directory as highly sensitive. The
  CA unlock password is the generated `ZEROECHO_TLS_PASSWORD` in `secrets.conf`.
- `logins/`: password-protected browser identity exports and public CA bundles.
- `units/`, `installation.json`, `manage.py`: pinned lifecycle configuration.

Generated leaf TLS/login certificates expire after **365 days**, and the private
deployment CA after 3650 days. Supplied edge certificates retain their original
expiry. Renewal is not automated by this installer: replace TLS material and
update certificate fingerprint mappings through a planned change before expiry;
validate and restart. The deployment CA is infrastructure/login trust, separate
from the PKI issuing authorities you create through the console.

For the default directory:

```sh
./deploy/rootless-pki.sh status
./deploy/rootless-pki.sh stop
./deploy/rootless-pki.sh start
```

For a different directory, append `--directory /absolute/path`. A private copy of
the manager is also retained as `<data-directory>/manage.py`, usable with Python
after the checkout is removed. Keep that manager updated with reviewed changes.
Stopping services preserves data, keys, image IDs, network and configuration.
Do not remove/recreate the network independently; its fixed addresses are part
of this installation. Do not move the data directory without explicitly updating
and validating all mounts, service links and recorded identities.

For startup without an interactive login, a host administrator must enable
lingering for the service owner, for example `loginctl enable-linger USER` under
the site's privilege policy. Merely enabling the user services does not enable
lingering. Inspect logs with the `journalctl --user -u ...` commands from
`NEXT-STEPS.txt`; inspect both service statuses after a failed install.

Take consistent offline backups of the entire directory, including external
control state, secrets and keys. Never run the local CLI concurrently with the
server against the same store. Follow [backup and restore](../admin/backup-restore.md)
for recovery; a container restart is not recovery of an uncertain signing result.

## Update an existing installation

Run from the reviewed source checkout, as the same service owner:

```sh
./deploy/rootless-pki.sh update
```

This builds both server and frontend from the current checkout, validates the
existing configuration with the new server, snapshots the manager, manifest and
unit files under `updates/<id>/`, then restarts the exact installation services
with immutable new image IDs. Configuration, TLS/client certificates, secrets,
keyring, approval policy and PKI state remain in place. It does not run bootstrap
or key generation. Existing browser identity exports keep their passwords.

For an older installation whose initial administrator does not yet have the
root own-decision permission, explicitly request it during update:

```sh
./deploy/rootless-pki.sh update --root-admin
```

Only the original initial administrator recorded in `installation.json` is
selected. The offline `zeroecho-pki-root-admin` tool validates the original
identities and grants before adding that one permission; it refuses altered,
disabled or revoked authority rather than restoring it. This does not change
`requesterSeparation` or the realm's policy commitment. Ordinary administrators
retain the second-person rule, and approval requests/decisions remain recorded.
Plain `update` never provisions this privilege.

Updates hold an exclusive per-installation lock. A private
`updates/pending.json` retains exact staged content hashes, image IDs and the
explicit access-migration intent before services stop. If interrupted, repeat
**the same command**, including every access flag originally requested. The
updater verifies and resumes those retained artifacts without rebuilding or
silently choosing different images. Changing access flags while an update is
pending is refused. Restore externally changed metadata/configuration only after
inspection; the updater will not overwrite unrelated changes.

New image pins and the manager are made durable before the optional root grant
is written. Older server versions may not understand the new permission code;
after an interrupted update, recover forward with the retained update rather
than rolling back image pins or replacing the control log. A failed authority
operation leaves services stopped and retains the snapshot/journal for diagnosis.
After success the retained journal becomes `updates/<id>/completed.json`.

Use `--directory /absolute/path` for a nondefault installation. The copied
`manage.py` remains suitable for start/stop/status; building an update requires
this source checkout. The updater does not change user lingering, DNS, firewall
rules or browser trust.

## Failure and rollback

Installation refuses an existing data directory and service-name collision.
Failure retains partial state; it does not retry bootstrap, issue certificates
again, overwrite keys, remove data, disable approvals or undo committed records.
The error identifies the failed executable and provisioning phase without
printing secret-bearing diagnostics. For a service failure, use its user journal.

To roll back service activation, stop and disable the two exact generated user
units, retaining state and network. For example, with the prefix printed in
`installation.json`:

```sh
systemctl --user disable --now zeroecho-PREFIX-web.service zeroecho-PREFIX-server.service
```

Only after explicit inspection and a decision to abandon that installation should
an operator remove its unit links, network and private data. There is no automatic
uninstall or reset command. Reuse retained state for restart, not another `install`.

## Check the installed service

Run the status command with the retained installation directory, replacing the
example path with the exact path selected during installation:

```sh
./deploy/rootless-pki.sh status --directory /absolute/path
```

Confirm both services are running.
Import the exported administrator identity into your browser and open the
printed console URL. Confirm the dashboard loads using that identity before
starting authority administration. Use the
[administrator walkthrough](../admin/getting-started.md) for the first CA and
[external client exercises](pki-exercise.md) to check the published interfaces.

If the service fails, retain its state and inspect the user-systemd logs described
above. Do not repeat `install` against an initialized directory.

## Certificate access on an existing installation

Fresh installations give the initial administrator pair explicit full-content
certificate-read and download grants. Existing installations preserve their
original numbered grants. Request this additive capability explicitly when
updating:

```sh
./deploy/rootless-pki.sh update --certificate-access
```

This option is independent of `--root-admin`; they may be combined when both
capabilities are intended. It does not enable a public listener or change
requester separation, keys, profile/policy commitments or root own-approval grants.
The offline helper validates the original mapped enabled users, proxy, reservation
marker, initialized PKI store and complete original permission baseline before
adding either user's missing content grants. Changed or revoked grants are not
restored. An interrupted migration retains its exact update intent; repeat the
same command so the helper can verify existing exact grants and finish any missing
ones. Do not reset the installation state or change flags to bypass a retained
update journal.

The launcher is also installed as `zeroecho-pki-certificate-access`, with the same
`--config`, `--admin-id`, `--approver-id`, and `--proxy-id` identity contract as the
initial bootstrap. It must run offline with the backend stopped. Normal rootless
updates invoke it in the pinned new image without network access and require its
`CERTIFICATE_ACCESS_READY` completion marker before reporting success.

Status-object content grants are separate. A compatible retained installation
can explicitly add the original administrator pair's missing grants with:

```sh
./deploy/rootless-pki.sh update --status-access
```

The same original-identity/authority checks and retained-intent rules apply.
Combine with the other explicit update flags only when all are intended. Fresh
installations include the initial grants; these flags do not publish objects or
change disclosure policy. This is an access migration, not a store migration.

Public repository access remains disabled by default. For a separately reviewed
public deployment, configure the public listener's TLS and trusted-proxy policy,
set `consoleBasePath` to `/public/v1`, and set nginx `PKI_PUBLIC_UPSTREAM` to that
listener's host and port. Its default `127.0.0.1:9` intentionally provides no public
upstream. The nginx public API location is `/public/v1`; `/public` remains the SPA
page. Set `authorityListExposed` explicitly if public authority listing is wanted.
These settings route requests; disclosure authorization still controls every
public object.
