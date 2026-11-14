# Rootless Podman installer

`deploy/rootless-pki.sh install` prepares a **fresh** persistent PKI realm and
starts the production server and web console under the current Linux user's
systemd manager. It uses the regular nginx mTLS edge and backend, not frontend
demo mode. One curses form collects all operator inputs before provisioning.

This automation has unit and local TLS/configuration integration tests. A full
Podman/systemd deployment must pass the opt-in gate below on the target platform
before production use; a successful local configuration test is not that gate.

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
   `zeroecho-lib:root.prv`. Review the prepared approval request and submit it
   explicitly with **Create approval request**. Root can select **Review approval
   decision**, enter a justification and approve it in the same dialog. Select
   **Use approved request**, then explicitly run the retained CA operation. An
   ordinary administrator needs another eligible identity for the decision.
6. Create an issuing CA with `intermediate-ca` and
   `zeroecho-lib:intermediate.prv`, then import a CSR and issue a certificate using
   `server-tls`, `vpn-server` or `vpn-client`. See
   [profiles and issuance](../admin/profiles-and-issuance.md) and
   [approval workflow](../admin/access-control.md).

Only the console/admin API is enabled initially. ACME, EST, SCEP, CMP, public
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
explicit root-designation intent before services stop. If interrupted, repeat
**the same command**, including `--root-admin` when originally requested. The
updater verifies and resumes those retained artifacts without rebuilding or
silently choosing different images. Changing the root flag while an update is
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

## Validation

The startup correction was also verified on an existing rootless deployment:
backend readiness returned HTTP 200 over verified mTLS, and authenticated access
through the published edge succeeded with the existing client identity. This
confirms the observed startup fix; fresh-install and broader lifecycle coverage
remain the responsibility of the explicit target-host gate below.

Local validation (real OpenSSL certificates, PKCS12, production Java decoder and
JSSE trust-store recognition when the server distribution exists):

```sh
./gradlew :pki-server:installDist
python3 -m unittest discover -s deploy -p 'test_*.py'
./gradlew :pki-server:test --tests '*PkiAdminBootstrapTest'
```

The `Rootless installer checks` CI workflow builds the server distribution, runs
the bootstrap JUnit tests and deployment/TLS contracts on Fedora with OpenSSL
JDK trust support. The real-engine gate remains an explicit target-host check.

The explicit target-host gate builds both images and creates temporary user
services and a private network. It checks installation, source update with explicit root designation, unchanged
configuration/client export/keyring, mTLS access, anonymous rejection, backend
replacement with edge recovery, and stop/start persistence;
cleanup targets only its own generated services/network:

```sh
ZEROECHO_RUN_INSTALLER_INTEGRATION=1 \
  python3 -m unittest discover -s deploy -p test_rootless_pki.py
```

This gate requires a functioning local Podman and user systemd manager. It does
not change host trust or lingering. For issuance/browser behavior through the
packaged nginx/server images, also run the existing
[packaged deployment gate](https://github.com/Egothor/ZeroEcho/blob/main/pki-frontend/e2e/packaged/README.md).

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

Public repository access remains disabled by default. For a separately reviewed
public deployment, configure the public listener's TLS and trusted-proxy policy,
set `consoleBasePath` to `/public/v1`, and set nginx `PKI_PUBLIC_UPSTREAM` to that
listener's host and port. Its default `127.0.0.1:9` intentionally provides no public
upstream. The nginx public API location is `/public/v1`; `/public` remains the SPA
page. Set `authorityListExposed` explicitly if public authority listing is wanted.
These settings route requests; disclosure authorization still controls every
public object.
