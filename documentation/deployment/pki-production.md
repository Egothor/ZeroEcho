# Production deployment from a source checkout

This guide is the operating path for a persistent Linux rootless installation.
For the complete command sequence from installation to CA creation, operator
onboarding, issuance and revocation, follow
[Set up and administer a PKI](../admin/getting-started.md).
Use [fast-track qualification](pki-fast-track.md) for disposable test fixtures.
The supported baseline starts with an **empty version-18 store**. No migration
from earlier PKI stores is supplied. Updating a compatible installation's images
or explicit access grants is different from migrating stored PKI data.

## Plan trust, identities and custody

Meet the [host requirements](rootless-podman.md#requirements). Reserve a hostname
such as `pki.northstar.example`, a published IPv4 address and unprivileged HTTPS
port. `.example` is reserved: configure actual DNS and a certificate matching your
chosen hostname before use. The installer does not change DNS, firewall, host
trust or user lingering. Keep the data directory outside the checkout on private
local POSIX storage. Establish backup, secret delivery and certificate-expiry
owners before exposing the service.

Choose distinct initial administrator and independent approver principals.
Protect their separate browser exports/passwords. The protected FIRST deployment
administrator is the only identity permitted to invoke managed `key.generate`,
with `MANAGED_KEY_GENERATE` and normal approval additionally required. Grant
management cannot select a different FIRST identity. Other authorized operators
may use existing compatible managed keys for CA creation; generation is explicit
and never a side effect of omitting a key reference.

Transport/login trust, applicant subject keys and business CA signing keys are
separate. Managed signing private keys stay on the server. New operator login
keys/CSRs belong to the operator; deployment signs the CSR, updates the configured
certificate-to-principal mapping and controls any restart. PKCS#12 exports are
secrets, not public certificates. Record expiry dates and a renewal change plan.

## Install and establish the first session

From the source checkout, as the service owner without sudo:

```sh
./deploy/rootless-pki.sh install \
  --directory "$HOME/.local/share/northstar-pki"
```

Fill the curses form with the planned network/realm/identity values. Use distinct
16-character-or-longer export passwords and the form's permitted signing-keyring
password. F2 validates, prepares and starts; Escape cancels before provisioning.
For an administrative hybrid SDK deployment, add `--hybrid-sdk` to this **fresh
install** command. It configures the administrative SDK at the external origin;
it does not provision a public OCSP SDK listener/responder for production.
The precise fields and secret/layout contract are in the
[installer reference](rootless-podman.md#install).

Read `<installation>/NEXT-STEPS.txt`. Import `logins/web-ca.pem` as trust when
using the generated web CA, then `logins/administrator.p12` with the export
password. Open the printed URL and select the client certificate. Deliver
`logins/approver.p12` and its different password privately to the independent
approver. Use separate browser profiles. No web password account is created.

The initial administrator has explicit own-request approval authority; it does
not remove eligibility, threshold or justification requirements. The second
administrator follows ordinary requester separation. Review a retained exact
request, record justification, and observe execution after approval.
An approved request or accepted signature is not a completed credential.

## Configure only the listeners you need

By default the rootless installer publishes the console/admin edge only. Backend
admin traffic stays on the private network and requires the configured proxy mTLS
identity plus verified forwarded client certificate. The shipped filesystem
publisher is not a public repository.

| Service | Required additional configuration and operating contract |
| --- | --- |
| Public repository | Separate public listener/TLS/proxy policy, nginx upstream and explicit disclosure/alias policy; [public routes](../reference/pki-server-public-repository.md). |
| ACME | Listener, directory, enrollment profile, namespace/challenge providers and activation; [ACME reference](../reference/pki-server-acme.md). |
| EST, SCEP, CMP | Explicit protocol configuration, authenticated enrollment policy and client capabilities; [enrollment guide](../admin/protocols.md). |
| Native OCSP | Exact issuer generation, delegated responder credential, managed signer, policy and activation; [OCSP reference](../reference/pki-server-ocsp.md). |
| Hybrid enrollment SDK | Opt-in configured origin, bounded requests, dual-subject proof and actual transport binding; [SDK reference](../reference/pki-operator-interfaces.md#hybrid-sdk-and-status-boundaries). |
| Separate SDK OCSP | Public SDK opt-in and dedicated alternative-role binding in addition to native responder setup; not standard AltSignature OCSP. |

The installer never infers these production configurations from a successful
disposable test. Configuration changes and necessary restarts belong to deployment
operators; an external client reports unmet prerequisites.

## Operate and update the retained installation

```sh
./deploy/rootless-pki.sh status --directory "$HOME/.local/share/northstar-pki"
./deploy/rootless-pki.sh stop --directory "$HOME/.local/share/northstar-pki"
./deploy/rootless-pki.sh start --directory "$HOME/.local/share/northstar-pki"
```

Stopping preserves state. Inspect the exact user-service journal commands printed
in `NEXT-STEPS.txt` after failure. Service startup without an interactive login
requires host-policy-controlled user lingering. Do not move the installation path
or recreate its private network independently.

After a consistent backup, update from a reviewed compatible checkout:

```sh
./deploy/rootless-pki.sh update --directory "$HOME/.local/share/northstar-pki"
```

The updater validates configuration, pins new image IDs and retains a journal;
it preserves keys, credentials and policy. Interrupted updates must resume with
the **same flags**, original directory and retained intent. Do not delete the
journal or replace committed control state to retry.

For a compatible installation missing explicitly desired additive grants, choose
only the needed flags:

```sh
./deploy/rootless-pki.sh update --root-admin --certificate-access --status-access \
  --directory "$HOME/.local/share/northstar-pki"
```

`--root-admin` designates only the original initial administrator for own approval;
`--certificate-access` adds original-pair certificate content/download grants;
`--status-access` adds original-pair status-object content grants. These migrations
validate original identities/grants and refuse altered or revoked authority.
Plain update does not silently add them. `--hybrid-sdk` is not an update flag.

## Back up, restore and recover safely

Retain a consistent offline copy of the full private installation, external
server-control/safety authority, keyring and unlock secret, TLS configuration,
audit and publication state. Restrict key backups separately. A logical PKI archive
or client export alone cannot recover all of these resources.

For supported streaming backup/restore, follow the exact
[backup workflow](../admin/backup-restore.md). Verify and stage before an
operator-controlled cold reopen; require `ACTIVATED`, then separately acknowledge.
`STAGED` is not success. Keep rollback roots and external no-regression authority.
Ordinary request recovery observes retained IDs; it never blindly reissues a
mutation. Never run local store administration while the server owns that store.

Do not rewind FIRST pins, managed keys, responder slots, signing receipts or
checkpoints. A source rollback does not prove a safe live-state rollback.
Lost current safety authority requires incident assessment, not unpacking an old
backup and assuming it is safe to issue.

## Troubleshoot by the failed boundary

| Observation | Action and completion evidence |
| --- | --- |
| Install rejects a directory | Keep partial state; inspect the recorded phase. Do not rerun bootstrap into it or delete it to hide uncertainty. |
| Browser cannot authenticate | Check hostname/trust, client certificate selection/expiry and exact configured mapping. A PKCS#12 password unlocks the export; it is not HTTP login. |
| Missing content access | Inspect current scoped grants and disclosure; use an authorized explicit access migration where applicable. Do not fall back to anonymous download. |
| `key.generate` unavailable/refused | Check actual FIRST identity/configuration and permitted parameters; normal grants alone cannot bypass FIRST protection. |
| Approval or signing pending | Keep request/approval/signing IDs and observe. Do not change request ID to retry. |
| Hybrid prerequisite missing | Configure the correct listener/origin under deployment control; no fallback to classical-only proof. |
| Download verifies syntax only | Inspect verification fields; use a capable verifier for signatures and selected trust path. PQC/alternative signatures need the SDK helper. |
| Restore awaiting restart | Deployment owner performs the cold-reopen boundary; client observes original restore and acknowledges separately. |

Record actual revision, command, environment and unsuccessful attempts. A green
historical qualification report does not establish current service health,
current OCSP freshness, universal client interoperability or compliance.
