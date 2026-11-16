# PKI operator interfaces

Owner: PKI maintainers. Reviewed: 2026-11-16. Review on launcher, API or schema
changes. Commands are checked against source contracts; procedure execution and
assembled-site verification remain outstanding.

## Choose the correct boundary

| Interface | Launcher and use | Authority and recovery |
| --- | --- | --- |
| Persistent deployment | `./deploy/rootless-pki.sh install|update|start|stop|status` | Deployment owner controls server lifecycle/configuration. |
| Disposable preparation | `./deploy/rootless-pki.sh test-start` | Foreground deployment console; `status`, `restart`, `stop`. No client testing hidden in the client. |
| External qualification | `./deploy/exercise-pki.sh` | HTTPS/protocol test client; its own keys/receipts only. |
| Reusable host operator | `./deploy/pki-operator.sh` | Direct administrative mTLS, structured requests and named binary downloads. |
| Interactive operator | `./deploy/pki-tui.sh` | Curses forms over the same Python transport/retained workflow. |
| Java application | `app/build/install/app/bin/app pki` | Local store or remote API according to explicit options; [Java CLI contract](pki-cli.md). A `zeroecho` wrapper shown in generic CLI examples must refer to this distribution launcher in your installation. |
| Backend | `zeroecho-pki-server` in server distribution | Long-lived configured HTTPS runtime; not a client or interactive installer. |

Build the app with `./gradlew :app:installDist --no-parallel`. Local/offline
`app pki --config FILE` has exclusive store ownership and trusted-local root
approval by explicit invocation. It must never open the running server's store.
Remote `app pki --url ORIGIN` uses server authentication/authorization/approval;
there is no local fallback. These modes do not share exit-code numbering with
the Python host client.

## Deployment arguments

`--directory PATH` selects private state (default
`$HOME/.local/share/zeroecho-pki`). Install/test-start require a **new** path;
test-start also requires a new sibling `NAME-client` export path. Install takes
its other inputs through the curses form.

| Flag | Type and valid command | Behavior |
| --- | --- | --- |
| `--root-admin` | Boolean switch; update only | Explicit original administrator own-approval designation. |
| `--certificate-access` | Boolean switch; update only | Explicit original-pair certificate content/download migration. |
| `--status-access` | Boolean switch; update only | Explicit original-pair status-object content migration. |
| `--hybrid-sdk` | Boolean switch; fresh install or test-start only | Install: administrative SDK. Test-start: administrative plus separate public OCSP SDK, public body bound 16384 bytes. Default off. |

`_ready` is an internal generated-service helper, not an operator installation
step. A rootless lifecycle `restart` subcommand does not exist: persistent service
changes use stop/start; disposable console restart is the literal `restart`
entered in its already running terminal. Rootless validation/tool errors exit 1,
argument errors 2, cancellation 130; `status` propagates systemctl status.

## Host client and TUI arguments

Place common options **before** the host-client subcommand:

| Common option | Type and requirement |
| --- | --- |
| `--url` | Required HTTPS origin; no credentials/query/fragment or disabled trust. |
| `--realm` | Required exact expected realm ID. |
| `--trust` | Required local PEM trust path. |
| `--p12` | Required owned private PKCS#12 path. |
| `--checkpoint` | Required owned mode-0700 directory; bound to origin/realm/certificate. |
| `--password-fd` | Optional nonnegative inherited FD with one bounded UTF-8 line; otherwise hidden terminal prompt. |
| `--crypto-classpath` | Optional local Java helper classpath; default app distribution `lib/*`. |

`pki-tui.sh` takes these same options and **no subcommand**. Catalog tree/A–Z,
typed nested/list forms, explicit review, worklist observation and artifact actions
are described in [the operator guide](../deployment/pki-operator.md#interactive-curses-operator).
Changing endpoint/realm/identity invalidates session choices and requires the
correct separate checkpoint. TUI exit 0 means normal UI exit, not successful
execution of pending work; setup failure exits 2.

| Host command | Exact inputs and result |
| --- | --- |
| `discover` | Current operation descriptors and parameter schemas. |
| `read FILE` | JSON `operation`, `arguments`, optional `authorityId`; discovered semantic reads only. |
| `submit FILE` | JSON `version:1`, stable `requestId`, `operation`, `arguments`, optional `authorityId`; durable operations only. |
| `action FILE` | Same input shape; discovered non-durable dedicated actions only; request ID is local once-only tracking. |
| `observe REQUEST_ID [--wait SECONDS]` | GET-only recovery; finite numeric wait 0–3600, default 0. |
| `certificate ID --output PATH [--representation original|pem]` | Exact credential content; default original DER. |
| `ca ID --output PATH [--representation original|pem]` | Current selected generation of that authority; digest checked. |
| `crl ID --output PATH [--representation original|pem]` | Exact retained status object content. |
| `chain ID --output PATH [--representation pem]` | Ordered issuer path bundle; original representation rejected. |

Inputs/credentials must be owned mode-0600 regular files. Outputs must be new
files, with no symlink/overwrite. Stdout is one JSON object with `exit` and
`result` or safe `error`; protect it as application data. Usage errors are stderr
and exit 2; interrupted processes can exit 130 before emitting JSON.

| Python host exit | Interpretation |
| --- | --- |
| 0 | Completed read/download or validated durable SUCCEEDED with result. |
| 2 | Invalid/refused/failed operation, I/O or verification failure. |
| 3 | Accepted, pending or approval-only; execution not successful yet. |
| 4 | Unknown acknowledgement; retain and reconcile without replay. |

## API, schemas and binary routes

| Route | Contract |
| --- | --- |
| `GET /admin/v1/realm` | Authenticated target identity checked before each host request. |
| `GET /admin/v1/operations`, `GET /admin/v1/schema` | Descriptors, typed fields, permissions, scope, availability and durable/dedicated selection. |
| `POST /admin/v1/requests` | Submit exact durable intent once; HTTP 202 retains administrative request identity. |
| `GET /admin/v1/requests/{requestId}` | Observe original durable request, linked approval/signing IDs and terminal result. |
| `POST /admin/v1/operations/{operation}` | Typed operation envelope for reads/dedicated actions and low-level API use; semantic reads may use POST. |
| `GET /admin/v1/certificate-artifacts/{credentialId}` | Authenticated metadata and permitted content links. |
| `GET /admin/v1/certificate-artifacts/{credentialId}/content?representation=original|pem` | Certificate DER or PEM, with independent content permission. |
| `GET /admin/v1/status-artifacts/{statusObjectId}/content?representation=original|pem` | CRL DER or PEM; not a generic JSON operation. |

The host client validates the exact advertised same-origin routes, metadata,
Content-Length, optional Content-Digest, object encoding and required DER/PEM
equivalence. Individual certificate/CRL parsing is not signature verification.
`chain` also verifies ordered cryptography and constraints against its explicitly
selected downloaded anchor. No redirects or anonymous fallback are used.

For each operation the schema specifies text, exact integer, boolean, enum,
base64, object and list fields. For example `key.generate` requires text
`generationId` and enum `parameters`; `algorithm.binding.list` requires integer
`limit`; profile register/validate carry base64 `document`. Nested profile models
are specified by [the profile schema](certificate-profile-schema.md). Do not
invent scalar switches for nested objects. Java remote scalar forms remain
`--arg`, `--arg-int`, `--arg-bool`; nested values use `--arg-json`.

The durable administrative request, approval and signing operation are distinct
identities/states. Preserve all returned coordinates. `ocsp.responder.issue-certificate`
returns server-canonical `ocsp-prov:<slot>:r<revision>`; the host client retains
that separately from the original local request ID. Later local `observe` resolves
to that canonical ID. If its initial acknowledgement is lost, the local ID is not
a server alias: reconcile manually, never guess or repeat the issuance.

See [administrative requests](../admin/administrative-requests.md),
[permissions](operation-permissions.md), [admin HTTPS](pki-server-admin-https.md)
and [Java exit/recovery contract](pki-deployment-cli-contracts.md#output-interruption-and-exit-codes).

## Hybrid SDK and status boundaries

`zeroecho-hybrid-sdk-v1` has strict version-1 JSON/media and exact binary proof
frames, not generic JSON operation extensions. Administrative discovery is
`GET /admin/v1/hybrid-sdk/v1`, challenge and accept are POST sidepaths. Supported
administrative issue/renew/reissue/replace use operation-bound proof of both
applicant keys, the configured origin, realm, actual transport authentication and
frozen issuer/profile/path. SDK client proofs use P-384/ECDSA-SHA384 plus pure
ML-DSA-87, empty context. Never substitute issuer signing keys for subject PoP.

Configured ACME, EST, SCEP and CMP SDK carriers have their own discovery,
challenge and acceptance sidepaths and native authentication. Listener and
enrollment-profile `sdkProfile` opt-in are both necessary; an ordinary endpoint
does not silently accept or fall back from hybrid input. The approval and
original protocol receipt/polling contracts still apply. See
[protocols](../admin/protocols.md) for the supported deployment boundary.

Native RFC 6960 OCSP remains a normal single-signature response.
The separately enabled `/ocsp/{alias}/hybrid-sdk/v1` query returns the ordinary
response plus signed F4/F5 evidence bound to exact request/response bytes,
independent fresh SDK nonce, native nonce, trusted issuer/path/responder roles
and evaluation time. It is **not standard AltSignature BasicOCSPResponse**.
The SDK profile bounds evidence life to 120 seconds, response age to 300 seconds
and future skew to 60 seconds, also bounded by nextUpdate and responder expiry.
Bundle-provided certificates/coordinates are evidence, not trusted expectations.
GOOD does not establish certificate-path or application validity. Historical
GOOD/freshness evidence does not establish current freshness or live
REVOKED/UNKNOWN SDK coverage.

## Qualification arguments and results

`exercise-pki.sh --mode live-demo|full|algorithms|plan` defaults to `live-demo`.
Shared inputs are `--directory PATH`, `--url ORIGIN`, `--admin-p12 PATH`,
`--trust PATH`, `--principal-id ID`, `--output PATH`; full qualification uses
`--connection-file PATH`. Public checks may use `--public-url`, `--public-trust`,
`--require-public`. `--strict-coverage` requires complete supported coverage;
`--maximum-download-bytes` is an integer, default 67108864. Demo selection uses
`--ca-key-ref` (default `zeroecho-lib:root.prv`), `--ca-profile` (`root-ca`) and
`--client-profile` (`vpn-client`).

Algorithms mode additionally takes `--variant p384|rsa4096|mldsa87|hybrid`, exact
`--realm-id`, local `--crypto-classpath`, and hybrid's `--sdk-authentication
direct-mtls-v1|trusted-proxy-mtls-v1`, with `--sdk-transport-principal` required
only for the proxy form. `--approved-sdk-target` pins the reviewed 128-hex SHA-512
target. See [executable recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios).
Unsupported Composite, automatic Twin pairs, P-521/SLH-DSA scenario menu choices
and universal PQC TLS support are not implied by lower-level algorithm classes.

Qualification exits are 0 for the requested successful run, 2 for invalid/blocked/
failed execution, 3 for incomplete/failed full or strict qualification, 4 for
external restart required. Full report flags, algorithm report verification and
cryptographic artifact proof are separate assertions. Counts from overlapping
native, integration, helper and live runs must not be summed as unique tests.

## Recorded qualification scope

The 2026-11-16 retained functional baseline at source revision
`72e45175520c7650aaed1dd1992d7d4687f967e2` has independent documentation-readiness
review PASS. This is historical evidence applicability, not a newly running
instance or new procedure execution.

The actual external rootless installer ran one test successfully; the separate
full host client completed with all four qualification flags true, 152 catalog
entries EXECUTED and one justified unavailable legacy `backup.restore` entry.
Streaming restore separately reached ACTIVATED and acknowledgement. Four hosted
P-384/RSA-4096/ML-DSA-87/hybrid hierarchies and four distinct certificate/ordered-
chain/full-delta-new-full CRL representation/signature proof sets passed. Native
ACME/EST/SCEP/CMP issuance included key/chain checks. This does not claim every
algorithm/protocol combination was tested live.

Supporting server tests were 611/0/0/0; deployment Python was 219/0/0/1 (218
executed, the installer separately executed externally). Earlier core 1909,
application 118 and API 4 results retain their source/environment applicability;
helper synthetic checks were 31 Java and 15 Python. These overlapping counts are
not a unique-test total and native helper tests are not hosted qualification.

The separate SDK OCSP live proof covered one SHA-256 CertID GOOD result,
verified at 16:47:28Z and independently at 16:48:13Z within its 120-second bound.
It does not establish current freshness or live SDK REVOKED/UNKNOWN coverage.
The final owner-controlled runtime stop was recorded at 17:00:19Z; no old
instance or retained `/tmp` is assumed. A portion of one earlier historical
startup/READY raw log was lost; independent earlier observations and later
exact-label absence checks do not reconstruct it or prove global cleanup.
Failed and intermediate attempts remain adverse evidence. Restart assurance
uses source and retained client receipts/checkpoints, not an independently
captured server wire/audit trace. Generation association is interval inference
where explicitly recorded, not invented direct metadata.

Fresh v18/no migration, no Composite, no atomic Twin, no private-key export and
no universal PQC browser/TLS compatibility remain the supported boundaries.
