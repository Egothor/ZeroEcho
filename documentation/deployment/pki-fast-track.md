# PKI fast-track: a disposable qualification

Owner: PKI maintainers. Reviewed: 2026-11-16. Review on launcher or configuration
changes. These written instructions have source review only; clean-environment
procedure execution and assembled-site verification are still outstanding.

Use this path to qualify a new disposable instance from a source checkout.
For a retained service use [production deployment](pki-production.md). The
qualification environment prepares test accounts, authorities, protocol listeners
and deliberate failure fixtures; it is not a production installation.

## Prepare the host and checkout

Use Linux as a non-root user, rootless Podman with subordinate UID/GID mappings,
working IPv4 networking, Python 3, OpenSSL with `pkcs12 -jdktrust` support
(OpenSSL 3.4+), and Java 25+. Container builds need registry and dependency
repository access. Keep sufficient private local POSIX storage for images,
server data and client evidence. Persistent installation additionally requires
user systemd, curses, curl and the [installer prerequisites](rootless-podman.md#requirements).
An OpenSSL installation requirement is not a claim of PQC key-generation support.

From the ZeroEcho checkout, prepare the local cryptographic helper. Run Gradle
commands serially, before starting a deployment that may build its own helpers:

```sh
./gradlew :app:installDist --no-parallel
mkdir -p "$HOME/.local/share" "$HOME/.local/state"
```

Choose an unused deployment path and unused sibling client path. In the examples,
`northstar-qualification` and `northstar-qualification-client` must not already
exist. Choose a new result directory for each new environment. Never redirect an
old connection descriptor or checkpoint to a replacement instance.

## Terminal 1: deploy and retain the console

Run in a normal console as the deployment owner:

```sh
./deploy/rootless-pki.sh test-start --hybrid-sdk \
  --directory "$HOME/.local/share/northstar-qualification"
```

Enter and confirm a new administrator PKCS#12 password at the hidden prompts.
Remember it: terminal 2 needs the same password. It protects the exported client
identity, not a web username/password login. `--hybrid-sdk` explicitly enables
the administrative SDK and the separate public OCSP SDK for this **fresh** test
environment; without it those optional SDK listeners remain disabled. It does
not turn native OCSP into standard AltSignature OCSP.

Wait for the actual `READY` line naming
`$HOME/.local/share/northstar-qualification-client/client-config.json`.
Keep this terminal open. The descriptor contains this instance's published
addresses, expected realm and client-only exports. Use the printed paths and
addresses; do not assume example ports or another instance's identifiers.

For browser inspection, use the exported administrator `.p12` and public trust
certificate paths recorded by this deployment's client descriptor. Import the
trust CA into your browser when it is private, then import the PKCS#12 using the
password just entered. Open the descriptor's administrative HTTPS origin and
select that client identity. Use an isolated browser profile for a test identity.
There is no username/password login; a successful curl call does not import a
browser identity. Do not browse or copy the server's private store or keyring.

## Terminal 2: run the external client

From the same checkout in a second normal console:

```sh
./deploy/exercise-pki.sh --mode full \
  --connection-file "$HOME/.local/share/northstar-qualification-client/client-config.json" \
  --output "$HOME/.local/state/northstar-qualification-results"
```

Enter the administrator export password privately. The client uses published
HTTPS/protocol interfaces and its own keys, receipts and files. It does not invoke
Podman, modify server files or restart anything. Missing configured prerequisites
are a blocked result, not permission for the client to deploy them.

### Restart and resume the retained restore

When the client exits **4** with `WAITING_EXTERNAL_RESTART`, retain its output.
In **terminal 1**, enter:

```text
restart
```

Wait for a new `READY`, then repeat the **identical terminal-2 command**, against
the same descriptor and output directory. The client observes the original
restore through `backup.stream.status` (a semantic read transported by POST),
then separately acknowledges `ACTIVATED`. It must not repeat the export, upload,
restore or approval mutations. Ordinary durable-request recovery uses GET only.

## Interpret results and stop

Inspect the client `report.json`, checkpoint and retained receipts. A complete
successful full qualification requires exit 0, `executionState=COMPLETE` and
`qualified`, `protocolQualified`, `deploymentQualified`, and
`catalogueQualified` all true. `COMPLETE` alone describes traversal, not success.
`BLOCKED`, `FAILED` and pending approvals are incomplete. `NOT_APPLICABLE` needs
a supported reason; the unavailable legacy `backup.restore` does not replace
streaming restore. See [full report semantics](pki-exercise.md#evidence-and-incomplete-prerequisites).

The full run and [four algorithm recipes](pki-exercise.md#approved-algorithm-scenarios)
are distinct. `algorithm-report.json` deliberately keeps `podmanQualified=false`;
a verified certificate scenario alone is not catalogue, protocol, CRL or OCSP
qualification. Keep actual environment/source association alongside its report.

In **terminal 1**, enter:

```text
stop
```

This disposable lifecycle cleans its owned server environment; preserve the
separate client export and output before losing access to the host. EOF or
Ctrl-C also ends its deployment console. Do not treat those client exports as
a server backup. Do not presume a previous instance or `/tmp` survives.

Retain source revision, actual commands, exit codes, complete available logs,
descriptors, reports, checkpoints and public artifacts under private access.
Keep failed/intermediate attempts as separate evidence. If a raw log is lost,
record the loss; later observations cannot reconstruct it. Status signatures
and freshness must be checked at the actual evaluation time: historical OCSP
evidence is not current status.
