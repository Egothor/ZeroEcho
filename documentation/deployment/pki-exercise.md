# PKI deployment and host-client qualification

The two entry points have separate responsibilities:

- `deploy/rootless-pki.sh` installs, starts and manages PKI containers, server keys,
  profiles and protocol prerequisites.
- `deploy/exercise-pki.sh` is a normal host-console HTTPS client. It never starts
  containers, restarts the server, opens its store or reads its private keyring.

The host client needs Python 3 and OpenSSL. **Full SCEP/CMP qualification also
requires Java 25 or later** for the compiled SDK/client helper prepared by the
deployment script. The live demo does not require that Java helper. Podman is a
dependency of the deployment script, not of the host test client.

## New demo objects on the existing installation

From the source checkout:

```sh
./deploy/exercise-pki.sh
```

The defaults are the deployed URL, `logins/administrator.p12` and
`logins/web-ca.pem` under `~/.local/share/zeroecho-pki`. The PKCS#12 password is
entered with hidden input and supplied to OpenSSL on stdin, never in arguments,
environment variables, checkpoints or reports. Extracted login material is private
and removed at exit.

This mode creates a new demo CA using an existing protected server key, generates
a random local P-256 client key and CSR, issues a client certificate, confirms key
possession and revokes that new client. It downloads CA/client DER and PEM, a full
CRL before revocation, its delta and a new full CRL after revocation. OpenSSL checks
signatures, key matching, the delta base, revoked serial and key-compromise reason.
Certificate verification with the final full CRL must fail specifically because
the client was revoked.

Existing authorities, roles, deployment configuration and backups are not changed.
New demo objects and their audit/approval records remain on the server. Only the
initial root administrator's existing own-approval capability is used; the client
does not grant itself permissions or change policy.

An explicit URL/login override is available:

```sh
./deploy/exercise-pki.sh --url https://localhost:8443 \
  --admin-p12 /path/to/administrator.p12 --trust /path/to/web-ca.pem \
  --principal-id bootstrap-admin --output "$HOME/.local/state/pki-demo"
```

The URL must match the actual trusted server certificate. TLS verification remains
enabled.

## Full qualification against a separately started deployment

First terminal — the deployment script owns the complete disposable environment:

```sh
./deploy/rootless-pki.sh test-start --directory "$HOME/.local/share/zeroecho-pki-test"
```

Wait for `READY` and keep this terminal open. The script exports a private client
connection file in the sibling `zeroecho-pki-test-client` directory. It owns
container lifecycle, server-side profiles, keys, protocol custody, DNS setup,
prepared publication failure states and the initial bounded legacy backup.
Those preparation actions are not counted as client test receipts.

Second terminal — run only the host client:

```sh
./deploy/exercise-pki.sh --mode full \
  --connection-file "$HOME/.local/share/zeroecho-pki-test-client/client-config.json" \
  --output "$HOME/.local/state/zeroecho-pki-test-results"
```

The client requires a private owner-only version-1 connection descriptor with
`purpose=qualification`. Its environment identity must match the realm returned
by verified HTTPS before any mutation. Only exported client credentials, public
certificates, protocol addresses and preparation metadata are accepted. Server
configuration paths, image IDs and server keyring passwords are rejected.

## Restore requires an external restart

When a restore is `STAGED`, the client writes `WAITING_EXTERNAL_RESTART` and exits
with code **4**. It does not execute a service command. In the **first terminal**,
enter:

```text
restart
```

After the deployment console reports `READY`, repeat the exact client command
with the **same output directory**. The client observes the retained restore ID
through the existing read-only `backup.stream.status` operation (HTTP POST), then
acknowledges `ACTIVATED` once. It does not repeat export, upload, restore or approval
mutations. GET realm checks continue to verify the target identity.

## Evidence and incomplete prerequisites

`report.json` records every reviewed catalogue operation. Positive results require
actual API receipts and state assertions. Publication checks use authoritative
HTTP state and source hashes; the client never inspects the publisher filesystem.
Prepared retry/reconciliation identities are required; their absence is `BLOCKED`,
not a successful test.

`protocolQualified` independently requires actual ACME, EST, SCEP and CMP issuance,
private-key matching and certificate-chain verification. Account creation,
discovery and signed general messages alone are insufficient. Protocol client
keys belong to the client directory; no server signing key is exported.

Public checks use a separate HTTPS client without administrator certificate,
cookie or bearer. Public CA and CRL bytes must match authenticated downloads, and
a private client certificate must remain undisclosed. Missing public/protocol
prerequisites leave full qualification incomplete.

Exit codes:

- `0`: requested demo passed, or full qualification completed.
- `2`: invalid input or execution failure.
- `3`: full/strict qualification is incomplete or failed.
- `4`: a retained restore awaits a restart by the separate deployment script.

Client keys, CSR, certificates, CRLs, checkpoint and report remain in the printed
private output directory. `client.key` is retained with mode `0600`; losing it
requires a fresh run/output directory rather than silently substituting a key.
Lost acknowledgements never cause blind replay of a mutation.

Unit and component tests support these contracts. They do not establish that an
unobserved deployment started successfully or that a real Podman qualification
run passed; retain the report produced by the actual host client.
