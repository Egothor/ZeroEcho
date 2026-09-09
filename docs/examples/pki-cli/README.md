# ZeroEcho PKI CLI — overview and worked examples

> Seed material for the user/admin guide (Task 16). This directory documents the
> single-process `zeroecho pki` command family and ships three runnable demos.

## 1. What it is

The PKI CLI is a **single-process command-line utility** — an `openssl`-style
tool that performs concrete PKI operations synchronously against a local store
and signer. It is **not** a client for a remote PKI service; a network front-end
is a separate, later concern. Everything one invocation needs (store, audit
sink, signing keyring, publishers) is described in one configuration file.

Each invocation runs one operation (or one plan), prints a machine-readable
result to stdout, and exits with a stable code. When an operation depends on an
**asynchronous** signer (e.g. a remote HSM/queue), the CLI waits a bounded time
and then exits cleanly with a "pending" result so an operator can resume later —
it never blocks indefinitely.

## 2. Command surface

```
zeroecho pki <operation> --config <file> [--output human|json] [--pending-wait <s>] [args…]
zeroecho pki run <plan-file> --config <file> [--output human|json] [--pending-wait <s>]
zeroecho -K …            # keyring management (key generation, listing) — see §7
```

- `--config` — path to the session configuration (§4). Required.
- `--output` — `human` (default) or `json`. Scripts should use `json`.
- `--pending-wait <seconds>` — bounded wait (default **3**, range 0–3600) for an
  asynchronously-signed operation to complete before a clean pending exit.

Run `zeroecho pki --help` for the full operation list with arguments.

## 3. Two ways to run a scenario

| Mode | Command | When to use |
|------|---------|-------------|
| **Per-operation** | one `zeroecho pki <op>` per step | scripting incrementally, wiring into other tools, or when later steps need IDs discovered mid-run |
| **Batch** | one `zeroecho pki run <plan.json>` | signing a whole **series** of certificates in a single operator run |

A batch plan is a JSON document whose steps can reference earlier steps' outputs
with `${<step-id>.<field>}` (e.g. `${inter.caId}`). Step ids are lowercase
kebab-case. `failurePolicy` is `FAIL_FAST` (stop on first failure) or
`CONTINUE`. See `plan-minimal.json` produced by `demo-minimal.sh`.

If a scenario cannot be expressed as one batch (because a step's arguments are
only known after inspecting the result of an earlier step), split it into
several invocations — the per-operation model.

## 4. Session configuration (version 2)

```json
{
  "version": 2,
  "store":  { "provider": "fs",     "properties": { "root": "<dir>" } },
  "audit":  { "provider": "memory", "properties": { "size": "512" } },
  "signing": {
    "workflow":  { "provider": "zeroecho-lib", "properties": { "keyringPath": "<keyring>" } },
    "framework": { "provider": "x509-bc", "properties": {} },
    "signatureAlgorithm": "SHA256withRSA",
    "signingTtlSeconds": 30,
    "unlockEnvironmentVariable": "ZEROECHO_KEYRING_PASSWORD"
  },
  "publishers": [
    { "provider": "filesystem", "properties": { "root": "<dir>", "targetId": "local" } }
  ]
}
```

- **store** — object store for CAs, requests, credentials, status objects.
- **signing.workflow** — `zeroecho-lib` signs with keys from a local keyring
  (`keyringPath`); the keyring is unlocked from `unlockEnvironmentVariable`.
- **signing.framework** — `x509-bc` produces X.509 via BouncyCastle.
- **publishers** — where status objects (CRLs) are published; referenced from
  `publication.*` operations by `targetId`.

## 5. Profiles (schemaVersion 5)

Certificate policy lives in **profiles**, registered and activated before use:

```
zeroecho pki profile.register --config c.json --profile-file root-ca.json
zeroecho pki profile.activate --config c.json --profile-id root-ca --profile-version 1
```

The demos install five practice-usable profiles: `root-ca`, `intermediate-ca`
(CA profiles with key usages `keyCertSign,cRLSign` and path-length limits) and
`server-tls`, `vpn-server`, `vpn-client` (end-entity profiles with the right
EKUs — `serverAuth` for TLS/IPsec gateways, `clientAuth` for road-warriors — and
SAN rules). They are self-contained JSON; adapt validity, algorithms, and SAN
constraints to your policy.

## 6. Operation catalog (by area)

- **configuration / algorithm** — `configuration.validate`,
  `algorithm.binding.list|inspect|validate`
- **profiles** — `profile.validate|register|inspect|list|activate`
- **authorities** — `ca.inspect|list|create|transition`,
  `ca.intermediate.create` (new sub-CA), `ca.intermediate.issue`
  (**cross-certification** — one root certifies another CA's key),
  `ca.rollover`, `ca.rotate`
- **issuer paths** — `issuer.generation.inspect`,
  `issuer.path.inspect|list|register|select`
- **requests** — `request.inspect|import|verify` (import a standard PKCS#10 CSR)
- **credentials** — `credential.inspect|issue|renew|replace|reissue`
- **revocation** — `credential.revoke`, `revocation.inspect|history|snapshot`
- **status objects** — `status.inspect|generate` (CRL / delta CRL),
  `inventory.status`
- **publication** — `publication.inspect|list|register|process|retry|reconcile`

The CLI **does not mint private keys**. CA keys are provisioned in a keyring up
front (§7); subjects hold their own keys and submit CSRs (`request.import`).

## 7. Keyring prerequisites

CA signing keys live in a POSIX keyring managed by `zeroecho -K`:

```
zeroecho -K --generate --alg RSA --alias root \
         --keystore <dir>/ca-keyring.zek --keystore-password-env ZEROECHO_KEYRING_PASSWORD
```

- The keyring's **parent directory must be mode 0700** and on a POSIX filesystem;
  key files are 0600. (`chmod 700` the directory before generating.)
- Operations reference a key as `zeroecho-lib:<alias>.prv` in `keyRef` /
  `--key-ref` (e.g. `zeroecho-lib:root.prv`).
- Non-interactive unlock uses `--keystore-password-env <VAR>` (and, for signing,
  `signing.unlockEnvironmentVariable`).

## 8. Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | invalid invocation |
| 3 | configuration failure |
| 4 | validation or policy rejection |
| 5 | not found or conflict |
| 6 | recovery required |
| 7 | external outcome unknown (**pending** async signing — resume later) |
| 8 | resource failure / overloaded |
| 9 | internal failure |
| 130 | cancelled |

## 9. The demo scripts

All three target a fictional org "Example s.r.o." Run any of them with a built
app distribution on PATH (`ZE_HOME=<dir with bin/app>`), `openssl` available,
and — for the per-operation and enterprise demos — `python3`.

| Script | Model | Scenario |
|--------|-------|----------|
| `demo-minimal.sh` | one **batch** | two-tier CA; issue HTTPS (`web`), IPsec gateway (`gtw`), road-warrior client; revoke the client (theft → `KEY_COMPROMISE`); publish a CRL. Self-contained single file. |
| `demo-per-operation.sh` | **per-operation** | identical scenario, one `zeroecho pki` process per step (openssl-style), threading IDs between calls. |
| `demo-enterprise.sh` | **per-operation** | two roots + one issuing CA; **cross-certification** of the issuing CA under a second root; **six** leaf certificates (two HTTPS, one gateway, three road-warriors); two revocations (`KEY_COMPROMISE`, `SUPERSEDED`); credential reissue; CRL publish; inventory/audit views. |

`demo-per-operation.sh` and `demo-enterprise.sh` share setup via `_common.sh`
(keyring seeding, config, profiles, CSR generation, and the `run_op`/`field`
helpers). `demo-minimal.sh` is intentionally standalone so it can be read top to
bottom as a single artifact.

```
ZE_HOME=/path/to/app/build/install/app ./demo-enterprise.sh /tmp/ze-ent
```

SAN addresses use the RFC 5737 documentation range (`192.0.2.0/24`) and the
RFC 2606 example domain (`example.com`); replace them for real deployments.

### Inspecting the results

Issued objects live in the store, not on disk. To hand the operator files they
can examine, each demo **publishes** every CA certificate, leaf certificate, and
the CRL to the filesystem publisher (a real `publication.*` operation) and then
copies the bytes into a `certs/` directory under the work dir, as both DER
(`.der`) and PEM (`.pem`):

```
<workdir>/certs/
  root-ca.pem  issuing-ca.pem  web.pem  gtw.pem  road-warrior.pem  crl.pem   (+ .der)
```

Inspect them with ordinary `openssl`:

```sh
openssl x509 -in <workdir>/certs/web.pem -noout -subject -issuer \
        -ext subjectAltName,extendedKeyUsage
openssl crl  -in <workdir>/certs/crl.pem -noout -text | head
# verify the chain:
openssl verify -CAfile <(cat <workdir>/certs/issuing-ca.pem <workdir>/certs/root-ca.pem) \
        <workdir>/certs/web.pem
```

(The filesystem publisher stores each object as `sha256(publicationId).bin`; the
scripts recompute that name to copy the bytes out under a friendly filename.)

## 10. Security notes

- Keep the keyring directory 0700 and its passphrase out of shell history —
  supply it via an environment variable, not a flag.
- The `memory` audit sink is for demos; production deployments should point
  `audit` at a durable sink.
- Profiles are policy: review key usages, EKUs, path-length and validity before
  issuing against them in anger.
