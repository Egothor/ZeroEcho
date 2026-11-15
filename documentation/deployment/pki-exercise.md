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

## Approved algorithm scenarios

The `algorithms` mode creates a **new root, intermediate and client hierarchy**
for exactly one selected variant. It is separate from the historical P-256 demo
and the full catalogue/protocol qualification. Use a fresh empty v18 installation;
there is no migration procedure. Maintainer: PKI engineering; review when the
SDK profile or issuer binding contract changes.

| Variant | Root, intermediate and client subject keys | Every issuer signature | Alternative role |
| --- | --- | --- | --- |
| `p384` | EC, named `secp384r1` | ECDSA with SHA-384 | Absent |
| `rsa4096` | RSA, 4096-bit modulus | PKCS#1 v1.5 with SHA-384 | Absent |
| `mldsa87` | ML-DSA-87 | Pure ML-DSA-87, empty context | Absent |
| `hybrid` | EC, named `secp384r1` | ECDSA with SHA-384 | ML-DSA-87 subject keys and Cor. 3 alternative signatures |

PQC and hybrid certificates target capable SDK clients. Their successful
verification does not establish ordinary browser/TLS interoperability. Transport
TLS and administrator login keys remain separate from these business keys.
Composite is excluded. A Twin deployment consists of independently running the
classical and PQC scenarios with separate outputs and retaining both hierarchies;
there is no atomic pair issuance or shared lifecycle promise.

### Deployment prerequisites

In the deployment terminal, prepare a new installation. The explicit flag enables
only the existing administrative SDK listener at the configured external origin:

```sh
./deploy/rootless-pki.sh install --hybrid-sdk \
  --directory "$HOME/.local/share/zeroecho-pki-c04"
```

Enter the intended hostname, port, realm and independent initial administrator
identities in the installer. Record the exact realm ID. The configured SDK origin
includes the explicit HTTPS port. The FIRST administrator generates managed keys;
ordinary administrators do not acquire that capability by selecting this mode.
Enable its existing own-approval and certificate-download capabilities explicitly:

```sh
./deploy/rootless-pki.sh update --root-admin --certificate-access \
  --directory "$HOME/.local/share/zeroecho-pki-c04"
```

These commands belong to the deployment operator. The external exercise never
executes them, changes server configuration or resolves missing prerequisites.
For classical/PQC-only installations, `--hybrid-sdk` can be omitted. This option
applies to fresh installation only; an already configured listener is not silently
changed on resume. Missing SDK configuration is a blocked prerequisite.

Build the local client cryptographic helper from this checkout with Java 25+:

```sh
./gradlew :app:installDist
```

Run Gradle commands serially. The helper uses the distribution's existing
Bouncy Castle/ZeroEcho libraries; it does not depend on OpenSSL having PQC support.
Python 3 and OpenSSL are still required for HTTPS login extraction. The scenario
requires a POSIX filesystem with owner-only files and directories.

### External client invocation

In a normal host console, set the exact selected realm and FIRST administrator ID
from the installation (the values below are examples to replace):

```sh
C04_REALM=production
C04_PRINCIPAL=bootstrap-admin
C04_INSTALL="$HOME/.local/share/zeroecho-pki-c04"
C04_OUTPUT="$HOME/.local/state/zeroecho-pki-c04-p384"

./deploy/exercise-pki.sh --mode algorithms --variant p384 \
  --directory "$C04_INSTALL" --realm-id "$C04_REALM" \
  --principal-id "$C04_PRINCIPAL" \
  --crypto-classpath "$PWD/app/build/install/app/lib/*" \
  --output "$C04_OUTPUT"
```

Use `--variant rsa4096` or `--variant mldsa87` and a **different initially empty**
output directory for the other ordinary scenarios. Explicit `--url`,
`--admin-p12` and `--trust` overrides work as in the demo. No client connection
file or server filesystem access is used in this mode. PKCS#12 passwords retain
the hidden-input/stdin handling described above.

The client generates and retains its own private key and signed PKCS#10 CSR.
Only the protected FIRST administrator asks `key.generate` for distinct managed
root/intermediate keys with explicit parameters; only public SPKI and opaque key
references return. Each run registers uniquely named root/intermediate/client
profiles restricted to its selected family. These `NONE`-approval profiles become
active through the existing registration contract; administrative operations still
use their configured durable approval policy. Root/intermediate creation passes
explicit `signatureAlgorithmId`; client issuance selects the exact intermediate
CA and checks the returned immutable generation. Normal CSR import and proof
verification precede ordinary issuance. No CA private key is downloaded.

For the hybrid scenario use its own output and the actual authentication context.
The rootless installer uses the following proxy context:

```sh
C04_OUTPUT="$HOME/.local/state/zeroecho-pki-c04-hybrid"
./deploy/exercise-pki.sh --mode algorithms --variant hybrid \
  --directory "$C04_INSTALL" --realm-id "$C04_REALM" \
  --principal-id "$C04_PRINCIPAL" \
  --crypto-classpath "$PWD/app/build/install/app/lib/*" \
  --sdk-authentication trusted-proxy-mtls-v1 \
  --sdk-transport-principal trusted-proxy --output "$C04_OUTPUT"
```

For a separately configured direct mTLS administrative endpoint use
`--sdk-authentication direct-mtls-v1` and omit `--sdk-transport-principal`.
Do not guess a proxy identity. Hybrid root and intermediate alternative keys are
separate managed ML-DSA-87 keys. Both client subject keys belong to the client;
the CSR requests its alternative SPKI, never an issuer private key.

The first hybrid invocation intentionally stops with exit 2 before signing either
SDK proof and writes `sdk-target-proposal.json`. Inspect its exact subject/SAN,
absolute validity, disclosure policy, approval commitment, generation/path and
selected arguments. Check the printed target SHA-512 against that file. Repeat
the **same command and output** with the printed literal digest:

```text
--approved-sdk-target <the reviewed 128-character targetSha512>
```

Complete review within the retained 300-second challenge lifetime. This explicit
pin binds the entire proposed policy, including the opaque provider binding-set
commitment; the client also independently checks selected issuer roles, actual
certificate digest, profile version/hash and operation arguments. It derives F6
from the login certificate and explicit actual transport context, then checks
origin, realm, request, nonce and both subject SPKIs before signing exact F1/F2.
This review does not replace administrative approval of the issuance request.
Expired or partially written proof attempts fail closed. Preserve their output;
use a fresh output only after checking that no acceptance occurred. A lost
challenge acknowledgement needs operator reconciliation; it is not automatically
replaced. A lost acceptance acknowledgement is observed by its saved request ID;
it never causes another issuance POST. Keep all retained keys and receipts.

### Artifacts, verification and evidence boundary

The output retains generated profile documents, CSR and private applicant keys,
HTTP request/approval receipts, and original DER/PEM root/intermediate/client
artifacts retrieved through the existing authenticated content routes. Private
applicant keys are PKCS#8 DER in `client-keys/`; they are not server-managed keys.
`algorithm-report.json` is scenario-only: `verified: true` requires actual helper
success; `podmanQualified` remains false. Failure/pending output is not success.

Verification checks exact algorithm OIDs and parameters (including named curve,
RSA modulus size and absent ML-DSA parameters), root self-signature and both issuer
links, CA constraints/usage, clientAuth/SAN, exact selected managed SPKIs, and
client private-key possession. Hybrid checks additionally require all three
alternative extensions, ML-DSA-87 SPKIs, both issuer relationships and every
Cor. 3 alternative signature. OpenSSL primary verification is not used as a
substitute for PQC/alternative verification. The authenticated downloaded root
is this scenario's trust anchor; this does not qualify external trust stores.
The cryptographic verification covers original DER; downloaded PEM is retained
as a separate representation, not independently asserted as verified.

The native rehearsal runs the real Python client and local helper against a
fresh localhost HTTPS PKI, including completed-run observation without mutation
replay:

```sh
./gradlew :app:test --tests zeroecho.pki.cli.CertificateScenarioCryptoTest
./gradlew :pki-server:certificateScenarioTest
PYTHONPATH=deploy python3 -m unittest discover -s deploy -p 'test_*.py'
```

This rehearsal is distinct from a live PKI in Podman. Actual Podman deployment,
protocol qualification and release readiness require separately retained C08
results. Scenario artifacts alone are not a full-catalogue, CRL, OCSP or protocol
qualification report. Existing C03 native mixed-issuer, protocol, CRL and OCSP
checks retain their narrower stated environments.
