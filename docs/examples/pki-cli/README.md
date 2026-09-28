# PKI CLI worked examples

These examples use the synchronous local CLI (mode c): every invocation opens
and closes the shared PKI implementation without starting an HTTP listener or
reactor. The same distribution also supports the remote mTLS CLI (mode b) for
operations on the permanent backend used by the web frontend (mode a). See the
[current CLI guide](../../pki-cli.md) for both configurations and remote receipts,
and the [deployment guide](../../../deploy/README.md) for the server and web app.

## Run the demos

Build the distribution from the repository root:

```sh
./gradlew :app:installDist --offline
```

All scripts require Bash, Python 3, OpenSSL and `sha256sum`. The generated launcher
is `app/build/install/app/bin/app`; `zeroecho` in the general CLI guide denotes this
same application. `ZE_HOME` can select another installed distribution.

Set `ZEROECHO_KEYRING_PASSWORD` to a nonempty password using your secret-management
mechanism, then run a script with a fresh, empty work directory:

```sh
docs/examples/pki-cli/demo-minimal.sh /tmp/pki-batch-demo
docs/examples/pki-cli/demo-per-operation.sh /tmp/pki-operation-demo
docs/examples/pki-cli/demo-enterprise.sh /tmp/pki-enterprise-demo
```

If the directory is omitted, the script creates a temporary one and prints its
path. It rejects a nonempty directory before generating keys. Files are private
by default (`umask 077`); the work and keyring directories have mode 0700. The
demos intentionally create unencrypted subject private keys for OpenSSL CSR
creation. Keep the entire work directory private and dispose of these test keys
when finished. No default keyring password is provided or written to configuration.

| Script | Execution | Scenario |
| --- | --- | --- |
| `demo-minimal.sh` | Three sequential plans, then export commands | Root and issuing CA; HTTPS, VPN gateway and client certificates; client revocation for theft; CRL publication. |
| `demo-per-operation.sh` | One operation per invocation | The same two-tier CA, three certificates, revocation and CRL. |
| `demo-enterprise.sh` | One operation per invocation | Two roots; issuing CA cross-certified under the second root; six leaf certificates; two revocation reasons; reissue; CRL publication and inventory reads. |

All three use `_common.sh` to provision the keyring, profiles, CSRs and local
configuration. CA keys use the application's existing `-K` keyring management;
subject keys and PKCS#10 requests use OpenSSL. SAN names and addresses are example
identities (`example.com`, `192.0.2.0/24`). These are demonstration profiles, not a
production certificate policy.

## Configuration and execution

Each generated `config.json` uses local schema version 1, `mode: "local"` and
`operatorId: "demo-local-root"`. That identity is an explicit trusted local audit
declaration. Invoking a signing command constitutes approval by the local root
operator; profile, key, proof and validity checks still apply. The configuration
uses the filesystem store, local `zeroecho-lib` signer, filesystem publisher and
an in-memory audit sink. Production use requires an appropriate durable audit
sink and reviewed profiles. Signing unlocks from the named environment variable;
the password value is never embedded in the file.

Only one writable process can own the store. Stop the backend before using a
local CLI configuration against its store. Do not run these scripts concurrently
against one directory. Use the remote CLI to administer a running backend.

The minimal demo writes `plan-root.json`, `plan-intermediate.json` and
`plan-issuance.json`. Plans use `failurePolicy: "FAIL_FAST"` and earlier-step
references such as `${csr-web.requestId}` and `${rw.credentialId}`. The other
supported failure policy is `CONTINUE_INDEPENDENT`. A completed signing operation
returns `credentialId`. `credential.inspect` supplies the issuing authority's
`authorityId`, which is also the subject CA for a self-signed root. For a new
intermediate, the scripts select the sole `INTERMEDIATE` authority in their fresh
store using `ca.list`; using its certificate's issuer would select the root.

New CA certificate validity is rounded inward to whole seconds. The scripts
inspect the certificate and wait at most five seconds for its actual `notBefore`
before using that issuer. This is a read-only example-level wait between plans
or commands, with no mutation resubmission. Local signing itself is synchronous;
`--pending-wait` applies only to the remote CLI.

## Results and recovery

JSON receipts are retained in `out/`, including nonzero exits. The minimal demo
also retains each full plan receipt. The scripts stop on failure and do not retry
an operation automatically. Read the retained receipt and its `operationId`
before deciding what to do next; do not rerun a whole script over the store.

To inspect and explicitly finish a selected local signing operation, use the
original configuration and retained ID:

```sh
app/build/install/app/bin/app pki signing.operation.inspect \
  --config /tmp/pki-batch-demo/config.json --operation-id SIGNING_OPERATION_ID --output json
app/build/install/app/bin/app pki signing.operation.complete \
  --config /tmp/pki-batch-demo/config.json --operation-id SIGNING_OPERATION_ID --output json
```

Inspection never advances the operation. Its successful read does not mean the
underlying operation succeeded: examine `output.state`. Completion advances only
the selected ID. A persisted signature may be completed without signing again;
an unrecoverable dispatch without a durable result is not silently repeated.
Live leases and future retries return immediately. Ordinary reads and unrelated
commands do not recover previous work.

Publication runs synchronously through `publication.register` and
`publication.process`. Filesystem publication failure is not successful export;
inspect the publication and resolve its reported failure/reconciliation state
before using explicit `publication.retry` or `publication.reconcile` as appropriate.
Signing receipts likewise distinguish domain completion from durable signing
alone. Exit codes and recovery flags are documented in the
[Deployment and CLI contracts](../../pki-deployment-cli-contracts.md).

## Inspect the artifacts

The examples publish CA certificates, leaf certificates and CRLs through the PKI
filesystem publisher, then copy them into `certs/` with readable names as DER and
PEM. The publisher stores bytes as `sha256(publicationId).bin`.

For the minimal and per-operation examples:

```sh
openssl x509 -in /tmp/pki-batch-demo/certs/web.pem -noout -subject -issuer \
  -ext subjectAltName,extendedKeyUsage
openssl crl -in /tmp/pki-batch-demo/certs/crl.pem -noout -text
openssl verify -CAfile /tmp/pki-batch-demo/certs/root-ca.pem \
  -untrusted /tmp/pki-batch-demo/certs/issuing-ca.pem /tmp/pki-batch-demo/certs/web.pem
```

Enterprise exports additionally include `root-a.pem`, `root-b.pem`,
`issuing-ca-cross.pem` and `alice-reissued.pem`. Verify the alternate chain with
Root B as the trust anchor and `issuing-ca-cross.pem` as the intermediate.
Certificate export does not claim that an end-entity confirmation protocol has
completed; these examples focus on local issuance, revocation and publication.
