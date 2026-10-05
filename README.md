# ZeroEcho

ZeroEcho is a Java 25 cryptography library and certificate-authority platform.
It includes a transport-neutral PKI backend, an HTTPS server, an administration
SPA, and a command-line client for local and remote operations.

## Modules

| Module | Responsibility |
|---|---|
| `lib` | Cryptographic algorithms and parameter discovery, PKIX facades and consumer SDK. BouncyCastle 1.86 is confined here. |
| `ext` | Optional integrations over library contracts. |
| `pki` | CA lifecycle, profiles, issuance, revocation, publication, scheduling, durable signing and filesystem persistence. |
| `pki-server` | HTTPS administration and enrollment protocols, authentication, authorization, approvals, metrics and server lifecycle. |
| `pki-frontend` | Administration SPA consuming generated operation descriptors. |
| `app` | CLI and application assembly. |
| `api-spec` | OpenAPI generation from the operation catalog. |
| `samples` | Public API examples. |
| `buildSrc` | Shared Gradle conventions and architecture checks. |

## Run and administer

Build the distributions with the repository's Java 25 toolchain:

```bash
./gradlew :app:installDist :pki-server:installDist
```

The application plugin emits the CLI launcher named `app`, not `zeroecho`.
From the repository root, define the documentation's `zeroecho` shorthand and
place the server launchers on `PATH`:

```bash
zeroecho() { ./app/build/install/app/bin/app "$@"; }
export PATH="$PWD/pki-server/build/install/zeroecho-pki-server/bin:$PATH"
```

Then:

```bash
zeroecho pki --help
zeroecho-pki-server --help
```

Local mode opens one lifecycle-owned `PkiSession` and executes synchronously.
It accepts individual typed operations or version-1 sequential plans. Remote
mode submits one operation over mutual TLS and polls accepted signing work;
an uncertain outcome must be inspected, never blindly resubmitted.

```bash
zeroecho pki configuration.validate --config local.json
zeroecho pki run administration-plan.json --config local.json --output json
zeroecho pki ca.list --url https://pki.example.com:8443 \
  --client-cert admin.pem --client-key admin-key.pem --trust server-ca.pem \
  --limit 25 --output json
zeroecho-pki-server --validate-config --config server.json
```

These deployment examples require the named configuration and TLS files.
`--config` and `--url` are mutually exclusive; `--pending-wait` is remote-only.
The public local CLI configuration is **version 1**, with `mode: "local"`
and `operatorId`. Its embedded backend configuration is a separate **version 6**
contract. Server configuration is **version 8**. Do not interchange them.
See the [CLI guide](docs/pki-cli.md), [worked local demos](docs/examples/pki-cli/README.md),
and [deployment instructions](deploy/README.md).

## Support and limits

- Classical and post-quantum cryptography use discoverable parameter sets;
  unsupported variants are rejected. See [BC migration](documentation/reference/bc-migration.md).
- Completed certificate tests cover RSA, EC, ML-DSA-44/65/87 and
  SLH-DSA-SHA2-128F roots. AltSignature supports root creation and lifecycle with
  an unchanged alternative key. Twin denotes independently administered
  classical/PQC hierarchies. Composite and AltSignature intermediate/leaf
  issuance are rejected. See [hybrid certificates](documentation/developer/cryptography.md).
- LMS/XMSS signing requires fresh durable enrollment and a separately preserved
  local state authority. Imported or ordinarily generated stateful keys cannot
  sign through a stateless executor. See [stateful signing](documentation/developer/stateful-signing.md).
- The server and frontend are implemented. Protocol availability depends on
  configured listeners, authority and policy; see [protocols](documentation/admin/protocols.md).
- Credential search, CRL/delta scheduling, operational metrics and generated
  administration forms are implemented with documented bounds. A frontend
  dashboard page is navigation; it is not a graphical aggregate metrics dashboard.
- Local backup uses a consistent file-backed snapshot, integrity manifest,
  bounded verification and staged cold activation with no-regression checks.
  Private keys and external authority/audit/configuration state require separate
  protection. Integrity does not establish archive authenticity. HTTP streaming,
  full frontend backup workflows and remote restore remain unavailable/deferred.
  See [backup and restore](documentation/admin/backup-restore.md).

## Documentation and development

The [documentation home](documentation/index.md) links user, operator and developer
guides. The [architecture](documentation/overview/architecture.md) and
[module reference](documentation/developer/modules.md) describe implemented ownership.
[Future work](docs/project-work-plan.md) lists accepted deferrals separately from
implemented capabilities.

```bash
python3 -m pip install -r documentation/requirements.txt
python3 -m unittest discover -s tools -p 'test_validate_documentation_links.py'
python3 tools/validate_documentation_links.py
python3 -m unittest discover -s tools -p 'test_validate_source_licenses.py'
python3 tools/validate_source_licenses.py
mkdocs build --strict
./gradlew :api-spec:generateOpenApi :pki-server:generateSchema
./gradlew :lib:javadoc :pki:javadoc :pki-server:javadoc :app:javadoc :ext:javadoc :api-spec:javadoc
```

Generated API and operation references are build outputs; edit their Java catalog
authority and regenerate. Public Java APIs use Javadoc with full doclint;
warnings fail generation. Cross-module links use the current build's module
metadata rather than an older published API index.

First-party source headers retain the complete text of `LICENSE-source.txt`,
including the author's name and original copyright year. The source-license
validator checks maintained code, build scripts, HTML/CSS and YAML, including
non-ignored new files. Generated outputs, dependencies and data-only JSON,
properties or TOML files are outside that header check. Original third-party
licenses must never be replaced: reviewed paths, provenance and notice hashes
are recorded in `tools/third_party_source_licenses.json`. A new foreign source
requires a provenance entry, not a ZeroEcho copyright header. The release
workflow runs this validation before building.
