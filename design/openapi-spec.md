# OpenAPI 3.1 Specification — Design Specification

## 1. Goals and Scope

ZeroEcho's administrative HTTP API consists of a single uniform endpoint
(`POST /admin/v1/operations/{operationId}`) that dispatches to one of approximately
99 operations. The operation registry is fully described at build time by the closed
set of types in `OperationSecurityDescriptors`, `PkiOperation`, `PkiSigningOperation`,
and `ServerControlOperation`. There is no runtime discovery required.

This specification describes how to auto-generate a standards-conformant OpenAPI 3.1
document from that source of truth, how to package the generator in the Gradle build,
how to produce optional Python and TypeScript client SDKs from the generated document,
and how to keep generated artifacts from drifting out of sync with the code.

The scope of the generated specification is the administrative HTTPS API only. The
ACME protocol, the public repository transport, and the OCSP responder are distinct
protocols with their own conventions and are explicitly out of scope.

---

## 2. Generation Strategy

### 2.1 Approach

The generator is a standalone Java program that runs at build time, reads the
closed operation registry by direct class loading (not reflection), and writes a
syntactically valid YAML document. No annotation processor is used.

**Why not an annotation processor?** Annotation processors run during `javac` and
cannot safely traverse sealed-interface hierarchies at compile time, because the
permitted subtypes may not yet be compiled when the processor fires. The operation
hierarchy (`PkiOperation`, `PkiSigningOperation`, `ServerControlOperation`) is
already a rich closed structure; making the processor understand it would require
duplicating the entire type hierarchy in processor code. A separate build-time Java
program that runs *after* compilation, in a `JavaExec` Gradle task, is far simpler
and more maintainable.

**Why not Jackson or SnakeYAML?** The dependency policy is strict: no new runtime
dependencies for the generator itself. The generated YAML is a flat document with
a simple nested structure; a small purpose-built `YamlBuilder` (about 150 lines)
using `StringBuilder` produces correct output without any external library. If
at a later date the YAML structure grows complex enough to warrant a library, the
minimal choice is SnakeYAML 2 (already indirectly available in the Gradle build
classpath through other plugins). Jackson is explicitly ruled out — it brings a
large transitive graph and is not already in the Gradle classpath.

### 2.2 Information Sources

The generator reads three sources:

1. **`OperationSecurityDescriptors`** — the closed registry of all operations with
   their family, required action, resource type, approval category, and mutating flag.
   This is the authoritative set of exposed operations.

2. **`PkiOperation`, `PkiSigningOperation`, `ServerControlOperation`** — the sealed
   interfaces and their permitted record subtypes. From these the generator extracts
   the stable `NAME` constant (the `operationId`), and reads the record component
   names and their declared types to produce request-body argument schemas.

3. **A hand-maintained `openapi-supplement.yaml`** file that holds the parts of the
   specification that cannot be derived from the code: human-readable summaries for
   each operation, descriptions for each argument field, the response `result` shape
   for each operation, and the server URL template. This file is the only manually
   maintained artifact; its completeness is verified by the generator at build time
   (any operation or field without a supplement entry causes a build failure with a
   clear error message listing the missing keys).

This split ensures that the structural skeleton — path items, security requirements,
HTTP method, envelope schemas, required vs. optional fields — is always derived from
code and never manually maintained, while human-readable prose stays in a separate
supplement file that is easy for a human editor to manage.

### 2.3 Domain Tag Derivation

The generator derives a tag for each operation from the operation's `operationId`
by taking the portion before the first `.` and mapping it to a display name. The
mapping is encoded in the generator itself:

| Prefix | Tag |
| --- | --- |
| `ca` | Authorities |
| `credential` | Credentials |
| `issuer` | Issuers |
| `profile` | Profiles |
| `request` | Requests |
| `revocation` | Revocation |
| `status` | Status Objects |
| `publication` | Publication |
| `algorithm` | Algorithm Bindings |
| `configuration` | Configuration |
| `inventory` | Inventory |
| `principal` | Principals |
| `role` | Roles |
| `grant` | Grants |
| `approval` | Approvals |
| `break-glass` | Break Glass |
| `audit` | Audit |
| `capability` | Capabilities |
| `repository` | Repository Aliases |
| `acme` | ACME |
| `ocsp` | OCSP |
| `server` | Server |

---

## 3. OpenAPI Document Structure

### 3.1 Info Block

```yaml
openapi: "3.1.0"
info:
  title: ZeroEcho PKI Administrative API
  version: "${project.version}"
  description: >
    Mutual-TLS administrative API for ZeroEcho PKI. All endpoints require
    a client certificate. Every operation is addressed as POST /admin/v1/operations/{operationId}.
  license:
    name: BSD 4-Clause
    identifier: BSD-4-Clause
```

The version string is substituted from the Gradle project version at generation time.

### 3.2 Servers Block

```yaml
servers:
  - url: "https://{host}:{port}/admin/v1"
    description: "ZeroEcho PKI administrative listener"
    variables:
      host:
        default: "localhost"
        description: "Server hostname or IP"
      port:
        default: "8443"
        description: "Administrative HTTPS port"
```

Operators supply the actual host and port. The path prefix `/admin/v1` is fixed.

### 3.3 Security Schemes

```yaml
components:
  securitySchemes:
    mutualTLS:
      type: mutualTLS
      description: >
        Every request must present a valid client certificate issued by the
        server's configured client trust anchors. There are no sessions, tokens,
        or cookies — each request is authenticated independently.
```

All paths inherit this scheme via a top-level `security` block:

```yaml
security:
  - mutualTLS: []
```

### 3.4 Common Schemas

The following schemas are defined once under `components/schemas` and referenced
by `$ref` in all path items:

**`OperationRequest`** — the request envelope:

```yaml
OperationRequest:
  type: object
  required: [version, arguments]
  additionalProperties: false
  properties:
    version:
      type: integer
      enum: [1]
    authorityId:
      type: string
      description: "Required for authority-scoped operations; must be omitted for realm-wide operations."
    approvalId:
      type: string
      description: "Supplied when re-submitting an operation that requires dual control."
    deadline:
      type: string
      format: duration
      description: "ISO-8601 duration bounding server-side execution (e.g. PT30S)."
    arguments:
      type: object
      description: "Operation-specific arguments; schema depends on operationId."
```

**`OperationResponse`** — the response envelope:

```yaml
OperationResponse:
  type: object
  required: [version, requestId, operation, status]
  properties:
    version:
      type: integer
      enum: [1]
    requestId:
      type: string
    operation:
      type: string
    status:
      type: string
      enum: [SUCCEEDED, PENDING, FAILED, APPROVAL_REQUIRED]
    result:
      type: object
      nullable: true
      description: "Operation-specific result object; null on FAILED."
    failure:
      nullable: true
      $ref: '#/components/schemas/OperationFailure'
```

**`OperationFailure`** — failure detail:

```yaml
OperationFailure:
  type: object
  required: [code, message]
  properties:
    code:
      type: string
      description: "Machine-readable failure code."
    message:
      type: string
      description: "Human-readable failure description."
    details:
      type: object
      additionalProperties:
        type: string
```

**`ApprovalCommitment`** — returned when status is `APPROVAL_REQUIRED`:

```yaml
ApprovalCommitment:
  type: object
  required: [operationCommitment, approvalTarget]
  properties:
    operationCommitment:
      type: string
      description: "Stable SHA-256 commitment identifying this operation instance."
    approvalTarget:
      type: string
      description: "The operationId that the approval workflow is attached to."
```

### 3.5 Path Items

The API exposes three path templates. Each maps to multiple operations via
`operationId` path parameters.

#### Discovery endpoint

```
GET /operations
```

Returns the list of operation identifiers available to the authenticated principal.

#### Operation execution endpoint

```
POST /operations/{operationId}
```

This is the primary endpoint. The generator emits one entry per operation under
a dedicated `x-operation-family` extension field, grouped by tag. Each entry
references the `OperationRequest` schema for the request body and the
`OperationResponse` schema for the response body. Per-operation argument schemas
are referenced inline via `$ref` to named schema entries in `components/schemas`.

#### Operation cancellation endpoint

```
DELETE /operations/{operationId}/{requestId}
```

Cancels an in-flight operation by its correlation identity.

### 3.6 Per-Operation Schema Derivation

For each record subtype of `PkiOperation`, `PkiSigningOperation`, and
`ServerControlOperation`, the generator produces a named schema under
`components/schemas` with a name derived from the operation's `NAME` constant:
dots are replaced with hyphens and the result is title-cased (e.g.
`credential.issue` → `CredentialIssueArguments`).

Each record component becomes a property in the schema. Type mapping:

| Java type | JSON Schema type |
| --- | --- |
| `String` | `string` |
| `int`, `long` | `integer` |
| `boolean` | `boolean` |
| `Optional<String>` | `string` (not in `required`) |
| `Optional<T>` | `$ref` to T's schema (not in `required`) |
| `byte[]` | `string`, `format: byte` (base64) |
| `PkiId` | `string` |
| `FormatId` | `string` |
| `Instant` | `string`, `format: date-time` |
| `RevocationReason` | `string`, `enum: [...]` (derived from enum constants) |
| `CaState` | `string`, `enum: [...]` |
| `PublicationSourceType` | `string`, `enum: [...]` |
| `EncodedObject` | `object` with `bytes: string (format: byte)` and `formatId: string` |

Components within `Optional<T>` are not listed in the `required` array; all other
components are required. The description for each property comes from the
supplement file.

### 3.7 Approval-Required Responses

Operations with `approvalCategory != NONE` in `OperationSecurityDescriptors` emit
an additional documented response:

```yaml
'409':
  description: "Dual-control approval required before the operation can proceed."
  content:
    application/json:
      schema:
        allOf:
          - $ref: '#/components/schemas/OperationResponse'
          - properties:
              status:
                enum: [APPROVAL_REQUIRED]
              result:
                $ref: '#/components/schemas/ApprovalCommitment'
```

`SelectIssuancePath` and `TransitionAuthority` are examples that carry
`HIGH_RISK` approval; the generator detects this from the descriptor and adds
the 409 response automatically.

### 3.8 Standard Error Responses

All operations declare the following standard HTTP error responses, defined once
in `components/responses` and referenced by `$ref`:

| Status | Code constant | Description |
| --- | --- | --- |
| 400 | `INVALID_OPERATION_REQUEST` | Malformed body or unknown fields |
| 401 | `AUTHENTICATION_REQUIRED` | No valid client certificate |
| 403 | `PERMISSION_DENIED` | Authenticated but not authorized |
| 404 | `OBJECT_NOT_FOUND` | Referenced object does not exist |
| 409 | `APPROVAL_REQUIRED` or `CONFLICT` | Dual control required, or concurrent modification |
| 413 | `REQUEST_TOO_LARGE` | Body exceeds configured maximum |
| 415 | `UNSUPPORTED_CONTENT_TYPE` | Wrong or missing `Content-Type` |
| 500 | `INTERNAL_ERROR` | Server-side error |

---

## 4. Module Placement and Build Integration

### 4.1 Gradle Subproject: `api-spec`

A new Gradle subproject `api-spec` is added at the top level. It does not declare
a `module-info.java` because it is a build-time tool, not a deployable module.
Its `build.gradle.kts` configures:

- A dependency on the compiled `pki` and `pki-server` modules on the classpath
  (using `compileClasspath` from those projects, not their published artifacts).
- A `generateOpenApi` task of type `JavaExec` that runs
  `zeroecho.apispec.OpenApiGenerator` from the `api-spec` source set.
- The task's output is `build/openapi/zeroecho-admin-api.yaml`.
- The task's inputs are declared as the source files of `pki` and `pki-server`,
  so Gradle's incremental build only re-runs generation when those sources change.

```kotlin
// api-spec/build.gradle.kts (sketch)
tasks.register<JavaExec>("generateOpenApi") {
    dependsOn(":pki:classes", ":pki-server:classes")
    classpath = sourceSets.main.get().runtimeClasspath +
                project(":pki").sourceSets.main.get().output +
                project(":pki-server").sourceSets.main.get().output
    mainClass.set("zeroecho.apispec.OpenApiGenerator")
    args = listOf(
        "${rootProject.version}",
        "${projectDir}/src/main/resources/openapi-supplement.yaml",
        "${buildDir}/openapi/zeroecho-admin-api.yaml"
    )
    inputs.files(project(":pki").sourceSets.main.get().allSource)
    inputs.files(project(":pki-server").sourceSets.main.get().allSource)
    outputs.file("${buildDir}/openapi/zeroecho-admin-api.yaml")
}
```

The `settings.gradle.kts` gains `include("api-spec")`.

### 4.2 The Generator Program

The generator lives in `api-spec/src/main/java/zeroecho/apispec/OpenApiGenerator.java`.
It follows this sequence:

1. Load and instantiate `OperationSecurityDescriptors`. Extract `descriptors()` map.
2. Load and iterate all permitted subtypes of `PkiOperation`, `PkiSigningOperation`,
   and `ServerControlOperation` using `Class.permittedSubclasses()` (available since
   Java 17; JDK 25 is the project's runtime).
3. Parse `openapi-supplement.yaml` using a minimal hand-written YAML parser
   (only the subset used by the supplement file is needed: nested maps and strings).
4. For each operation subtype: derive the schema name, enumerate record components
   via `RecordComponent[]` from `Class.getRecordComponents()`, produce argument
   schema, and emit the path item.
5. Validate that every operation and field has a supplement entry; fail the build
   with a descriptive error if any are missing.
6. Write the YAML document to the output file.

The generator is a single-class program with no dependencies beyond the JDK and
the compiled `pki`/`pki-server` output. Estimated size: ~600 lines.

### 4.3 CI Integration

The `check` task in the root project gains a dependency on `:api-spec:generateOpenApi`.
The generated YAML is published as a build artifact alongside the JAR files. In CI,
a dedicated step runs the generator and then compares the output against the
previously committed `api-spec/build/openapi/zeroecho-admin-api.yaml` using `diff`;
a non-empty diff fails the build with the message "OpenAPI spec is out of date —
run ./gradlew :api-spec:generateOpenApi and commit the result."

---

## 5. SDK Generation

### 5.1 Python SDK

The recommended generator is `python-pydantic-v2` from the
[openapi-generator](https://openapi-generator.tech) project. It produces typed
Pydantic v2 models and a thin `httpx`-based client. The generated client is
suitable for integration scripts, automation tooling, and operator dashboards.

A Gradle task `generatePythonSdk` runs `openapi-generator-cli` (fetched as a
Gradle dependency from Maven Central — the single additional build dependency this
process introduces):

```kotlin
tasks.register<JavaExec>("generatePythonSdk") {
    dependsOn("generateOpenApi")
    classpath = configurations["openapiGeneratorCli"]
    mainClass.set("org.openapitools.codegen.OpenAPIGenerator")
    args = listOf(
        "generate",
        "-i", "${buildDir}/openapi/zeroecho-admin-api.yaml",
        "-g", "python-pydantic-v2",
        "-o", "${buildDir}/sdk/python",
        "--package-name", "zeroecho_pki",
        "--additional-properties", "generateSourceCodeOnly=false"
    )
}
```

### 5.2 TypeScript SDK

The recommended generator is `typescript-fetch`. It produces a native `fetch`-based
client with full TypeScript types. The task is analogous to the Python one, with
`-g typescript-fetch` and output to `${buildDir}/sdk/typescript`.

### 5.3 SDK Distribution

Generated SDKs are placed under `build/sdk/` and are not committed to the main
repository. They are published as release artifacts (zip archives) alongside the
server JAR. If external SDK maintenance becomes a significant effort, a separate
repository per language SDK is the appropriate next step; for now, build-time
generation on release is sufficient.

---

## 6. Drift Detection and Versioning

### 6.1 Drift Detection

Two mechanisms prevent silent drift:

**Build-time validation** — the generator validates that every operation from
`OperationSecurityDescriptors` has a supplement entry and that every record
component of every operation type has a description. Any gap is a build failure.
This means adding a new operation without updating the supplement file breaks
the build immediately.

**CI diff check** — the generated YAML is committed to `api-spec/spec/` under
version control. CI regenerates the file and diffs it against the committed version.
Any change to a PKI operation type, a record component, or the descriptor set
is reflected in the generated YAML and the diff check will catch it. The
`spec/` directory contains only the YAML file; the generator itself and the
supplement are in `src/`.

### 6.2 Versioning

The spec's `info.version` field matches the Gradle `project.version`. The version
follows the same semver scheme as the server itself. Major version increments in the
Gradle project version trigger a new API prefix (e.g. `/admin/v2/`) only when the
envelope format changes in a breaking way; the operation set and argument schemas
can grow without a version bump.

---

## 7. Security Considerations

The generated specification must not expose operational risk. Two rules apply:

**mTLS must be prominently documented.** The top-level `security` block ensures
OpenAPI tooling and SDK generators know the scheme is `mutualTLS`. Every generated
SDK's README must include a prominent note that the endpoint requires a client
certificate and that no fallback authentication mechanism exists.

**Internal class names must not appear in schema `$ref` paths.** Schema names are
derived from the stable `operationId` constants (e.g. `CredentialIssueArguments`),
not from Java class names. This prevents leaking internal package structure and
ensures that refactoring Java class names does not change the public schema names.

Additionally, the supplement file must not include examples containing real
credentials, private keys, or production identifiers. The generator validates that
example values, if present in the supplement, are explicitly marked with
`x-example-synthetic: true`.

---

## 8. Implementation Plan

| Step | Description | Complexity |
| --- | --- | --- |
| 1 | Create `api-spec` Gradle subproject with empty `build.gradle.kts` and include in `settings.gradle.kts` | S |
| 2 | Write `YamlBuilder` — a ~150-line `StringBuilder`-based YAML emitter handling indented maps, sequences, and quoted strings | S |
| 3 | Write the supplement file skeleton: enumerate all operation IDs (from a temporary run of `OperationSecurityDescriptors`) and produce a YAML file with `TODO` descriptions for each operation and argument | M |
| 4 | Implement `OpenApiGenerator`: load descriptors, iterate permitted subtypes, map Java record components to JSON Schema types, call `YamlBuilder`, validate supplement completeness, write output | M |
| 5 | Wire `generateOpenApi` `JavaExec` task with correct classpath, inputs, and outputs; verify incremental build works | S |
| 6 | Fill in supplement descriptions for all 99 operations and their arguments (operator task — not automated) | L |
| 7 | Commit the generated YAML to `api-spec/spec/` and add the CI diff check to the build pipeline | S |
| 8 | Add `generatePythonSdk` and `generateTypeScriptSdk` tasks using `openapi-generator-cli`; verify generated clients compile against a local server stub | M |
| 9 | Document the SDK generation workflow in `documentation/developer/openapi.md` | S |

Steps 1–5 and 7 constitute the structural skeleton and can be delivered together.
Step 6 (supplement authoring) is the primary ongoing effort and can be done
incrementally — the build will list missing entries on each run until all are filled.
Steps 8–9 are independent and can be deferred to a later release.
