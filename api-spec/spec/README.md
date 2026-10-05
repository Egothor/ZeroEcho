# ZeroEcho PKI Administrative API — OpenAPI Specification

This directory documents generation; generated OpenAPI 3.1 output lives under
`api-spec/build/openapi/` and is not maintained source.

## Generating the specification

Run the Gradle task from the repository root with the repository Java 25 toolchain:

```bash
./gradlew :api-spec:generateOpenApi
```

The generated file is written to:

```
api-spec/build/openapi/zeroecho-admin-api.yaml
```

## How generation works

1. `OperationDescriptorCatalog` supplies the validated operation authority.
2. Its entries provide argument fields, permissions, transport and availability metadata; the generator does not maintain a parallel operation catalog.
3. Human-authored descriptions are loaded from `api-spec/src/main/resources/openapi-supplement.yaml`.
4. The generator validates that every registered operation has a supplement entry and fails the build if any are missing.
5. An OpenAPI 3.1 YAML document is assembled and written to the output file.

## Editing descriptions

All human-readable text (summaries, descriptions, argument descriptions) lives in
`api-spec/src/main/resources/openapi-supplement.yaml`.

Edit that file and re-run `generateOpenApi` to update the specification. Never edit the
generated YAML directly — it is overwritten on every build.

## Design constraints

- No external runtime dependencies (no Jackson, SnakeYAML, or OpenAPI libraries).
- The generator uses only the JDK standard library and classes from `:pki` and `:pki-server`.
- Type information comes from the validated descriptor catalog.
- The specification uses `mutualTLS` as the sole security scheme; no token-based auth.
- Every operation maps to `POST /operations/{operationId}`; cancellation uses `DELETE /operations/{operationId}/{requestId}`.
