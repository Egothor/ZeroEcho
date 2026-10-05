# PKI failure model

This document defines the consistent, stable, and safe failure semantics used
across the `pki` and `pki-server` modules (issue #16). It is the
authoritative reference for how failures are classified, carried, redacted, and
translated into external protocol outcomes.

## Principles

1. **Failures are typed, not textual.** A failure carries its machine-readable
   classification and code as structural, typed values. Application logic and trust
   boundaries branch on those typed values — never by parsing the human-readable
   exception message.
2. **The message is diagnostic only.** An exception message exists for logs and
   operators. It must never contain secrets (private keys, plaintext, shared
   secrets), and no control flow may depend on its text.
3. **Internal diagnostics are separated from external responses.** Fine-grained
   internal reason codes describe authoritative state for operators and audit; a
   trust boundary exposes only a coarse, protocol-independent classification (and a
   classification-derived stable code) to external clients.

## Core types

| Type | Package | Role |
| --- | --- | --- |
| `PkiFailureClassification` | `zeroecho.pki.api` | Closed, protocol-independent top-level classification (13 constants: validation, authentication, authorization, policy, not-found, conflict, recovery-required, external-outcome-unknown, resource, cancelled, deadline, overloaded, internal). |
| `PkiFailureCode` | `zeroecho.pki.api` | Closed set of stable, externally exposable codes, each bound to exactly one classification. |
| `PkiFailureReason` | `zeroecho.pki.api` | Closed set of typed **internal** machine reason codes. Each reason declares its `classification()` and an `externalSafe()` flag; a non-external-safe reason describes internal state and only its classification may cross a boundary. |
| `PkiFailure` / `PkiFailureException` | `zeroecho.pki.api` | Immutable `(classification, code)` value and the exception that carries it across the diagnostic boundary. |
| `PkiOperationFailure` / `PkiOperationOutcome.Failed` | `zeroecho.pki.application` | Application-layer classification and the typed result (operation, classification, stable `[A-Z0-9_]{3,64}` code) returned from the synchronous operation executor. |

### Structural carriage

`PkiException` carries an optional typed `PkiFailureReason` (`failureReason()`).
`DefaultPkiOperationExecutor.classify` maps the
owner-approved `STORE_DURABILITY_UNCONFIRMED` case to application classification
`RECOVERY_REQUIRED` and stable external code `RECOVERY_REQUIRED`. The internal
reason token, exception message and cause remain internal. Classification does
not retry the failed operation or inspect message text.

Exception-type and internal control-marker classifications remain unchanged.
The enum's declared classification describes its semantic reason family.

Store and domain layers each own their reason families, all carried structurally:

- **Durability** — `STORE_DURABILITY_UNCONFIRMED`.
- **Revocation** — `REVOCATION_*` and `CONFIRMATION_REVOCATION_*` (`FilesystemPkiStore`
  producers; `DefaultRevocationService` sanitises a hostile store failure to a typed
  reason from a closed `EnumSet<PkiFailureReason>` allow-set, never a raw message).
- **Publication** — `PUBLICATION_*` (`DefaultPublicationService`).
- **Authority / issuance lookup** — `ISSUER_CA_NOT_FOUND`, `ISSUER_CA_NOT_ACTIVE`,
  `ISSUER_GENERATION_NOT_FOUND`, `ISSUER_CHAIN_PATH_NOT_FOUND`, `ISSUER_CREDENTIAL_NOT_FOUND`,
  `CREDENTIAL_NOT_FOUND`, `STATUS_TARGET_NOT_FOUND` remain declared reason families.
  Current point-inspection operations use the executor's internal missing-object
  marker to return `NOT_FOUND`; the declared reason families do not imply exhaustive application mapping.
- **Issuance** — profile-validation rejections carry their stable code on the typed
  `ProfileValidationRejection`; the issuance path reads `rejectionCode()` directly.
- **Algorithm identity** — an unresolved identity throws the typed
  `UnknownAlgorithmIdentityException` (a subclass of `IllegalArgumentException`, so the
  standard invalid-argument convention and existing catchers are preserved), caught
  by type rather than by matching the message.

## Trust-boundary translation (`pki-server`)

No `pki-server` boundary serializes an exception message, cause, or stack trace to a
client. Each boundary maps from a typed classification or typed exception to its own
external model:

- **HTTP** — `HttpResponses.status(...)` maps classification → status; the body carries
  only `{classification, code, messageKey, recoveryRequired, reconciliationRequired}`.
- **ACME** — `AcmeHttpHandler.protocolFailure(...)` maps typed throwables → a closed
  problem-type vocabulary with a fixed `detail`.
- **OCSP** — `OcspHttpHandler` maps typed exceptions → OCSP/HTTP status only, no body.
- **PKIX / CRL** — the closed `RevocationReason` enum maps to standard CRL reason codes.
- **CLI** — `PkiServerMain` maps startup/config failures to fixed exit codes.

## Documented, intentional residuals

These are deliberate and reviewed; they are not the internal message-parsing
anti-pattern this model removes.

1. **Type-only structural fallback in `classify()`.** The executor's internal
   markers (`Missing`, `Conflict`, `CapabilityMissing`, `ExternalUnknown`) carry
   control flow without message parsing. Typed `STORE_DURABILITY_UNCONFIRMED`
   maps to `RECOVERY_REQUIRED`; other `PkiException` values retain
   `POLICY_REJECTION`. An `IllegalArgumentException` maps to `VALIDATION_FAILURE`,
   an `IllegalStateException` to `RESOURCE_FAILURE`, and other failures to
   `INTERNAL_FAILURE`. The focused `PkiOperationInspectionTest` cases
   `mapsTypedStoreDurabilityUncertaintyToSafeRecoveryOutcomeWithoutRetry` and
   `preservesPolicyClassificationForMessageTokensAndOtherTypedReasons` verify the
   approved narrow durability translation through the public executor boundary.
2. **Jackson strict-duplicate detection.** `STRICT_DUPLICATE_DETECTION` is a stable,
   documented Jackson behavior whose only signal is the exception message; the library
   exposes no typed duplicate-field exception. Matching that narrow third-party marker
   is a controlled library-integration point, not interpretation of one of our own
   machine-coded messages.
3. **Authorization decision codes in HTTP responses.** A denied gateway outcome places
   the closed `AuthorizationEngine.Code` (e.g. `APPROVAL_REQUIRED`, `GRANT_EXPIRED`,
   `OUTSIDE_REALM`) in the response body for the authenticated caller. This is
   intentional, non-sensitive, actionable authorization feedback — no secret, other
   principal's data, or internal system state is disclosed — and the finer per-operation
   denial codes remain audit-only. Reviewed and retained.
