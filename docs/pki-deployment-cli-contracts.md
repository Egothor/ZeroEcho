# PKI deployment and CLI contracts

This reference defines the implemented web, remote CLI and standalone local CLI
boundaries. See the [CLI guide](pki-cli.md) and
[deployment guide](../deploy/README.md) for usage.

## Deployment boundary

| Mode | Runtime and authority | Signing completion |
|---|---|---|
| a — Web | Permanent backend, existing authentication/authorization and reactor; frontend uses its API. | POST accepts once with `202 PENDING` and body `operationId`; GET observes the result. |
| b — Remote CLI | Same authenticated backend; CLI opens no local store or signer. | Submit once, bounded GET polling; receipt survives timeout/interruption. |
| c — Local CLI | Trusted root/superadministrator operator, explicit local configuration, exclusive store ownership, local ZeroEcho signer; no HTTP listener or reactor construction/start. | The explicit invocation constitutes local approval; caller-thread execution reaches durable domain completion or an explicit failure retaining its identity. |

Existing synchronous operations retain their completion semantics. No temporary
reactor, implicit local fallback, remote signer in c, or new server control plane
is introduced. Network publishers remain supported. A local session executes
commands sequentially, including session closure; concurrent local signing
calls or closing the session during a call are not a supported mode.

## Public Java boundary

All new application types below belong to `zeroecho.pki.application`. Reuse the
existing referenced API types. Existing reactive `PkiSession.open(...)` overloads
remain available. `PkiSession` exposes:

```java
static PkiSession openLocal(LocalPkiSessionConfiguration configuration,
        PkiSessionRuntimeDependencies dependencies);
static PkiSession openLocal(LocalPkiSessionConfiguration configuration,
        PkiSessionRuntimeDependencies dependencies, Clock clock);
Optional<PkiSigningCommands> signingCommands();
Optional<LocalSigningExecutor> localSigning();
```

The session is the sole resource owner. Returned services borrow its lifetime,
have no separate close/registration/lease handle and become unusable after it
closes. `localSigning()` is absent in reactive sessions and when local signing
is unconfigured. `signingCommands()` is present when signing is configured in
either mode. Existing non-signing services remain available without a signer.

The ten signing commands belong to the shared `PkiSigningOperation` sealed
interface. Server and local callers use the same records, validation and external
operation names; there is no duplicate hierarchy or legacy adapter. HTTP/security decoding
stays in `pki-server`; `app` depends on `pki`, not on `pki-server`.

```java
public interface PkiSigningCommands {
    PreparedSemanticSigningRequest prepare(PkiSigningOperation operation,
            AccessContext access, Optional<IssuanceExecutionEvidence> evidence,
            CancellationSignal cancellation);
    PkiOperationResult completedResult(SemanticSigningOperation operation);
}

public interface LocalSigningExecutor {
    LocalSigningResult execute(PkiSigningOperation operation,
            CancellationSignal cancellation);
    LocalSigningResult complete(PkiId operationId, CancellationSignal cancellation);
    PkiOperationOutcome inspect(PkiId operationId, CancellationSignal cancellation);
}

public sealed interface LocalSigningResult {
    record Completed(PkiOperationResult result, SigningAcceptanceReceipt receipt)
            implements LocalSigningResult {}
    record Failed(PkiOperationOutcome.Failed failure,
            Optional<SigningAcceptanceReceipt> receipt) implements LocalSigningResult {}
}
```

`prepare` shares existing semantic preparation, not HTTP authorization. Admission
remains `SemanticSigningService.accept`; neither call secretly executes the
signer. `completedResult` rejects a non-completed semantic observation. Result
fields retain existing domain metadata used by the server. HTTP envelopes stay
in the server. Inspection uses `SemanticSigningService.find(PkiId)` through the
local executor; there is no second operation registry. The narrow
`inspect` facade exists to apply the existing configured invocation/result audit to this
read, without exposing another audit sink or advancing the selected operation.
A found observation completes the read independently of the observed signing
state; output contains safe state/identity metadata and completed-result metadata
only for an outer `COMPLETED` operation.

`Completed` requires outer `COMPLETED`, not merely a durable signature.
`Failed` uses existing classifications and safe codes. Retain the receipt as
soon as one exists, including uncertain admission; absence must not be reported
as proof that no mutation occurred. An absent operation selected for completion
returns not-found and echoes the requested ID without inventing a receipt.
There is no local signing `Pending` result.

## Configuration

```java
public record LocalPkiSessionConfiguration(
        ProviderConfig store, ProviderConfig audit, String operatorId,
        Optional<LocalSigningConfiguration> signing,
        List<ProviderConfig> publishers,
        List<PkiSessionConfiguration.BindingProviderConfiguration> bindingProviders) {}

public record LocalSigningConfiguration(
        ProviderConfig provider, String signatureAlgorithm, Duration signingTtl,
        Optional<String> unlockEnvironmentVariable, Duration claimLease,
        Duration providerCallTimeout, OptionalLong pureEdDsaMaximumTbsBytes) {}
```

Use defensive immutable copies and existing provider/binding validation. Require
a nonblank local audit `operatorId`, validated by constructing
`new Principal("LOCAL_OPERATOR", operatorId)` and subject to existing audit and
acceptance-envelope bounds. There is no principal existence lookup or registry.
It is a trusted-local declaration, never server-authenticated identity.
Signing accepts only provider `zeroecho-lib`, validated before store
opening or preparation. Optional signing permits inspection/profile/CSR work
without opening a keyring. Secrets remain environment references, never output.

Backend session configuration remains version 6 with its existing topology.
The standalone CLI document is separately identified by `mode: "local"` and
`version: 1`; this is a configuration format, not a new persisted PKI format.
Its exact root keys are `version`, `mode`, `operatorId`, `store`, `audit`,
`signing`, `publishers`, `bindingProviders`. Only `signing` may be omitted;
empty provider lists are explicit. Provider objects retain `provider` and
`properties`; binding provider objects retain the existing configuration fields.
Reject unknown keys, duplicate keys, obsolete CLI v1–v4 documents without the
local discriminator, wrong types and conflicting remote/local options.

Local `signing` keys are `provider`, `signatureAlgorithm`, `signingTtlSeconds`,
`unlockEnvironmentVariable`, `claimLeaseMillis`, `providerCallTimeoutMillis`,
`pureEdDsaMaximumTbsBytes`. Only the environment reference and EdDSA bound are
optional. Durations use exact positive integers with overflow checks;
claim/call durations are at most one day and claim lease strictly exceeds call
timeout, as in `SigningCoordinatorLimits`. The algorithm, TTL, environment-name
and explicit EdDSA bound retain `SigningConfiguration` validation. No default
claim/call durations or fabricated lane topology are introduced.

The omitted EdDSA limit uses the existing heap-buffer calculation for one
executing signer, preserving buffer overhead and array bounds. This does not
make total PKI memory constant. Local JSON contains no pools, routes, queue,
prefetch, idle-poll or reactor-shutdown settings. The backend loader continues
to parse the real version-6 topology; no local CLI command starts that runtime.

## Operation and command matrix

Existing `PkiOperation` records and their `NAME` constants define the complete
non-signing core catalog. Existing `HttpOperationCodec` additionally defines the
remote server catalog. Do not infer local commands from every lower-level API.

| Family / exact signing command | a/b | c |
|---|---|---|
| Existing non-signing core catalog: profile, CSR, CA/certificate/status inspection, revocation, publication/export | Existing HTTP contract and authorization | Existing core executor and configured capabilities |
| `ca.create`, `ca.intermediate.create`, `ca.intermediate.issue` | Async signing | Synchronous semantic signing |
| `ca.rollover`, `ca.rotate` | Async signing | Synchronous semantic signing |
| `credential.issue`, `credential.renew`, `credential.replace`, `credential.reissue` | Async signing plus required approval | Synchronous semantic signing with local root approval by explicit invocation |
| `status.generate` | Async CRL/delta-CRL signing | Synchronous CRL/delta-CRL signing; existing OCSP-target rejection retained |
| Signing inspection | Authorized GET | Semantic lookup without execution |
| Selected interrupted signing completion | Existing backend recovery | Explicit local completion by ID |
| RBAC, grants, server approvals, ACME control and server-only configuration/search endpoints | Existing server catalog | Unsupported before mutation |

**Owner clarification (2026-09-28):** in mode c the operator acts as a trusted
root/superadministrator. Explicitly requesting an operation constitutes its
local administrative approval, including issuance/lifecycle commands whose
effective profile declares `SINGLE` or `THRESHOLD`. No additional approvers or
confirmation flag are required. This defines an explicit local override of
the approval gate described by
`IssuanceApprovalRequirement`; it does not represent collected independent
approvals or satisfaction of the server's M-of-N process. The stored profile
and its approval requirement are not rewritten.

All other profile, issuer, key, CSR/proof, validity, signature, publication and
durability validations remain required. Approval is not a guarantee of successful
execution. Modes a/b retain their existing server authorization and approval
enforcement; neither a client-supplied principal label nor absent evidence can
select local approval there. No local approval authority, server evidence,
OS-root UID check or new authentication subsystem is introduced. Root authority
is the trusted local operating contract, not a claim derived from `operatorId`.

`publication.register` completes registration, so its domain result may contain
publication state `PENDING`. This is not unfinished signing success. Explicit
publication process/retry/reconcile retain their existing synchronous outcomes;
the local CLI never starts background delivery. No new raw-signing or generic
OCSP/export family is implied by these execution modes.

The CLI supports local single commands and version-1 sequential plans with
result references. Signing uses the shared commands and their field validation.
These control commands select an operation through `--operation-id`:

```text
zeroecho pki --config local.json signing.operation.inspect --operation-id ID
zeroecho pki --config local.json signing.operation.complete --operation-id ID
zeroecho pki --url URL [existing mTLS options] signing.operation.inspect --operation-id ID
```

Remote inspection performs the existing signing-operation GET; it is not a new
POST operation or HTTP endpoint. Remote `signing.operation.complete` is invalid.
Local inspection completes the read command successfully even when its domain
observation is nonterminal; it never claims the signing operation succeeded.
Control commands accept only `operationId` as their operation argument, including
in local plans. `--pending-wait` belongs to remote submission only, defaults to
three seconds, and is rejected in local mode. Preserve existing mTLS options,
remote typed `--arg` forms and `--output human|json`.

Use `--arg-json name=<JSON>` for
structured remote arguments, retaining scalar `--arg`, `--arg-int` and
`--arg-bool`. Reuse the strict closed operation-value model, reject duplicate
arguments across forms, and apply the server request framing limits without
relaxing local configuration/plan parsing. Bound the complete encoded request as
well as each JSON argument. This adds no operation or HTTP endpoint.

## Identity, recovery and durable boundaries

New local signing uses `AccessContext` with
`Principal("LOCAL_OPERATOR", operatorId)`, `Purpose(operation.name())` and empty
optional contexts. Server-specific `IssuanceExecutionEvidence` is absent.
Use the configured existing audit sink and generic audit events for local
invocation/result attribution, including non-signing calls. The retained local
actor and command identify approval by local root invocation, not an authenticated
server approval or a set of independent approvers. Preserve existing
audit failure behavior; no new audit-before-mutation transaction is introduced.

Explicit completion preserves the original accepted access context, command,
provider binding, profile and evidence. Attribute the invocation separately to
the currently configured operator; a configuration identity change must neither
rewrite acceptance nor create a new identity-equality authorization rule.

Only the selected ID advances. Preserve
`INTENT → fenced DISPATCHED → local sign → durable result → verified publication → outer completion`.

| Selected persisted state | Local completion behavior |
|---|---|
| Eligible INTENT | Execute its first eligible stage. |
| Retained proof / certificate-ready stage | Continue existing proof verification and subsequent stages. |
| Recovered DISPATCHED without durable signature | Reconcile to existing `LOCAL_RESTART_UNRECOVERABLE`; never re-sign. |
| Durable signature, unfinished outer publication | Verify/publish without signing again. |
| COMPLETED | Return the existing completed result. |
| Terminal failure, cancellation or expiry | Return its terminal failure; never revive. |
| Live lease or future retry | Immediate recovery/not-ready failure; no sleep, forced claim or retry loop. |
| Unknown durability/admission | Recovery-required result retaining any available receipt. |

Ordinary open/read retains existing WAL/content/evidence repair, publication
uncertainty marking and deadline expiry. These can write state. They must not
automatically dispatch/sign, advance proof/domain publication or retry publisher
delivery for an earlier operation. Store exclusivity remains unchanged.

## Output, interruption and exit codes

Retain JSON version 1 and existing local `single`/`batch` envelope with `steps`,
and remote `mode: "remote"` envelope. Local step status/result/failure fields
remain as in `PkiOutputRenderer`; add optional `operationId` to a signing step
whenever known, including failure. Inspection puts the observed domain state in
its `output`; it is distinct from the read step's success. Batch dependencies
consume only successful completed command results; existing failure policies and
numeric exit aggregation remain unchanged.

Remote statuses remain `SUCCEEDED`, `PENDING`, `APPROVAL_REQUIRED`, `FAILED`.
Keep `result`, `operationCommitment`, `failure`, `code`, `recoveryRequired` and
`reconciliationRequired` in their existing contexts. Signing success includes
the validated body `operationId`; pending and post-acceptance failures retain it.
HTTP errors, malformed responses and transport errors are not synthesized as
successful terminal results. Do not infer receipt identity from Location alone.

Remote wait expiry returns `PENDING`, ID and exit 7. Interrupted polling retains
`PENDING` and ID but exits 130. A polling transport/protocol error returns
`PENDING`, ID and a safe `observationFailure` classification/code object; use
exit 8 for transport/resource failure and 9 for invalid protocol. These describe
the observer, not a terminal failure of the backend operation. Explicit remote
inspection uses the same observation envelope and pending exit 7. A submission
with unknown acceptance has no invented ID and reports uncertainty (exit 7).
Neither interruption nor timeout cancels, resubmits or falls back to local mode.

| Exit | Meaning |
|---|---|
| 0 | Completed command / successful local inspection |
| 2 | Invalid invocation or unsupported mode/command combination |
| 3 | Invalid/unavailable configuration |
| 4 | Validation/policy/authorization denial or remote approval required |
| 5 | Not found or conflict |
| 6 | Recovery required |
| 7 | Remote pending, external outcome unknown or existing deadline-exceeded mapping; distinguish via status/classification |
| 8 | Resource failure or overload |
| 9 | Internal failure or invalid remote protocol |
| 130 | Caller cancellation/interruption |

Do not convert a definite local recovery failure into remote-style pending.
Human output conveys the same identity/state/classification distinctions as JSON.
Print no secrets, raw payloads or exception details. Emit one complete JSON
document and newline on stdout; keep diagnostics separate from machine output.

## Execution and resource boundaries

The execution helper owns no queue, scheduler or operation registry. Local
orchestration has constant metadata and work per stage; domain preparation,
cryptography, streaming and store recovery keep their existing costs. Remote
polling uses O(p) requests and O(1) retained observer state. No new throughput or
total-memory guarantee is made.

Source anchors: `PkiSession`, `PkiSessionConfiguration`, `PkiSigningOperation`,
`PkiSigningCommands`, `DefaultPkiSigningCommands`, `SigningStepExecutor`,
`ServerSigningExecutor`, `PkiOperation`, `HttpOperationCodec`,
`SigningAcceptanceReceipt`, `SemanticSigningService`, `SigningReactor.process`,
`SigningOuterTerminalDriver`, `ZeroEchoLibSigningProvider`,
`IssuanceApprovalRequirement`, `EndEntitySigningPreparation`,
`IssuanceExecutionEvidence`, `FilesystemPkiStore.getSignWorkflow`,
`PkiOutputRenderer`, `PkiRemoteReporter`, `PkiExitCodes`, `PkiRemoteExitCodes`.


## Deployment-only profile bootstrap

The owner approved an internal distribution launcher,
`zeroecho-pki-profile-bootstrap`, for container startup. It does not extend the
public `pki` command catalog or backend API. Its explicit mounted local-v1
configuration supplies the trusted local operator, filesystem store and audit
provider; signing and publishers are absent. The helper parses bounded profile
documents with the existing codec, skips any known identity and registers then
activates the actual imported version of an absent identity. Its local session
closes before server startup. An existing inactive identity remains inactive;
partial failure requires operator inspection and explicit remediation. The
entrypoint fails closed on validation/bootstrap failure. See the
[deployment guide](../deploy/README.md) for launcher arguments and configuration.
