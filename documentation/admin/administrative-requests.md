# Durable administrative requests

The web console submits a supported business mutation once. The backend retains
its exact typed target, original authenticated requester, authoritative scope and
execution budget. It creates the required approval automatically. Approval is an
explicit human decision; it never executes the target as the approving person.
After approval a realm-owned worker continues the retained target without a
browser connection or a repeated operation POST.

## API and state

`POST /admin/v1/requests` accepts version 1 with `requestId`, `operation`,
`arguments`, optional `authorityId`, and optional `deadline` (an ISO duration).
The duration is an execution budget starting after approval, not an approval-wait
expiry. HTTP 202 returns the retained state. Repeating the same owner, identity
and exact target returns the same retained request; changing its target returns
409. An uncertain response is resolved by reading the original request identity.

`GET /admin/v1/requests/{requestId}` returns detail. The list endpoint accepts
`offset`, `limit` (1–100), and optional exact `state`, `requester`, and `operation`
filters. Continue with `nextOffset` while `hasMore` is true, including after an
empty filtered page. Lists omit original arguments. Authorized detail can disclose
read-only `target` and final `result`; owners also receive a bounded subject summary.
Approval rows link back through `administrativeRequestId`. Legacy approvals have
only their historical commitment and cannot be converted to executable requests.

States are `WAITING_APPROVAL`, `READY`, `DISPATCHING`, `RUNNING`, `SUCCEEDED`,
`FAILED`, `REJECTED`, `EXPIRED`, and `RECONCILIATION_REQUIRED`. Failed or uncertain
work never becomes an issued certificate row. Its worklist entry retains the safe
machine reason and any exact signing-operation identity.

## Admission and authorization

Required approvals are created only after pure validation of the supported
operation's current input and dependencies. Validation never prepares a signing
candidate, allocates a serial, stages content, signs a challenge or changes
metadata. Execution validates again against current state. Signing requests pin
an active profile version/hash and refuse dispatch if that profile changes.
Format-owned subject metadata supplies field guidance; the configured credential
framework and certificate profile remain authoritative validators.

A retained request is an authenticated intent, not a reusable TLS session. Before
new signing acceptance or synchronous dispatch the server rechecks the original
principal's enabled state, current live grants, authentication mode, trusted proxy,
and original certificate/key mapping. Removing the mapping or disabling the
account prevents new execution. The original transport certificate is not
reauthenticated for expiry or revocation after approval. Already accepted signing
is observed through its exact receipt even if the requester later loses authority.

## Recovery and limits

A signing receipt and linked approval execution claim are committed atomically
before signing acceptance. Recovery observes that same receipt: matched work is
observed, proven nonacceptance can be revalidated and prepared again, and conflict
or unresolvable outcomes remain visible without blind replay. An observation error
retains the receipt and retries only observation. A synchronous mutation left
`DISPATCHING` after a crash is marked `RECONCILIATION_REQUIRED` rather than replayed.

This does not make a signing provider's in-flight private state recoverable.
For example, the local provider can report `LOCAL_RESTART_UNRECOVERABLE` after a
restart during an accepted provider operation. The worklist reports that actual
terminal failure and does not issue a second operation automatically.

The realm retains at most 10,000 request records and admits at most 1,000 unfinished
requests. Full capacity rejects new submission; terminal history is not silently
deleted. Each private request payload is bounded to 512 KiB, HTTP submission to
256 KiB, and execution budget to 120 seconds (also constrained by configured HTTP
limits). One realm worker scans bounded pages; durable state remains authoritative
if a wakeup is lost. Audit projections contain request identities, state and target
commitments, never original arguments or credential hashes.

## Operation coverage

Grant-conditioned automatic approvals follow the existing closed category rules:
revocation, hold, release, and pending-confirmation revocation can require the
configured high-risk policy, and leaf issuance follows its active profile policy.
An arbitrary `APPROVAL_REQUIRED` grant on another `NONE` category is denied before
persistence; it does not create a new policy category.

The table covers every mutating catalog entry. Read operations remain direct,
authorized reads. `durableRequest` in operation metadata is the console's runtime
capability indicator; current authorization and installed provider/service
availability are separate checks. A provider without the required pure validation
capability fails before any approval is created. There is no automatic fallback
to the old approval-then-repeat business flow.

| Operation | Workflow | Validation / dedicated boundary |
|---|---|---|
| `acme.account.deactivate` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `acme.directory.activate` | Durable | Current authority/profile/providers and frozen directory checks |
| `acme.directory.deactivate` | Durable | Current authority/profile/providers and frozen directory checks |
| `acme.directory.register` | Durable | Current authority/profile/providers and frozen directory checks |
| `backup.export` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.restore` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.acknowledge` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.download` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.export` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.reserve` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.restore` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.upload` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `backup.stream.verify` | Dedicated | Explicit backup artifact/stream transport; restore availability remains separately enforced |
| `ca.create` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `ca.intermediate.create` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `ca.intermediate.issue` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `ca.rollover` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `ca.rotate` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `ca.transition` | Durable | Pure current security/control or PKI preconditions before approval |
| `certificate.publication.enroll` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `cmp.endpoint.deregister` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `cmp.endpoint.register` | Durable | Current enrollment-policy binding and runtime credential metadata |
| `credential.confirmation.challenge.issue` | Dedicated | Interactive challenge/proof exchange with credential holder |
| `credential.confirmation.pending.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `credential.confirmation.proof.complete` | Dedicated | Interactive challenge/proof exchange with credential holder |
| `credential.hold` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `credential.issue` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `credential.reissue` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `credential.renew` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `credential.replace` | Durable | Pure signing input/profile/key validation; receipt before acceptance |
| `credential.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `credential.unhold` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `enrollment.profile.activate` | Durable | Policy identity/encoding and active endpoint compatibility |
| `enrollment.profile.register` | Durable | Policy identity/encoding and active endpoint compatibility |
| `enrollment.profile.suspend` | Durable | Policy identity/encoding and active endpoint compatibility |
| `enrollment.profile.update` | Durable | Policy identity/encoding and active endpoint compatibility |
| `enrollment.request.approve` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `enrollment.request.reject` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `est.endpoint.deregister` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `est.endpoint.register` | Durable | Current enrollment-policy binding and runtime credential metadata |
| `issuer.path.register` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `issuer.path.select` | Durable | Pure current security/control or PKI preconditions before approval |
| `ocsp.responder.activate` | Durable | Certificate/algorithm/public-key metadata; signing proof only during approved execution |
| `ocsp.responder.deactivate` | Durable | Certificate/algorithm/public-key metadata; signing proof only during approved execution |
| `ocsp.responder.register` | Durable | Certificate/algorithm/public-key metadata; signing proof only during approved execution |
| `profile.activate` | Durable | Pure current security/control or PKI preconditions before approval |
| `profile.register` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `publication.process` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `publication.reconcile` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `publication.register` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `publication.retry` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `repository.alias.remove` | Durable | Immutable target/disclosure and expected-current alias checks |
| `repository.alias.set` | Durable | Immutable target/disclosure and expected-current alias checks |
| `request.import` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `scep.endpoint.deregister` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `scep.endpoint.register` | Durable | Current enrollment-policy binding and runtime credential metadata |
| `security.approval.approve` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `security.approval.cancel` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `security.approval.reject` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `security.approval.request` | Dedicated | Explicit human approval/decision helper; linked work resumes on the server |
| `security.break-glass.activate` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.break-glass.create` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.break-glass.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `security.disclosure.capability.issue` | Dedicated | One-time secret delivery, not a retained ordinary result |
| `security.disclosure.capability.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `security.disclosure.set` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.grant.create` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.grant.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `security.principal.disable` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.principal.enable` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `security.principal.register` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `security.role-assignment.create` | Durable | Pure current security/control or PKI preconditions before approval |
| `security.role-assignment.revoke` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |
| `status.generate` | Durable | Typed status input; signing receipt before acceptance |
| `status.schedule.set` | Durable | Strict typed input; current domain checks at dispatch; no approval unless policy requires it |

The legacy `/admin/v1/operations/*` endpoints remain available for explicit CLI and
dedicated protocol callers. Their historical approval handoff is not used by the
managed web business forms.

## Upgrade and recovery procedure

Use the [rootless deployment procedure](../deployment/rootless-podman.md) to
build and pin both matching images before starting the updated services. The
operator must retain a coherent backup of the PKI, control log, audit and installer
state. This change adds a closed server-control namespace; after requests have
been persisted, an older server binary is not a safe rollback target.

On restart, inspect the request detail and user-service journals. Expected recovery
is continued observation of an existing receipt, a newly authorized dispatch only
after proven nonacceptance, or an explicit reconciliation/terminal failure state.
Do not delete request/approval records, reset the PKI store, or repeat the original
operation to make an uncertain request disappear. Retain the matching images and
all durable state while investigating a reconciliation-required result. A source
rollback before any new state is admitted remains possible; after admission prefer
a reviewed forward fix or an operator-controlled coherent restore under the
separate disaster-recovery procedure.

The repository `AdministrativeWorkflowFixture` rehearses this forward-recovery
branch against the actual filesystem store, control log, local signing provider
and cryptographic keys: close/reopen after approval, interruption before acceptance,
and lost projection after actual acceptance. It asserts three actual authorities
for three approved intents, with no replay of an uncertain synchronous mutation.
This is JVM integration evidence; it does not establish a native Podman or browser
rehearsal of these exact source changes.
