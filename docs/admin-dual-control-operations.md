# Administrative dual-control (HIGH_RISK) operations

This document records which administrative operations require dual-control
(second-person approval) and why. It exists so the decision can be folded into
the ZeroEcho operations documentation without re-deriving the rationale.

## Mechanism

Dual-control is expressed by classifying an operation's security descriptor as
`ApprovalCategory.HIGH_RISK` in
`zeroecho.pki.server.OperationSecurityDescriptors`. A HIGH_RISK operation cannot
be executed by a single request: a separate approval request is first created,
committed to the exact typed target operation and its resource scope; a
different, authorized principal then decides it; and the later ordinary operation
request supplies the approval ID, which the gateway claims and completes exactly
once. An approval decision never itself executes the target, and execution after
approval re-evaluates all authorization and preconditions rather than trusting
the approval request.

The approval quorum (how many distinct approvers, and which principals may
approve) is **an operational-deployment concern**: the deployment must define at
least two eligible operator principals with the appropriate scoped
`REQUEST_APPROVE` grant for dual-control to be enforceable in practice. The
server enforces that the requester and the approver are distinct authorized
principals; it does not itself provision operators.

## HIGH_RISK operations (owner decision 2026-09-05)

The following administrative operations mint or redirect trust and are therefore
HIGH_RISK dual-control:

| Operation | Name | Why |
|-----------|------|-----|
| Create authority (root) | `ca.create` | Establishes a new trust anchor. |
| Authority lifecycle transition | `ca.transition` | Changes a CA's operational trust state. |
| CA certificate rollover | `ca.rollover` | Issues new CA trust material. |
| CA key rotation | `ca.rotate` | Introduces a new CA signing key. |
| Reissue credential | `credential.reissue` | Re-mints an end-entity credential. |
| Create intermediate CA | `ca.intermediate.create` | Creates a new subordinate CA and its initial CA credential. |
| Issue intermediate certificate | `ca.intermediate.issue` | Certifies (cross-signs / renews) an intermediate CA. |
| **Select issuance path** | `issuer.path.select` | Atomically switches the issuer generation / chain path used for **all future issuance** from a CA. |

### Rationale for `issuer.path.select`

`issuer.path.select` does not mint new key or certificate material — it only
selects among issuer generations and chain paths that are already registered and
already trusted. It was nonetheless classified HIGH_RISK because it redirects
every subsequently issued certificate onto a different signing generation and
chain, which is a trust-affecting change comparable in blast radius to rollover
and rotation. Requiring dual-control makes the change fail safe: no single
operator can silently repoint a production issuing CA. This is the enterprise-grade
default agreed with the owner on 2026-09-05.

## Operations that are intentionally NOT dual-control

- `issuer.path.register` (`RegisterIssuerChainPath`) — adds an alternative chain
  path under an already-trusted parent path. It does not change the active
  issuance path and mints no trust material, so it is a mutating but
  approval-free operation.
- Read/inspection and listing operations for issuer generations and chain paths
  (`issuer.generation.inspect`, `issuer.path.inspect`, `issuer.path.list`) are
  non-mutating and approval-free.

## Publication authority binding

Publication operations bind the declared envelope `authorityId` to the owning
authority. Because `PublicationRecord` carries no authority field,
the gateway resolves the owning authority — from the committed record for
retry/reconcile/inspect/process, and directly from the declared source for
register — and denies any request whose declared authority does not match, or
whose source cannot be resolved. It is independent of the dual-control
classification recorded here.
