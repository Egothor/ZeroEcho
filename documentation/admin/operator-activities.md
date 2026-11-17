# Operator activity reference

For a complete command sequence, start with
[Set up and administer a PKI](getting-started.md). This page maps administrative
tasks to their interfaces, permissions and resulting objects.

Use this reference to choose an activity, its authority and its safe completion
condition. [The host client and forms](../deployment/pki-operator.md) provide the
same retained workflow without server-store access. Java local commands have a
different trusted-local authority model; see [interface reference](../reference/pki-operator-interfaces.md).

## Common procedure for every activity

1. Authenticate to the exact origin/realm with your own mapped certificate and
   checkpoint. Discover the actual operation and schema. Confirm `action`,
   `resourceType`, scope, availability and `durableRequest`; discovery grants no
   authority. [Permissions](../reference/operation-permissions.md) are separate
   from content access, disclosure, profile eligibility and managed-key custody.
2. In the TUI choose the operation from the type tree or A–Z view, fill the typed
   fields, review the complete request and explicitly confirm. Structured profile,
   grant and list fields use forms; no manual JSON reconstruction is required.
   In automation supply the corresponding typed `arguments` object to `read`,
   `submit` or `action` according to discovery.
3. For mutations retain the local request identity and exact target before send.
   Durable requests retain server request, approval and signing identities.
   An eligible approver reviews that target and records justification. The FIRST
   administrator's explicit own-request permission does not waive thresholds or
   eligibility. An ordinary administrator uses a separate eligible identity.
4. Observe the original request until `SUCCEEDED` with a result. Approval-only,
   `PENDING`, `RUNNING`, an allocated ID or a durable signature are not completion.
   Verify the activity-specific result below and retain artifacts separately.
5. On lost acknowledgement keep the checkpoint and inspect/observe; never invent
   a new ID to replay. Dedicated actions have local once-only identities, not
   server idempotency. Treat an uncertain dedicated action as reconciliation
   work. Do not remove state or alter server files to make a retry possible.

The tables add each activity's purpose, required role, inputs, output checks and
recovery conditions to this common procedure. Their linked task pages describe
individual fields. The live typed schema is authoritative for required values;
do not infer one algorithm or profile from a descriptive certificate-type label.

## Trust, identities and policy

| Activity and purpose | Role, prerequisites and inputs | Procedure, approval and output verification | Safe recovery |
| --- | --- | --- | --- |
| Establish root/intermediate CA | CA operator with `AUTHORITY_CREATE` / `ISSUER_CREATE`; active compatible profile, explicit existing key, `formatId`, `subjectRef`, `profileId`, `keyRef`, selected `signatureAlgorithmId`; intermediate also `issuerCaId`. | `ca.create` / `ca.intermediate.create`, high-risk approval. Resolve returned `credentialId` to its outgoing issuer generation; inspect `caId`, selected issuer/path and immutable binding. Download/verify certificates. [CA tasks](authorities.md). | Observe original accepted work. An intermediate certificate's metadata `authorityId` is its **parent**, not necessarily the new subordinate authority. Resolve the generation by exact credential. |
| Generate a managed signing key | Protected FIRST administrator plus `MANAGED_KEY_GENERATE`; explicit `generationId`, `parameters=ECDSA_P384`, `RSA_4096` or `ML_DSA_87`. | `key.generate`, high-risk approval; retain generation/request identities, returned `keyRef`, public SPKI and algorithm. No private-key export. Compare SPKI to subsequent immutable CA binding. | Preserve generation reservation and receipt. Ordinary grants cannot bypass FIRST. No new generation ID as an uncertain retry. |
| Onboard users and approvers | Access administrator with `PRINCIPAL_MANAGE`; operator-owned login key/CSR; distinct enabled principal and deployment-approved trust. | `security.principal.register` with ID/type/displayName/enabled, then appropriate role/grant workflow. Inspect the registered principal. Deployment adds the actual certificate mapping and performs any restart. [Access](access-control.md). | A principal record alone does not authenticate a certificate. Keep old/new identity and mapping evidence; do not silently restore revoked access. |
| Map login certificate to principal | Deployment configuration owner; trusted operator certificate, exact fingerprint/SPKI or supported mapping commitments and enabled persisted principal. | Update the appropriate direct-mTLS or proxy forwarded-client mapping in configuration; validate and restart under deployment control. Verify a real session has the intended principal and permissions. [Authentication schema](../reference/configuration-reference.md#administrative-authentication). | No catalog certificate-mapping operation is implied. Missing mapping is an unmet deployment prerequisite; clients do not edit it. |
| Assign roles and scoped grants | Access administrator with `ROLE_MANAGE` / `PERMISSION_GRANT`; exact template version, principal, resource/action/relationship/data view and optional conditions/expiry. | `security.role-assignment.create` / `security.grant.create`, high-risk. Inspect assignment/grant and use `security.authorization.evaluate`; test allowed and denied scope separately. [Access](access-control.md). | Read current authority before revoking/replacing. An explicit deny and profile policy can still prevent use. Do not use broad grants to repair an unrelated refusal. |
| Register/activate a profile | Profile operator with `PROFILE_VALIDATE`, `PROFILE_REGISTER`, `PROFILE_ACTIVATE`; complete bounded base64 JSON/DER profile document. | `profile.validate`, then `profile.register`; retain exact version/hash. NONE profiles activate on registration; SINGLE/THRESHOLD require approved `profile.activate`. Inspect the active exact version. [Profiles](profiles-and-issuance.md). | Identical active content reconciles; changed content is a new version. Do not assume an update reboots or overwrites existing profiles. |

## Issuance, inventory and lifecycle

| Activity and purpose | Role, prerequisites and inputs | Procedure, approval and output verification | Safe recovery |
| --- | --- | --- | --- |
| Prepare subject keys and CSR | Applicant owns its private key(s); supported key/provider and approved profile. Ordinary import uses `formatId=x509`, base64 DER `encoded`. | Generate locally; `request.import`, retain returned `requestId`, then `request.verify` and inspect. A hybrid request needs native PoP and fresh SDK proof of **both** subject keys; see [recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios). | Keep applicant keys and original CSR private. A login key is not implicitly an issuance key; a CA key is never transferred to an applicant. |
| Issue a credential | Issuance operator with `CERTIFICATE_ISSUE`; verified request, exact `issuerCaId`, `requestId`, `profileId`, eligible selected generation/path. | `credential.issue`; profile SINGLE/THRESHOLD approval still applies. Observe terminal execution; inspect returned `credentialId`, issuer generation, profile and subject keys. Download certificate and selected chain and verify actual signatures. | Preserve request/approval/signing identity. No classical fallback if alternative proof or required algorithm fails. |
| Inventory authorities, requests, credentials and status | Corresponding read permissions; authority context where required, pagination `limit` and returned cursor. | `ca.list`, `request.list`, `credential.list`, `issuer.generation.list`, `inventory.status`, plus inspect operations. `credential.list` works without H2; advanced `credential.search` needs the optional index. Compare IDs and metadata before using them. | Reads do not grant content access. Continue with returned cursor, not fabricated offsets; retain IDs even without a search index. |
| Download certificate, CA, chain or CRL | Content/download permissions and a new local output path; retained credential/authority/path/status ID. | Host `certificate`, `ca`, `chain`, `crl` use binary routes, not JSON operations. Verify object identity and DER/PEM equivalence; inspect `signatureVerified`. Chain verifies under the selected downloaded anchor. [Downloads](../deployment/pki-operator.md#certificate-current-ca-crl-and-chain-files). | No overwrite, redirect or anonymous fallback. Transport/parse success alone is not cryptographic trust or public disclosure. |
| Renew, replace or reissue | `CERTIFICATE_RENEW`, `CERTIFICATE_REKEY` or `CERTIFICATE_ISSUE`; original credential/profile and, for replacement, new verified request. | `credential.renew(credentialId)`, `credential.replace(existingCredentialId,requestId,profileId)`, `credential.reissue(credentialId)`; profile approval plus high-risk reissue as applicable. Hybrid renew/reissue require fresh operation-bound proof of both unchanged subject keys; replacement proves the requested tuple. Verify new credential and issuer binding. | Accepted work keeps frozen keys/policy; a later CA head change does not retarget it. Inspect result; do not resubmit when pending. |
| Roll over or rotate a CA | CA lifecycle operator, `ISSUER_CREATE` / `ISSUER_ROTATE`; current exact head, compatible existing selected keys/algorithms. | `ca.rollover` or `ca.rotate`, approved high-risk workflow. Rotation explicitly chooses primary/alternative/both roles; omitted roles stay unchanged. Changed-key/algorithm roots publish a candidate, then require separate approved path activation after distribution acknowledgement. [CA lifecycle](authorities.md#certificate-rollover-and-key-rotation). | Capture/compare `expectedHead`; never auto-activate or claim trust-store updates from acknowledgement. Preserve historical generation/path and pending work. |
| Confirm certificate possession | Holder/confirmation operator with the applicable confirmation permissions and retained challenge/revision/commitments. | `credential.confirmation.challenge.issue` then `credential.confirmation.proof.complete`; use exact expected lifecycle/challenge commitments and canonical response. Inspect active/confirmed result. | An expired or changed challenge is not success. Pending confirmation may be explicitly revoked through its supported workflow. |

## Status, publication, protocols and assurance

| Activity and purpose | Role, prerequisites and inputs | Procedure, approval and output verification | Safe recovery |
| --- | --- | --- | --- |
| Hold, release or revoke | Revocation operator with `CERTIFICATE_HOLD`, `CERTIFICATE_RELEASE_HOLD`, `CERTIFICATE_REVOKE`; exact credential, reason and justification. | `credential.hold`, `credential.unhold`, `credential.revoke`; verify `revocation.inspect`/history and subsequent status. Revocation is not a reversible hold. [Status tasks](revocation-and-status.md). | Reconcile the original request. Never attempt to erase revocation history or reuse a test run against production. |
| Generate full/delta CRLs | `CRL_GENERATE`; selected authority/generation and suitable valid full base for delta; `issuerCaId`, `formatId=x509`, `type=CRL` or `DELTA_CRL`. | `status.generate`; retain `statusObjectId`, issuer and base/number/time metadata; download and verify primary/alternative signatures as required. After either signing role's key/algorithm changes, start a new full CRL; qualified same-tuple rollover may reuse a compatible base. | A rejected/invalid latest base is not permission to use an ancient one. Keep generation/lineage and base relation. Native OCSP is not `status.generate` output. |
| Publish and expose objects | Publication operator plus disclosure/alias authority; source ID, configured target and intended audience. | `publication.register`, `publication.process`; inspect actual delivery. `PENDING` registration is not delivered. Set disclosure and `repository.alias.set` only when intended; verify public bytes anonymously and private denial. [Publication](publication.md). | Retry only supported retryable delivery; reconcile `OUTCOME_UNKNOWN` using retained evidence, never blindly duplicate an external effect. |
| Enroll with ACME/EST/SCEP/CMP | Deployment configured listener/enrollment profile and protocol-specific authenticated client credentials. | Follow [protocol guide](protocols.md); inspect actual issued credential, private-key match and chain. Hybrid requires listener/profile opt-in plus native authentication and both SDK proofs. | Native protocol polling/idempotency applies. Do not reconstruct protected initial messages or claim native issuance tests qualify every hybrid carrier live. |
| Provision and activate OCSP responder | Issuer-use and OCSP administration authority; dedicated existing managed primary/alternative keys, exact issuer/profile/path/validity. | `ocsp.responder.issue-certificate` is controlled durable issuance; retain canonical request ID. Registration and approved activation are **separate** operations. Verify native response and, if selected, separate SDK evidence against trusted generation/path. [OCSP](../reference/pki-server-ocsp.md). | Occupied provisioning slot returns canonical result/conflict; a changed date or caller ID cannot mint another certificate. Deliberate same-slot renewal requires exact predecessor. Never clear slots to retry. |
| Inspect audit and disclosure | Distinct `AUDIT_READ_REDACTED`, `AUDIT_READ_FULL`, `AUDIT_READ_PII`, `AUDIT_EXPORT`, `AUDIT_INTEGRITY_VERIFY` as needed. | Use `security.audit-view.*`, `security.audit.search`, `security.audit.verify-integrity`; retain query scope and exact verification result. [Audit](audit-and-disclosure.md). | A redacted view is not full evidence. Keep sensitive exports private; disclose only explicitly authorized fields. |
| Backup, restore and recover | Backup/restore-authorized operator, enabled transfer contract, verified archive and surviving safety authority. | Streaming prepare/download/upload/verify/stage; deployment cold restart; observe original restore until ACTIVATED, then separate acknowledgement. [Backup](backup-restore.md). | No archive bytes in ordinary operation JSON. Preserve receipts and external no-regression authority; no replay or rollback of occupied state. |

## One form and its automation counterpart

All examples use the fictitious **Northstar Example**, `northstar.example` and
private client files. Substitute the actual deployed origin, realm and identity;
no server IDs below are fabricated. In the TUI choose **ca.list**, set integer
`limit=25`, review, and run the read. Launch with:

```sh
./deploy/pki-tui.sh --url https://pki.northstar.example:8443 --realm northstar \
  --trust "$HOME/northstar-client/trust.pem" \
  --p12 "$HOME/northstar-client/administrator.p12" \
  --checkpoint "$HOME/northstar-client/operator-state"
```

The equivalent automation input is an owned mode-0600 `ca-list.json`:

```json
{"operation":"ca.list","arguments":{"limit":25}}
```

```sh
./deploy/pki-operator.sh --url https://pki.northstar.example:8443 --realm northstar \
  --trust "$HOME/northstar-client/trust.pem" \
  --p12 "$HOME/northstar-client/administrator.p12" \
  --checkpoint "$HOME/northstar-client/operator-state" \
  read "$HOME/northstar-client/ca-list.json"
```

Use the returned CA ID as `caId` in `ca.inspect` and the returned issuer/path
identities in later commands. For mutations, the same TUI review shows the exact
`operation`, `authorityId` and nested `arguments` that automation stores in a
version-1 [durable intent](../deployment/pki-operator.md#structured-requests-and-recovery).
Keep the returned request/approval/result IDs instead of substituting example IDs.
The [algorithm recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios)
carry generation, profile, CSR and credential IDs automatically through a complete
new hierarchy and retain each actual receipt.
