# ZeroEcho PKI Server Architecture and Authorization Model

**Status:** Normative architecture decision  
**Version:** 1.0  
**Target location:** `docs/pki-server-architecture.md`  
**Applies to:** `pki`, planned `pki-server`, future ACME and public repository interfaces  
**Change authority:** Project owner approval is required for any semantic change to this document.

## 1. Purpose

This document defines the mandatory architecture, authority boundaries, authorization model, disclosure model, approval model, and ACME integration principles for the ZeroEcho PKI server.

The implementation MUST remain consistent with this document. Codex, contributors, future agents, and maintainers MUST NOT silently reinterpret or weaken these decisions.

A change to this document is an explicit architecture decision. It MUST NOT be introduced as an incidental implementation detail, compatibility workaround, optimization, or refactoring.

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

Where this document conflicts with an implementation convenience, the document prevails unless the project owner explicitly approves a revision.

## 3. Core architectural decision

### 3.1 Multi-CA server process

One ZeroEcho PKI server process MUST be capable of serving multiple certificate authorities.

A deployment MAY still configure a server process to expose only one authority.

The server process MUST NOT assume that one process equals one CA.

### 3.2 PKI realm

A server process serves one **PKI realm**.

A realm is one shared operational and security domain containing one or more logical authorities.

A realm MAY share:

- authentication configuration;
- authorization policy;
- audit infrastructure;
- configured cryptographic providers;
- configured publisher providers;
- a logical PKI store;
- process lifecycle and health state.

Every logical authority inside the realm MUST retain separate:

- `authorityId`;
- issuer generations;
- `KeyRef` and signing authority;
- profiles and issuance policy;
- revocation state;
- CRLs and other status objects;
- publication policy;
- disclosure policy;
- authorization scope;
- readiness and lifecycle state;
- audit scope.

### 3.3 Isolation boundaries

Unrelated trust domains, organizations, regulatory domains, classification levels, or HSM security domains SHOULD use separate realms and normally separate server processes.

A single process is a shared compromise boundary. Deployments MUST NOT assume that logical multi-CA separation is equivalent to process or HSM isolation.

### 3.4 Root CA deployment

Offline or high-assurance root CAs SHOULD run outside the continuously online issuing server.

Recommended topology:

```text
offline or high-assurance root realm
        |
        +-- signs intermediate CA certificates
                |
                +-- online issuing realm
                        |
                        +-- issues leaf certificates
```

A root CA MAY be served online only through an explicit deployment decision and corresponding security policy.

## 4. Authority and issuer model

### 4.1 Logical authority

A **logical authority** is the long-lived administrative and policy identity of a CA service.

It survives issuer rotation.

### 4.2 Issuer generation

An **issuer generation** is one concrete CA certificate, signing key reference, validity period, and lifecycle state.

Example:

```text
authority: internal-tls
    issuer: 2024-retiring
    issuer: 2026-active
```

### 4.3 Identity model

The server MUST distinguish at least:

- `realmId`;
- `authorityId`;
- `issuerId`;
- `credentialId`;
- `requestId`;
- `statusObjectId`;
- `publicationId`.

These identities MUST use canonical ZeroEcho identities such as `PkiId`.

No magic numeric identifier is permitted.

In particular:

- certificate ID `1` MUST NOT implicitly mean a CA certificate;
- an authority certificate MUST be retrieved through an authority/issuer-specific operation;
- a random object ID MUST NOT be treated as an access token.

## 5. Server and module boundaries

### 5.1 `pki`

The `pki` module remains the reusable backend authority.

It owns:

- PKI domain services;
- certificate profiles and policy;
- authority and issuer lifecycle;
- issuance;
- revocation;
- status objects;
- publication state;
- snapshots and restore;
- X.509 algorithm bindings;
- durable persistence and recovery;
- transport-neutral typed PKI operations;
- lifecycle-owned `PkiSession`.

It MUST NOT depend on HTTP, CLI parsing, terminal output, process exit codes, or server authentication types.

### 5.2 `pki-server`

The planned `pki-server` module owns:

- HTTP or other network transport;
- server configuration;
- authentication;
- authorization;
- request admission;
- bounded execution;
- request cancellation and deadlines;
- API versioning;
- server lifecycle;
- transport-safe auditing;
- health and readiness endpoints.

It MUST reuse `PkiSession` and transport-neutral typed operations from `pki`.

It MUST NOT duplicate PKI business rules.

### 5.3 `app`

The `app` module owns the CLI and batch-plan adapter.

The CLI and server MUST use the same backend session and typed operation contracts.

## 6. Authority invariants

The server MUST preserve the existing ZeroEcho authority model.

### 6.1 Immutable PKI authority

No API permission may permit direct mutation of:

- issued certificate bytes;
- certificate identity;
- signed certificate fields;
- committed revocation history;
- committed status objects;
- committed audit events;
- committed signing records.

Corrections MUST occur through explicit domain operations such as:

- revocation;
- replacement issuance;
- issuer rotation;
- new status-object generation;
- superseding policy or profile activation.

### 6.2 No database-forgery permission

There MUST NOT be an owner, administrator, or break-glass permission equivalent to:

```text
rewrite certificate database
edit issued certificate
erase revocation history
rewrite audit history
force challenge valid
```

Such operations MUST NOT exist in the normal API.

### 6.3 Private-key confinement

Production `pki` and `pki-server` MUST NOT materialize or expose CA private keys.

Signing MUST use `KeyRef` and the established signing workflow boundary.

### 6.4 Signing staging, retirement, and recovery

Synchronous X.509 adapters are one-shot resources. They stream to disposable,
operation-lifecycle staging and MUST be closed on every path. Closing before the
signature request completes aborts partial staging. Once submission to the signing
bus begins, the bus owns disposition of the completed reference: it deletes the
reference only after proving that no durable intent exists, and retains it when a
commit is present or durability is uncertain.

Operation retirement separates live payload from durable evidence. After an
immutable provider terminal state is observed, retirement removes staged
to-be-signed content and workflow continuation state. The authoritative signing
record remains through the signing horizon with content-free commitment metadata
and, for a trustworthy on-time success, the signature result. A provider that is
not yet terminal remains `CANCELLING`; it is not falsely retired.

If staged-content deletion fails after the content-free `RETIRED` record commits,
the store retirement boundary reports only the stable redacted cleanup marker
`SIGNING_CONTENT_CLEANUP_FAILED`; higher-level adapters may map it to their stable
cleanup marker. Logical retirement still deletes workflow continuation state and
retires advisory state before reporting that marker. The retained record does not
regain a live content reference. Store restart recovery uses authoritative live
references to reclaim the orphaned staged file safely.

Each fully opened realm owns exactly one signing-reconciliation worker. The
worker starts immediately before the server becomes ready, runs one synchronous
bounded pass at a time, and self-schedules the next pass only after the current
pass returns. It has no queue of missed ticks and creates no active-active lease;
the existing realm, provider, and filesystem ownership locks remain the
single-active authority.

The reconciliation cursor is an advisory exclusive key into a metadata snapshot
ordered by canonical submission identifier. A pass examines no more than its
record bound, makes no more than its independent provider-call budget, and wraps
to the beginning after reaching the end so deferred records cannot starve other
records. Per-record failures are isolated and persisted separately from the
provider detail code with a store-time retry schedule of 2, 4, 8, 16, then 30
seconds. Terminal and retired records carry no retry metadata.

Shutdown first stops reconciliation admission and scheduling, then cooperatively
cancels and drains the active pass before closing the realm session, providers,
or store. If a provider ignores cancellation beyond the forced-shutdown period,
the server reports `SIGNING_RECONCILIATION_SHUTDOWN_TIMEOUT` and leaves those
dependencies open so close can be retried without use-after-close behavior.

`SignatureWorkflow` implementations are trusted in-process components and every
submit, status, verify, and cancel call now requires a `CallControl` carrying an
absolute deadline and cancellation signal. This is an intentionally breaking
provider-SPI migration: implementations must check the control before and
between I/O, before an externally visible effect, and before returning. These
controls are cooperative bounds; the server does not kill provider threads or
close their dependencies while a violating call remains live. Providers that
need enforcement against untrusted or non-cooperative code require a future
out-of-process provider boundary with process or RPC isolation.

Payload staging remains streaming `O(n)` time and `O(1)` aggregate auxiliary heap
excluding the signature. Synchronous waiting performs
`O(TTL / polling interval)` status observations. For `M` metadata keys and a
bound `B`, an ordered reconciliation page is `O(log M + B)` traversal and each
candidate point access is `O(log M)`, for `O(B log M)` candidate access in the
worst case. Normal pass auxiliary memory is `O(B)`. A concurrent metadata commit
may detach the currently pinned index generation once in `O(M)` time and memory;
later commits do not copy again merely because an older generation remains
pinned. A pass uses at most `maximumProviderCalls` external calls, and each realm
owns `O(1)` scheduler state.

## 7. Authorization architecture

### 7.1 Model

Authorization MUST use:

```text
RBAC templates
        over
fine-grained scoped permission grants
```

Roles are convenience bundles. Permissions are the actual authority.

### 7.2 Permission structure

A permission decision SHOULD be expressible as:

```text
action
+ resource type
+ realm scope
+ authority scope
+ issuer scope
+ profile scope
+ object relationship
+ data-view level
+ optional conditions
```

Example:

```text
action: CERTIFICATE_REVOKE
realm: production
authority: corporate-tls
profiles: [server-tls, client-tls]
relationship: ANY
conditions: reason-required
```

### 7.3 Mandatory rules

- Authorization MUST be default deny.
- Explicit deny MUST override allow.
- Administrative operations MUST have explicit realm and authority scope.
- Search permission MUST be distinct from direct object lookup.
- Creating a request MUST NOT grant approval permission.
- A principal MUST NOT approve its own request where separation of duties applies.
- Server-level administration MUST NOT implicitly grant CA administration.
- CA administration MUST NOT implicitly grant identity and role administration.
- Access denial MUST NOT reveal whether a protected object exists.

## 8. Administrative roles

Roles below are normative default templates. Deployments MAY define additional roles, but MUST preserve the underlying separation of duties.

### 8.1 Platform Operator

May manage:

- server lifecycle;
- listener configuration;
- health and readiness;
- deployment-level provider availability;
- operational diagnostics.

Does not automatically receive:

- issuance rights;
- CA lifecycle rights;
- profile activation rights;
- revocation rights;
- access to PII;
- signing-key usage rights.

### 8.2 Security Administrator

May manage:

- principals;
- roles;
- scoped grants;
- authentication providers;
- break-glass policy.

Does not automatically receive CA or issuance rights.

### 8.3 CA Security Officer

May manage assigned authorities:

- authority creation or import;
- issuer generation;
- key ceremony;
- issuer activation, suspension, retirement, and rotation;
- CA-specific profiles and policies.

Does not automatically manage principals or grant its own permissions.

### 8.4 Profile and Policy Manager

May:

- register profiles;
- validate profiles;
- activate or deactivate profiles;
- inspect policy;
- manage allowed algorithm bindings where authorized.

Does not automatically issue certificates.

### 8.5 Enrollment or RA Officer

May:

- inspect and process enrollment requests;
- issue certificates within assigned authority/profile scope;
- manage approved request workflows.

Does not automatically approve its own requests.

### 8.6 Approver

May approve or reject assigned operations.

Approval rights MUST be independently scoped.

### 8.7 Requester

May:

- create requests;
- inspect its own requests;
- download its own resulting credentials;
- request renewal, rekey, or revocation when policy permits.

### 8.8 Revocation Officer

May:

- revoke;
- place on hold;
- release from hold;
- inspect revocation history within scope.

Issuance rights are separate.

### 8.9 Publication Operator

May:

- register publication where policy permits;
- process publication;
- retry definitive retryable failures;
- reconcile unknown outcomes;
- inspect publication state.

Cannot modify the source certificate or status object.

### 8.10 Backup Operator

May:

- create or export backups;
- verify backup integrity.

Restore is a separate permission.

### 8.11 Recovery Officer

May perform restore or recovery operations when approval policy is satisfied.

### 8.12 Standard Auditor

Receives a read-only redacted view sufficient to verify PKI operation and control compliance.

### 8.13 Privileged or Forensic Auditor

May receive full PII and object content only through explicit, reason-bound, time-limited, and audited authorization.

### 8.14 ACME Administrator

May configure:

- ACME directories;
- authority/profile binding;
- challenge providers;
- EAB requirements;
- identifier namespace policy;
- ACME rate and validity policy.

Does not receive arbitrary issuance rights outside configured ACME policy.

### 8.15 ACME Account

Receives protocol-specific rights only for its own account, orders, authorizations, challenges, and certificates.

### 8.16 Anonymous or Public Principal

May access only explicitly public protocol and repository resources.

## 9. No permanent omnipotent owner

The system MUST NOT define a permanent principal with unrestricted authority over:

- platform;
- identities;
- CA lifecycle;
- issuance;
- approval;
- PII;
- restore;
- audit.

Emergency access MUST use a break-glass mechanism.

Break-glass access MUST be:

- explicit;
- time-limited;
- reason-bound;
- audited;
- optionally multi-party approved;
- incapable of rewriting immutable PKI or audit history.

## 10. Permission catalog

The implementation SHOULD provide permissions equivalent to the following categories.

### 10.1 Realm and platform

```text
REALM_READ
SERVER_HEALTH_READ
SERVER_CONFIGURATION_READ
SERVER_CONFIGURATION_UPDATE
IDENTITY_PROVIDER_MANAGE
PRINCIPAL_MANAGE
ROLE_MANAGE
PERMISSION_GRANT
```

### 10.2 Authorities and issuers

```text
AUTHORITY_LIST
AUTHORITY_READ
AUTHORITY_CREATE
AUTHORITY_IMPORT
AUTHORITY_ACTIVATE
AUTHORITY_SUSPEND
AUTHORITY_RETIRE
ISSUER_CREATE
ISSUER_ROTATE
ISSUER_RETIRE
CA_CHAIN_DOWNLOAD
```

### 10.3 Profiles, policy, and X.509 bindings

```text
PROFILE_READ
PROFILE_REGISTER
PROFILE_VALIDATE
PROFILE_ACTIVATE
PROFILE_DEACTIVATE
POLICY_READ
POLICY_UPDATE
X509_BINDING_READ
X509_BINDING_PROVIDER_ENABLE
```

### 10.4 Enrollment and issuance

```text
REQUEST_SUBMIT
REQUEST_READ_OWN
REQUEST_READ_ANY
REQUEST_APPROVE
REQUEST_REJECT
REQUEST_CANCEL
CERTIFICATE_ISSUE
CERTIFICATE_RENEW
CERTIFICATE_REKEY
```

### 10.5 Certificates

```text
CERTIFICATE_READ_METADATA
CERTIFICATE_READ_CONTENT
CERTIFICATE_SEARCH
CERTIFICATE_READ_PII
CERTIFICATE_DOWNLOAD
CERTIFICATE_PUBLICATION_CHANGE
```

### 10.6 Revocation and status

```text
CERTIFICATE_REVOKE
CERTIFICATE_HOLD
CERTIFICATE_RELEASE_HOLD
REVOCATION_HISTORY_READ
CRL_GENERATE
CRL_PUBLISH
CRL_DOWNLOAD
OCSP_ADMINISTER
```

### 10.7 Publication

```text
PUBLICATION_REGISTER
PUBLICATION_READ
PUBLICATION_PROCESS
PUBLICATION_RETRY
PUBLICATION_RECONCILE
```

### 10.8 Audit, backup, and recovery

```text
AUDIT_READ_REDACTED
AUDIT_READ_FULL
AUDIT_READ_PII
AUDIT_EXPORT
AUDIT_INTEGRITY_VERIFY
BACKUP_EXPORT
BACKUP_VERIFY
RESTORE_EXECUTE
```

Permission names MAY be adjusted to repository conventions, but their semantic separation MUST be preserved.

## 11. Approval model

High-risk operations MUST support approval policy.

Applicable operations include:

- root or intermediate CA creation/import;
- issuer activation or retirement;
- key rotation or destruction;
- significant profile activation;
- custom X.509/OID binding changes;
- privileged role or grant changes;
- snapshot restore;
- bulk revocation;
- disclosure transition to a more public state;
- audit mechanism changes;
- high-assurance issuance.

Approval policy MUST be able to express:

```text
N-of-M approvals
requester and approver separation
required approver roles
approval expiry
mandatory justification
authority and profile scope
```

An approval record MUST be durable, attributable, immutable after commitment, and bound to the exact operation content or commitment.

## 12. Auditor and PII model

### 12.1 Standard auditor

A standard auditor MAY see:

- audit event identity;
- event time;
- authority, issuer, profile, and operation identities;
- state transitions;
- safe error classifications;
- object commitments and digests;
- approval chain;
- revocation state;
- redacted subject and SAN metadata;
- aggregate operational data.

A standard auditor MUST NOT automatically receive:

- full certificate DER;
- full CSR;
- full subject or SAN;
- ACME contact data;
- internal asset names;
- publisher credentials;
- secret configuration.

### 12.2 Privileged auditor

A privileged auditor MAY inspect full certificate, CSR, subject, SAN, and related PII only when:

- the permission is explicit;
- the reason is recorded;
- access is time-limited;
- access is audited;
- approval is applied where policy requires it.

### 12.3 DER and redaction

A certificate containing PII cannot be meaningfully redacted while preserving the original DER.

Therefore:

- redacted audit access MUST return a redacted metadata view;
- full DER access requires the corresponding full-content and PII permissions.

Auditors never require private keys or unlock secrets.

## 13. Issuance, publication, and disclosure

These are distinct lifecycle dimensions:

```text
issuance
publication processing
retrieval disclosure
```

Issuing a certificate MUST NOT automatically make it public.

Publication success MUST NOT change certificate authority or validity.

### 13.1 Disclosure policy

Every retrievable certificate or repository object SHOULD have a persisted disclosure policy equivalent to:

```text
PUBLIC
PUBLIC_UNLISTED
AUTHENTICATED
OWNER_ONLY
RESTRICTED
NOT_PUBLISHED
```

### 13.2 Semantics

#### PUBLIC

- anonymously retrievable;
- MAY be publicly indexed or searchable when policy permits.

#### PUBLIC_UNLISTED

- not publicly indexed;
- not publicly searchable;
- anonymous retrieval MUST require a separate capability token or equivalent.

The object ID itself MUST NOT be the capability token.

#### AUTHENTICATED

- retrievable by authenticated principals within configured scope.

#### OWNER_ONLY

- retrievable by the requester, owner, and specifically authorized administrators.

#### RESTRICTED

- retrievable only by explicit principals or roles.

#### NOT_PUBLISHED

- validly issued;
- available only through authorized ownership or administrative access;
- not placed in a public repository.

### 13.3 Default disclosure recommendations

| Object type | Recommended default |
|---|---|
| Root CA certificate | `PUBLIC` |
| Intermediate CA certificate | `PUBLIC` |
| CA chain | `PUBLIC` |
| CRL | `PUBLIC` |
| OCSP protocol response | Public protocol access |
| Internal leaf certificate | `OWNER_ONLY` or `AUTHENTICATED` |
| Public TLS leaf certificate | Profile-defined |
| Certificate with sensitive PII | `RESTRICTED` or `NOT_PUBLISHED` |

Disclosure policy changes MUST NOT alter issued certificate bytes or revocation history.

## 14. API separation

The server architecture MUST separate:

```text
/admin/v1/...
/acme/{directoryAlias}/...
/public/v1/...
```

Exact paths MAY change according to API conventions, but the boundaries MUST remain distinct.

### 14.1 Administrative API

Requires:

- configured authentication;
- scoped permission evaluation;
- approval handling;
- typed PKI operations;
- safe audit.

### 14.2 ACME API

Uses:

- ACME account-key authentication;
- ACME state machine;
- directory-specific policy;
- challenge validation;
- optional EAB.

It MUST NOT expose general administrative operations.

### 14.3 Public API

May expose only:

- CA certificates;
- CA chains;
- CRLs;
- OCSP endpoints;
- explicitly `PUBLIC` objects;
- capability-based retrieval for `PUBLIC_UNLISTED` objects where supported.

## 15. ACME architecture

### 15.1 Directory binding

Each ACME directory MUST be bound to:

- one realm;
- one logical authority;
- one certificate profile;
- one issuance policy;
- allowed identifier types;
- allowed DNS suffixes, IP ranges, or other namespaces;
- maximum validity;
- allowed key algorithms;
- allowed X.509 algorithm bindings;
- challenge provider policy;
- optional EAB policy;
- resulting disclosure policy;
- rate/admission policy.

An ACME client MUST NOT freely select arbitrary authorities or profiles.

### 15.2 ACME account permissions

An ACME account may receive permissions equivalent to:

```text
ACCOUNT_UPDATE_OWN
ORDER_CREATE
ORDER_READ_OWN
AUTHORIZATION_READ_OWN
CHALLENGE_RESPOND_OWN
ORDER_FINALIZE_OWN
CERTIFICATE_DOWNLOAD_OWN
CERTIFICATE_REVOKE_OWN
```

An ACME account MUST NOT receive:

```text
AUTHORITY_MANAGE
PROFILE_MANAGE
CERTIFICATE_ISSUE_ARBITRARY
CERTIFICATE_SEARCH
CERTIFICATE_DOWNLOAD_ANY
CHALLENGE_FORCE_VALID
```

### 15.3 External Account Binding

EAB policy SHOULD bind the account to:

- realm;
- authority;
- directory;
- profile;
- identifier namespace;
- account policy;
- expiry;
- single-use state.

After registration, these restrictions become part of the account authorization policy.

### 15.4 Challenge validation

There MUST NOT be a permission or endpoint that simply marks a failed challenge as valid.

Out-of-band validation MAY be supported only through a configured validator SPI producing durable evidence equivalent to:

```text
validatorId
identifier
accountKeyCommitment
evidenceType
validatedAt
expiresAt
policyCommitment
result
```

Issuance requires:

```text
valid ACME account
+ valid authorization evidence
+ directory issuance policy
+ active profile
+ active authority and issuer
```

### 15.5 ACME is not generic issuance

ACME MUST NOT invoke a generic arbitrary `credential.issue` operation using only ACME account authorization.

ACME issuance MUST pass through the ACME order, authorization, challenge, directory, profile, and authority constraints.

## 16. Public retrieval rules

### 16.1 CA certificates and chains

CA certificates and chains SHOULD be publicly retrievable through explicit authority/issuer resources.

### 16.2 CRL and OCSP

CRLs and OCSP protocol endpoints SHOULD be public unless deployment policy explicitly establishes a closed PKI.

### 16.3 Leaf certificates

Leaf certificate retrieval MUST honor persisted disclosure policy.

Knowing `credentialId` alone MUST NOT grant access unless the object is `PUBLIC`.

### 16.4 Search

Public search MUST be separately authorized from direct retrieval.

Search by subject, SAN, email, account, or asset identity has elevated privacy impact and MUST require explicit permission.

## 17. Multi-process and frontend aggregation

A future frontend MAY aggregate multiple ZeroEcho server endpoints.

The frontend MUST NOT collapse authority identities or authorization decisions across realms.

Each server remains authoritative for its own realm.

Cross-realm UI aggregation is presentation and orchestration, not shared PKI authority.


## Trusted reverse-proxy TLS termination

The ZeroEcho PKI server MUST support exactly these two explicit administrative authentication deployment modes:

```text
DIRECT_MTLS
TRUSTED_REVERSE_PROXY
```

### Direct mutual TLS

In `DIRECT_MTLS` mode, ZeroEcho terminates TLS, validates the client certificate, verifies possession through the TLS handshake, and maps the validated certificate to one persisted `SecurityPrincipal`.

Forwarded client-identity headers MUST be rejected in this mode.

### Trusted reverse proxy

In `TRUSTED_REVERSE_PROXY` mode, a configured TLS-terminating reverse proxy such as NGINX validates the external client certificate and forwards the authenticated client identity to ZeroEcho.

The proxy-to-ZeroEcho connection MUST itself be authenticated.

The preferred deployment is:

```text
administrative client
    -- mutual TLS -->
trusted reverse proxy
    -- separate mutual TLS -->
ZeroEcho
```

The proxy MUST authenticate using a dedicated infrastructure identity that is distinct from every end-user principal.

The server MUST distinguish:

```text
transport principal
end-client principal
```

The transport principal identifies the trusted proxy. The end-client principal is used for administrative authorization.

The proxy principal MUST NOT inherit the permissions of the end-client principal. It MAY only receive the narrowly scoped infrastructure authority required to forward an authenticated client identity.

That infrastructure authority MUST be an explicit realm-scoped permission equivalent to `FORWARD_AUTHENTICATED_CLIENT_IDENTITY`. It grants no PKI, identity-administration, PII, approval, or end-client authority, and break-glass access MUST NOT create implicit forwarding authority.

### Forwarded certificate formats

The preferred forwarding format is the RFC 9440 `Client-Cert` header and optional `Client-Cert-Chain` header.

ZeroEcho MAY additionally support one explicitly configured NGINX compatibility format based on URL-escaped PEM, but it MUST NOT auto-detect arbitrary proxy-specific identity headers.

Every accepted format MUST have:

* one stable configuration identifier;
* strict bounded decoding;
* duplicate-header rejection;
* exact certificate consumption;
* canonical certificate validation;
* no subject-string-only identity mapping.

### Header sanitization

The trusted reverse proxy MUST remove or overwrite every incoming forwarded client-certificate header.

A request for which external mutual TLS authentication did not succeed MUST NOT contain a forwarded client identity.

ZeroEcho MUST reject:

* forwarded identity received from an untrusted transport principal;
* duplicate client-certificate headers;
* malformed certificate or chain data;
* absent client identity for an administrative operation;
* zero or multiple principal mappings;
* conflicting identity representations.

### Independent backend validation

ZeroEcho MUST independently validate the forwarded certificate and, when provided, its chain using the configured administrative-client trust policy.

ZeroEcho MUST validate:

* strict canonical certificate DER;
* certificate validity;
* configured trust;
* allowed certificate usage;
* exact certificate or SPKI commitment mapping;
* persisted principal enabled state.

The proof of possession for the external client certificate is attested by the trusted reverse proxy. Therefore, proxy authentication and transport integrity are part of the authentication authority in this mode.

### Backend transport policy

Plain unauthenticated HTTP over TCP MUST NOT be an enterprise-grade trusted-proxy mode, including over loopback.

A production trusted-proxy deployment MUST use either:

* mutually authenticated TLS from proxy to ZeroEcho; or
* a future explicitly supported operating-system-authenticated local transport such as a permission-protected Unix domain socket.

Client source-address headers, `X-Forwarded-For`, `Forwarded`, or PROXY protocol information MUST NOT establish authentication or authorization.

### Audit

Safe authentication audit MUST record:

* authentication mode;
* transport-principal identity;
* end-client principal identity when resolved;
* request correlation ID;
* safe result classification.

It MUST NOT record:

* raw certificates;
* subjects or SAN values;
* forwarded certificate headers;
* private material;
* proxy credentials;
* unrestricted parser or provider errors.

### Security invariant

Possession of a forwarded identity header is never authentication authority by itself.

Forwarded client identity is trusted only when all of the following hold:

```text
configured trusted-proxy mode
+ authenticated authorized transport principal
+ valid forwarded-certificate format
+ successful certificate and principal validation
```

## 18. Server implementation constraints

The future server implementation MUST:

- maintain one long-lived `PkiSession` per realm/server instance;
- support multiple logical authorities within the realm;
- require explicit authority scope for administrative operations;
- use bounded request execution;
- use default-deny authentication and authorization;
- keep server execution state non-authoritative;
- preserve `RECOVERY_REQUIRED` and `EXTERNAL_OUTCOME_UNKNOWN`;
- avoid automatic retries of unknown external outcomes;
- avoid implicit checkpoint or publication scheduling unless explicitly configured later;
- never expose private-key material;
- never place secrets or PII in thread names or unsafe logs.

## 19. Configuration principles

Server configuration MUST explicitly define:

- realm identity;
- allowed authorities;
- provider configuration;
- authentication providers;
- authorization roles and grants;
- listener/TLS settings;
- audit configuration;
- optional approval policies;
- optional ACME directories;
- public disclosure defaults;
- deployment-specific limits.

Configuration MUST NOT silently grant broad permissions.

Unknown security-relevant fields MUST be rejected.

Secrets MUST use external references rather than ordinary plaintext configuration output.

## 20. Persistence principles

The following must be durable where implemented:

- role and grant assignments;
- approval requests and decisions;
- disclosure policy;
- ACME account, order, authorization, challenge, and evidence state;
- capability-token metadata;
- configuration commitments required to validate authority;
- audit records.

Durable operational records MUST remain separate from certificate, revocation, and status-object authority.

## 21. Deferred design areas

The following remain separate future workstreams and MUST NOT be guessed during the initial server foundation:

- exact REST resource schemas;
- production authentication provider implementations;
- server clustering;
- leader election;
- horizontal scaling;
- distributed store semantics;
- ACME protocol implementation;
- OCSP responder implementation where absent;
- frontend implementation;
- metrics platform;
- log compaction policy;
- deployment orchestration.

Deferral does not permit deviation from this document.

## 22. Mandatory architecture tests

The server and authorization implementation MUST eventually test:

- multiple authorities in one realm;
- strict cross-authority isolation;
- one-authority deployment;
- separate issuer generations;
- default deny;
- explicit deny precedence;
- role and authority scoping;
- requester/approver separation;
- break-glass expiry and auditing;
- redacted versus privileged auditor views;
- PII exclusion from redacted output;
- public versus restricted certificate retrieval;
- object ID not acting as bearer token;
- public CA chain and CRL retrieval;
- ACME account isolation;
- ACME directory authority/profile binding;
- challenge evidence validation;
- impossibility of force-validating a challenge;
- no API for certificate, revocation, or audit rewriting.

## 23. Change-control rule

Any implementation that conflicts with this document MUST stop and report the conflict.

Codex or another agent MUST NOT:

- weaken a requirement to make tests pass;
- add a compatibility path that changes authority semantics;
- replace scoped permissions with coarse process-wide administrator access;
- make certificate IDs act as bearer credentials;
- combine admin and ACME authorization models;
- introduce a permanent omnipotent owner;
- allow direct editing of immutable PKI records;
- silently make issued certificates public;
- permit challenge force-validation.

A proposed deviation MUST be presented to the project owner with:

1. the exact conflicting requirement;
2. the implementation reason;
3. security and operational consequences;
4. at least one compliant alternative;
5. an explicit requested decision.

Until approval, the normative design in this document remains authoritative.

## 24. Accepted architecture summary

The following decisions are final for the current architecture:

1. One process serves one PKI realm.
2. One realm may contain multiple logical authorities.
3. Deployments may restrict a process to one authority.
4. Unrelated security domains use separate realms/processes.
5. Root CA is normally offline or isolated.
6. Logical authorities are distinct from issuer generations.
7. No magic certificate IDs exist.
8. RBAC roles are templates over scoped permissions.
9. No permanent omnipotent owner exists.
10. High-risk operations support multi-party approval.
11. Standard and privileged auditor views are separate.
12. PII access is explicit, reason-bound, and audited.
13. Issuance, publication, and disclosure are independent.
14. Leaf certificates are not public by default unless policy says so.
15. Object identity is not a bearer credential.
16. Admin, ACME, and public APIs are separate.
17. ACME directories are bound to authority, profile, and policy.
18. ACME accounts have only protocol-scoped rights.
19. ACME challenge validity cannot be administratively forged.
20. The future frontend may aggregate multiple realms without merging their authority.
