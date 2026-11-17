# Access control

This page covers who may act in the realm and how their permissions are expressed:
principals, role templates and role assignments, explicit grants, the approval
workflow with requester/approver separation, and break-glass emergency access.

These areas live under **Trust & Access**: **Principals**, **Roles & Grants**,
**Approvals**, and **Break-glass**. The full model is also documented in the
[security model reference](../reference/security-model.md).

!!! warning "Access-control changes are governed changes"
    Disabling a principal, creating a role assignment or grant, and creating or
    activating break-glass are high-risk and require an [approval](#approvals).
    Principal registration and enablement are not statically high-risk; current
    grants can still impose approval. Check the exact operation and policy
    rather than assuming all access-control writes have the same approval rule.

## Principals

A **principal** is an identity that can authenticate and be authorised. Every
principal has a type:

| Type | Meaning |
|---|---|
| `USER` | A human operator. |
| `SERVICE` | A machine or automation identity. |
| `ACCOUNT` | An enrolment account identity. |
| `PUBLIC` | The unauthenticated public identity. |

The **Principals** area lists principals (`security.principal.list`). Manage them
with:

- **Register principal** (`security.principal.register`) — supply
  `principalId`, `type`, `displayName`, and whether it is `enabled`.
- **Enable principal** (`security.principal.enable`) — re-enable a principal.
- **Disable principal** (`security.principal.disable`) — high-risk; disable a
  principal so it can no longer act.
- **Inspect principal** (`security.principal.inspect`).

## Roles and grants

Authorisation is expressed two ways: **role assignments** apply a reusable role
template to a principal, and **grants** express one explicit permission. Both are
managed under **Roles & Grants**, which shows Grants, Role assignments, and Role
templates as tabs.

### Role templates and assignments

- **List role templates** (`security.role-template.list`) and **Inspect role
  template** (`security.role-template.inspect`) — browse the available reusable
  roles and their versions.
- **Create role assignment** (`security.role-assignment.create`) — high-risk;
  assign a template to a principal. Supply `assignmentId`, `principalId`,
  `templateId`, and `templateVersion`; optionally scope it to a `profileId` and
  set an `expiresAt`.
- **Inspect role assignment** (`security.role-assignment.inspect`), **List role
  assignments** (`security.role-assignment.list`), and **Revoke role assignment**
  (`security.role-assignment.revoke`).

### Grants

A grant is one permission expressed over a precise vocabulary. Create it with
**Create grant** (`security.grant.create`) — high-risk — supplying:

| Field | Meaning |
|---|---|
| `grantId`, `principalId` | The grant identity and the principal it applies to. |
| `effect` | `ALLOW` or `DENY`. |
| `action` | The permitted action (see below). |
| `resourceType` | The resource type the action applies to. |
| `issuerId`, `profileId`, `responderId` | *(Optional)* Narrow the grant's scope. |
| `relationship` | `OWN` (only the principal's own objects) or `ANY`. |
| `dataView` | The maximum data view the grant confers (see below). |
| `conditions` | Zero or more conditions that must hold (see below). |
| `expiresAt` | *(Optional)* When the grant expires. |

Inspect, list, and revoke grants with **Inspect grant** (`security.grant.inspect`),
**List grants** (`security.grant.list`), and **Revoke grant**
(`security.grant.revoke`). To test the effective decision for a principal without
performing an action, use **Evaluate authorization**
(`security.authorization.evaluate`), supplying the `principalId`, `action`,
`resourceType`, `relationship`, and `dataView`.

#### Effect, relationship, and data view

| Dimension | Values | Meaning |
|---|---|---|
| **Effect** | `ALLOW`, `DENY` | Whether the grant permits or forbids. A `DENY` overrides. |
| **Relationship** | `OWN`, `ANY` | Whether the grant applies only to objects the principal owns, or to any object. |
| **Data view** | `METADATA_REDACTED`, `METADATA_FULL`, `CONTENT_FULL`, `PII_FULL` | The maximum sensitivity of data the grant exposes. Content and PII authority are kept separate — neither is implied by the other. |

#### Conditions

Conditions are closed, non-programmable predicates attached to a grant:

| Condition | Effect |
|---|---|
| `REASON_REQUIRED` | The action must carry a reason/justification. |
| `APPROVAL_REQUIRED` | The action must proceed through an approval, even if not statically high-risk. |
| `REQUESTER_APPROVER_SEPARATION` | The requester may not also approve. |
| `AUTHORITY_ACTIVE` | The target authority must be `ACTIVE`. |
| `PROFILE_MATCH_REQUIRED` | The action's profile must match the grant's profile scope. |

#### Actions and resource types

Grants draw their `action` and `resourceType` from fixed vocabularies. Actions
span the whole surface — realm and server configuration, principal and role
management, permission granting, authority lifecycle, issuer and chain operations,
profile management, request handling, certificate issuance and lifecycle,
certificate reads at metadata/content/PII levels, revocation and hold, CRL
generate/publish/download, OCSP administration and queries, publication
register/process/retry/reconcile, audit reads (redacted/full/PII), export and
integrity verification, backup and restore, disclosure and capability management,
repository-alias management, and ACME directory/account management. Resource types
cover the corresponding objects (authority, issuer, profile, certificate,
revocation, status object, publication, audit, disclosure, capability, approval,
break-glass, repository alias, ACME directory/account, OCSP responder, and the
server/realm/principal/role/grant control objects).

The complete enumerations are listed in the
[security model reference](../reference/security-model.md). For a per-operation
lookup table that maps every operation ID to its required action and resource
type, see the
[operation permissions reference](../reference/operation-permissions.md).

## Approvals

An **approval** is a durable record that authorises one exact high-risk (or
grant-conditioned) operation to run. It binds the operation identity, the exact
arguments (through an *operation commitment*), and the scope, so an approval can
never be reused for a different action.

The lifecycle of an approval:

| State | Meaning |
|---|---|
| `PENDING` | Awaiting decisions. |
| `APPROVED` | The threshold of approvals has been met; it can be claimed. |
| `REJECTED` | An approver rejected it. |
| `EXPIRED` | Its lifetime elapsed before it was approved or executed. |
| `CANCELLED` | The requester cancelled it. |
| `EXECUTING` | It has been claimed and the operation is running. |
| `EXECUTED` | The operation completed; the safe result is linked to the record. |

Manage approvals under **Approvals** (`security.approval.list`):

- Business forms submit one durable administrative request. The server decides
  whether approval is needed and creates its linked approval automatically.
- **Approve** (`security.approval.approve`) and **Reject**
  (`security.approval.reject`) record an explicit human decision with justification.
  Linked approvals point back to the retained administrative request.
- **Cancel approval** (`security.approval.cancel`) withdraws a pending approval.
- **Inspect approval** (`security.approval.inspect`) reads its current state.

For linked requests, reaching the approval threshold lets the server execute the
retained operation automatically; the browser never replays the target. Track the
result under **Requests**. Legacy low-level `security.approval.request` records
contain a target commitment but no executable intent: the console labels these
**Legacy approval-only**. Existing API clients still explicitly execute their exact
target with that approval ID; such records are not queued business operations.

### Requester/approver separation

An approval policy defines a **threshold** of distinct approvals and the set of
eligible approvers (named principals and/or required role templates), a lifetime,
and whether a **justification** is mandatory. Crucially, a policy can require
**requester separation**: ordinary administrators cannot approve their own
requests, and no principal may record more than one decision. An explicitly
designated root administrator can receive the dedicated realm-scoped
`APPROVAL_DECIDE_OWN` capability for its own approval requests. This designation
does not change the realm policy or grant the capability to other administrators.
Thresholds, eligibility, justification, expiry and exact-operation binding still
apply. See the [rootless deployment guide](../deployment/rootless-podman.md)
for initial-administrator designation and source updates.

!!! note "Approvals expire"
    A pending or approved approval that is not acted on within its policy lifetime
    expires automatically and can no longer be executed. Request a fresh approval
    if this happens.

## Break-glass emergency access

Break-glass provides a controlled path to emergency privilege when the normal
grant path is insufficient. It is deliberately conspicuous: creation and
activation are both high-risk and every step is audited.

Manage break-glass under **Break-glass** (`security.break-glass.list`):

- **Create break-glass** (`security.break-glass.create`) — high-risk. Supply the
  `breakGlassId`, the `principalId` it empowers, the `grantId` it stands in for,
  the `action` and `resourceType` it covers, a `reason`, and a mandatory
  `expiresAt`.
- **Activate break-glass** (`security.break-glass.activate`) — high-risk; bring
  the emergency grant into effect.
- **Revoke break-glass** (`security.break-glass.revoke`) — withdraw it.
- **Inspect break-glass** (`security.break-glass.inspect`).

!!! warning "Use, then account for, break-glass"
    Every break-glass grant is time-bounded and requires a reason, and each
    creation, activation, and revocation is recorded in the
    [audit trail](audit-and-disclosure.md). Treat any break-glass activation as a
    reviewable event.

## Related tasks

For a command-based principal/grant workflow, start with
[Set up and administer a PKI](getting-started.md#6-register-another-operator-and-grant-access).
For the deployment-owned TLS login step, use the procedure below.

- See the outcome of governed actions: [Audit and disclosure](audit-and-disclosure.md).
- Understand how discoverability reflects your permissions in the UI:
  [The administration console](console.md#the-console-hides-what-you-cannot-do).

## Give a registered operator a TLS login

This procedure adds a login to an existing persistent installation created by
`rootless-pki.sh install`. The principal must already exist and have the intended
grants. It does not create a new business CA or change approval eligibility.

### The operator creates the private key and CSR

On Alice's machine, in her private client directory:

```sh
umask 077
mkdir -p "$HOME/northstar-alice"
chmod 700 "$HOME/northstar-alice"
cd "$HOME/northstar-alice"
openssl req -new -newkey rsa:3072 -keyout alice-login.key \
  -out alice-login.csr -subj '/CN=Alice PKI Operator'
openssl req -in alice-login.csr -verify -noout
```

OpenSSL prompts for a private-key encryption password. Alice sends only the CSR
to the deployment owner. Her private key/password never go to the server owner.
The owner verifies the requested principal and CSR/public-key fingerprint through
the organization's identity-verification channel.

### The deployment owner signs the login certificate

On the deployment host, as the original service owner, set the actual paths:

```sh
INSTALL="$HOME/.local/share/northstar-pki"
LOGIN_WORK="$HOME/northstar-login-alice-01"
umask 077
mkdir "$LOGIN_WORK"
chmod 700 "$LOGIN_WORK"
```

Receive the verified CSR as `$LOGIN_WORK/alice-login.csr`. Do not overwrite a
previous enrollment directory. Validate it and create the fixed client extension:

```sh
openssl req -in "$LOGIN_WORK/alice-login.csr" -verify -noout
cat > "$LOGIN_WORK/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
```

The installer encrypts `provisioning/ca.key` with a randomly generated transport
secret retained in its private `secrets.conf`. This is **not** either user's
PKCS#12 password or the business signing-keyring password. The following supplies
only that named secret to OpenSSL through an inherited descriptor, without
printing it or putting it in command arguments/environment values:

```sh
SERIAL=$(python3 -c 'import secrets; print(secrets.randbits(159) or 1)')
openssl x509 -req -in "$LOGIN_WORK/alice-login.csr" \
  -CA "$INSTALL/provisioning/ca.crt" -CAkey "$INSTALL/provisioning/ca.key" \
  -passin fd:3 -set_serial "$SERIAL" -days 365 -sha256 \
  -extfile "$LOGIN_WORK/client.ext" -out "$LOGIN_WORK/alice-login.crt" \
  3< <(python3 - "$INSTALL/secrets.conf" <<'PY'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text().splitlines()
values = [line.partition('=')[2] for line in lines if line.startswith('ZEROECHO_TLS_PASSWORD=')]
assert len(values) == 1 and values[0]
sys.stdout.write(values[0] + '\n')
PY
)
openssl verify -purpose sslclient -CAfile "$INSTALL/provisioning/ca.crt" \
  "$LOGIN_WORK/alice-login.crt"
```

Run this only in a private owner console without shell tracing or transcript
capture. The secret-producing subprocess writes to the OpenSSL descriptor, not
the terminal. The certificate lifetime must fit your login-CA and renewal policy.
For an externally managed administrative CA, use its enrollment process instead;
do not copy its key into this installation.

### The deployment owner adds the exact mapping and restarts

Stop consistently and retain a private configuration backup before changing it:

```sh
./deploy/rootless-pki.sh stop --directory "$INSTALL"
cp -p "$INSTALL/config/server.json" "$LOGIN_WORK/server-before.json"
python3 - "$INSTALL/config/server.json" "$LOGIN_WORK/alice-login.crt" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
path = pathlib.Path(sys.argv[1])
certificate = subprocess.run(['openssl', 'x509', '-in', sys.argv[2], '-outform', 'DER'],
                             check=True, stdout=subprocess.PIPE).stdout
digest = hashlib.sha256(certificate).hexdigest()
document = json.loads(path.read_text())
authentication = document['authentication']
assert authentication['mode'] == 'TRUSTED_REVERSE_PROXY'
mappings = authentication['forwardedClientMappings']
assert not any(item['mappingId'] == 'alice-login-01' or
               item.get('certificateSha256') == digest for item in mappings)
mappings.append(dict(mappingId='alice-login-01', principalId='alice', certificateSha256=digest))
temporary = path.with_name('server-alice-next.json')
with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
    json.dump(document, output, indent=2)
    output.write('\n')
os.replace(temporary, path)
print('Mapped alice-login-01 to alice; certificate SHA-256:', digest)
PY
./deploy/rootless-pki.sh start --directory "$INSTALL"
./deploy/rootless-pki.sh status --directory "$INSTALL"
```

The certificate chains to the installer's already configured login CA; leave
`tls/admin-trust/admin-ca-bundle.pem`, backend administrative-client trust and all
existing proxy/client mappings intact. A certificate from a different login CA
requires a separately planned trust update at both verification boundaries.
If validation/start fails, keep the stopped state and inspect the specific error;
do not keep issuing certificates or delete retained service state to retry.

Deliver only `alice-login.crt`, the public administrative CA chain and the public
web CA to Alice. Keep `server-before.json` private; never give her `secrets.conf`
or `provisioning/ca.key`.

### The operator exports PKCS#12 and connects

Alice puts the delivered certificate and CA in her original directory, then:

```sh
cd "$HOME/northstar-alice"
openssl pkcs12 -export -inkey alice-login.key -in alice-login.crt \
  -certfile administrators-ca.pem -out alice-login.p12
chmod 600 alice-login.key alice-login.p12
```

OpenSSL prompts for her existing key password and a new PKCS#12 export password.
Set the real checkout, origin and realm on Alice's machine. Her initial grant in
the walkthrough permits realm metadata, so verify that access before mutations:

```sh
REPO="$HOME/work/ZeroEcho"
URL='https://pki.northstar.example:8443'
REALM='northstar'
umask 077
alice() {
  "$REPO/deploy/pki-operator.sh" --url "$URL" --realm "$REALM" \
    --trust "$HOME/northstar-alice/web-ca.pem" \
    --p12 "$HOME/northstar-alice/alice-login.p12" \
    --checkpoint "$HOME/northstar-alice/operator-state" "$@"
}
alice discover
```

Enter Alice's PKCS#12 export password at the hidden prompt. Successful discovery
exits 0 and prints `{"exit":0,"result":{"operations":...,"schema":...}}`.
Before fetching those descriptors, the client reads `GET /admin/v1/realm` and
requires its actual realm to match `--realm`; a mismatch fails discovery. The
realm check is built in, not a separate `realm.inspect` operation, and its fields
are not repeated in discovery's result. Discovery is not a grant: if authentication
succeeds but a request is refused, inspect the principal's effective `REALM_READ`
permission and mapping.
A TLS/trust, wrong-realm or permission refusal exits 2; do not bypass it with
disabled certificate validation or another user's identity. Keep this checkpoint
separate from administrator and approver sessions.
