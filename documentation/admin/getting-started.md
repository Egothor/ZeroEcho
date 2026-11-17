# Set up and administer a PKI

This walkthrough starts with a persistent installation and uses the host client
to create a root CA, add an intermediate, register an operator and issue and
revoke a server certificate. Run deployment commands as the Linux service owner;
run administrative requests as the named PKI operator. These are separate roles:
the host client never accesses the server store or controls containers.

The examples use Bash, Python 3 and OpenSSL, plus the built ZeroEcho client for
chain verification. Substitute your real hostname, realm and locally selected
identities. Values returned by the server are captured below; do not invent CA,
credential, key, approval or issuer-path IDs.

## 1. Install a persistent instance

Prepare the [rootless host requirements](../deployment/rootless-podman.md#requirements),
DNS, an unused HTTPS port, a private storage path and a backup destination.
From the checkout:

```sh
./gradlew :app:installDist --no-parallel
./deploy/rootless-pki.sh install --directory "$HOME/.local/share/northstar-pki"
```

In the installer choose your hostname, published address/port, realm, initial
administrator and separate approver. Keep the signing-keyring secret and the two
PKCS#12 export passwords separately. F2 validates and provisions; Escape cancels.
The installation starts with an empty version-18 store and imports the shipped
`root-ca`, `intermediate-ca`, `server-tls`, `vpn-server` and `vpn-client` profiles.
No CA business signing key is silently generated when you create an authority.

Read the generated `NEXT-STEPS.txt`. The deployment owner delivers
`logins/administrator.p12`, `logins/approver.p12` and `logins/web-ca.pem` to their
respective users through a private channel. Do not give an operator the server
directory, transport CA private key or signing keyring. Use separate browser
profiles if you also use the console; trust the web CA and select the correct
client certificate. A PKCS#12 password unlocks a file, not a web password account.

On the administrator's machine, put the delivered files in a private directory:

```sh
umask 077
mkdir -p "$HOME/northstar-client"
chmod 700 "$HOME/northstar-client"
cd "$HOME/northstar-client"
chmod 600 administrator.p12 web-ca.pem
```

Run the remaining commands from the checkout, keeping inputs under that directory.
Set your actual connection values and the path to the checkout:

```sh
REPO="$HOME/work/ZeroEcho"
CLIENT="$HOME/northstar-client"
URL='https://pki.northstar.example:8443'
REALM='northstar'
ADMIN='northstar-admin'
cd "$REPO"
pki() {
  "$REPO/deploy/pki-operator.sh" --url "$URL" --realm "$REALM" \
    --trust "$CLIENT/web-ca.pem" --p12 "$CLIENT/administrator.p12" \
    --checkpoint "$CLIENT/admin-state" "$@"
}
pki discover > "$CLIENT/discovery.json"
python3 -m json.tool "$CLIENT/discovery.json"
```

`ADMIN` must be the actual initial administrator principal chosen in the form.
The password prompt is hidden. Do not put passwords in shell arguments or
environment variables. The client also supports an inherited `--password-fd` for
automation; see [host client authentication](../deployment/pki-operator.md).

Discovery returns `result.operations` and `result.schema`. Check that the needed
operations are available, their required arguments and realm/authority scope,
and their permission/policy requirements. The initial FIRST administrator alone
can generate managed keys; a grant to another user cannot transfer FIRST status.

## 2. Prepare requests and handle approval

These small shell helpers write private JSON inputs. They are convenience code
for this walkthrough, not additional ZeroEcho commands. `jsonargs` makes a JSON
object from string key/value pairs. `intent` writes a new file exclusively, so a
second invocation cannot overwrite a retained target:

```sh
jsonargs() {
  python3 -c 'import json,sys; a=sys.argv[1:]; assert len(a)%2==0; print(json.dumps(dict(zip(a[::2],a[1::2]))))' "$@"
}
intent() {
  python3 - "$@" <<'PY'
import json, os, sys
path, operation, arguments = sys.argv[1:4]
authority = sys.argv[4] if len(sys.argv) > 4 else ''
request_id = sys.argv[5] if len(sys.argv) > 5 else ''
document = {'operation': operation, 'arguments': json.loads(arguments)}
if authority:
    document['authorityId'] = authority
if request_id:
    document.update(version=1, requestId=request_id)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    json.dump(document, output, indent=2)
    output.write('\n')
PY
}
```

Use `read FILE` only for discovered nonmutating operations. Use `submit FILE`
for durable business mutations. Use `action FILE` for dedicated once-only actions
such as an approval decision or confirmation challenge/proof. Each mutation has
an explicit, locally unique request ID; keep both input and checkpoint.

After `submit`, inspect the printed durable record. Exit 3 means pending, not
failure or completion. If it is `WAITING_APPROVAL`, retain its exact `approvalId`
and have the independent approver inspect that linked request and decide it.
The approver uses their own client directory, certificate and checkpoint:

```sh
approver() {
  "$REPO/deploy/pki-operator.sh" --url "$URL" --realm "$REALM" \
    --trust "$APPROVER_CLIENT/web-ca.pem" --p12 "$APPROVER_CLIENT/approver.p12" \
    --checkpoint "$APPROVER_CLIENT/approver-state" "$@"
}
```

Set `APPROVER_CLIENT` to the approver's private directory on their machine; repeat
the connection/helper definitions there. For each actual approval:

```sh
read -r -p 'Approval ID from the retained request: ' APPROVAL_ID
read -r -p 'Unique local decision ID: ' DECISION_ID
intent "$APPROVER_CLIENT/$DECISION_ID-inspect.json" security.approval.inspect \
  "$(jsonargs approvalId "$APPROVAL_ID")"
approver read "$APPROVER_CLIENT/$DECISION_ID-inspect.json"
intent "$APPROVER_CLIENT/$DECISION_ID.json" security.approval.approve \
  "$(jsonargs approvalId "$APPROVAL_ID" justification 'Reviewed the exact retained request and target')" \
  '' "$DECISION_ID"
approver action "$APPROVER_CLIENT/$DECISION_ID.json"
```

Approve only after reviewing the exact requester, operation, arguments and
authority. Decision exit 3 is intentional: it is approval-only. Back in the
requester's terminal, observe the **original** request ID:

```sh
read -r -p 'Original local business request ID: ' BUSINESS_REQUEST_ID
pki observe "$BUSINESS_REQUEST_ID" --wait 60
```

Continue only after that original request is `SUCCEEDED`, with its expected
result. The server executes a linked approved request; do not POST the business
operation again with the approval ID. Exit 4 means acknowledgement is uncertain:
retain the checkpoint and observe/reconcile, never choose a new ID as a retry.
Dedicated actions have no generic retry guarantee. The initial administrator's
explicit own-approval capability does not waive eligibility, threshold,
justification or expiry; use the separate approver in normal operation.

## 3. Generate a managed key and create a root CA

Run as the protected initial administrator. This example selects RSA-4096,
compatible with the persistent installer's default RSA/SHA-256 signing binding:

```sh
intent "$CLIENT/root-key.json" key.generate \
  '{"generationId":"northstar-root-rsa-01","parameters":"RSA_4096"}' \
  '' northstar-root-key-01
pki submit "$CLIENT/root-key.json"
```

Complete the approval/observe procedure above using `northstar-root-key-01`.
From the terminal result record copy the returned **keyRef**, not generationId:

```sh
read -r -p 'Generated root keyRef: ' ROOT_KEY
intent "$CLIENT/root-profiles.json" profile.list-all '{"limit":100}'
pki read "$CLIENT/root-profiles.json"
```

Confirm `root-ca` has an active ROOT_CA version. `profile.list-all` is realm-scoped;
do not call the authority-scoped `profile.list` before an authority exists.
Check every page if the listing is truncated. Then create the authority:

```sh
intent "$CLIENT/root-create.json" ca.create \
  "$(jsonargs formatId x509 subjectRef 'CN=Northstar Root CA' profileId root-ca keyRef "$ROOT_KEY")" \
  '' northstar-root-create-01
pki submit "$CLIENT/root-create.json"
```

Approve and observe `northstar-root-create-01`. Retain the returned `caId`,
`credentialId` and `issuerId`; inspect the committed authority:

```sh
read -r -p 'Root caId: ' ROOT_CA
intent "$CLIENT/root-inspect.json" ca.inspect "$(jsonargs caId "$ROOT_CA")" "$ROOT_CA"
pki read "$CLIENT/root-inspect.json"
```

The outer `authorityId` and inner `caId` both name the actual root. Retain its
current issuance issuer/path selection. Download its public certificate with
`pki ca "$ROOT_CA" --representation pem --output "$CLIENT/root-ca.pem"`.
Distribute the verified public root through your trust-management process; a
download does not install trust on other machines.

## 4. Add an issuing intermediate

Generate a second managed key with a new generation/request identity; do not reuse
the root key. Approve and observe it:

```sh
intent "$CLIENT/intermediate-key.json" key.generate \
  '{"generationId":"northstar-intermediate-rsa-01","parameters":"RSA_4096"}' \
  '' northstar-intermediate-key-01
pki submit "$CLIENT/intermediate-key.json"
```

After successful observation, capture its keyRef and create the subordinate:

```sh
read -r -p 'Generated intermediate keyRef: ' INTERMEDIATE_KEY
intent "$CLIENT/intermediate-create.json" ca.intermediate.create \
  "$(jsonargs formatId x509 issuerCaId "$ROOT_CA" subjectRef 'CN=Northstar Issuing CA' \
    profileId intermediate-ca keyRef "$INTERMEDIATE_KEY")" \
  "$ROOT_CA" northstar-intermediate-create-01
pki submit "$CLIENT/intermediate-create.json"
```

Approve and observe that request; `ca.intermediate.create` creates and certifies
the new subordinate. Do not immediately call `ca.intermediate.issue` again:
that separate operation issues a certificate for an already known subordinate.
Capture the new `caId` as the issuing authority:

```sh
read -r -p 'Intermediate caId: ' ISSUING_CA
intent "$CLIENT/issuing-inspect.json" ca.inspect "$(jsonargs caId "$ISSUING_CA")" "$ISSUING_CA"
pki read "$CLIENT/issuing-inspect.json"
```

Confirm ACTIVE state and the intended current issuer/path before issuing leaves.
Use [issuer generations and paths](authorities.md#issuer-generations-and-chain-paths)
when selecting another chain or rotating keys; those are governed changes.

## 5. Validate and manage certificate profiles

The shipped `server-tls` profile requires DNS/IP service identity and holder
confirmation. Inspect the active version within the actual issuing authority:

```sh
intent "$CLIENT/tls-profile.json" profile.inspect \
  '{"profileId":"server-tls","profileVersion":1}' "$ISSUING_CA"
pki read "$CLIENT/tls-profile.json"
```

For a new policy, copy a complete shipped profile, edit its identity/version and
constraints, and validate it before registering. Do not edit a production profile
in place without reviewing its issuance and confirmation consequences:

```sh
cp "$REPO/deploy/pki-server/profiles/server-tls.json" "$CLIENT/new-server-profile.json"
```

Edit that copy to use a new `profileId` and your approved subject/SAN/validity
constraints. Encode the **whole document** as standard padded Base64:

```sh
PROFILE_DOCUMENT=$(python3 -c 'import base64,pathlib,sys; print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode())' "$CLIENT/new-server-profile.json")
intent "$CLIENT/profile-validate.json" profile.validate \
  "$(jsonargs document "$PROFILE_DOCUMENT")"
pki read "$CLIENT/profile-validate.json"
intent "$CLIENT/profile-register.json" profile.register \
  "$(jsonargs document "$PROFILE_DOCUMENT")" '' northstar-profile-register-01
pki submit "$CLIENT/profile-register.json"
pki observe northstar-profile-register-01 --wait 60
```

Validation is read-only; inspect its actual findings before registration.
Registration with `approvalRequirement: NONE` activates a new version immediately;
SINGLE/THRESHOLD versions remain draft until `profile.activate` is approved. To
activate a reviewed version, create an authority-scoped durable request with
arguments `{"profileId":"your-profile-id","profileVersion":1}` and operation
`profile.activate`, then approve/observe that original request. Identical active
canonical content reconciles to the existing version rather than creating another.
The remaining issuance example deliberately uses the unchanged shipped `server-tls`.

## 6. Register another operator and grant access

Registering a principal creates a durable authorization identity, **not** a TLS
login certificate, password account or permission grant:

```sh
intent "$CLIENT/alice-register.json" security.principal.register \
  '{"principalId":"alice","type":"USER","displayName":"Alice PKI Operator","enabled":true}' \
  '' northstar-alice-register-01
pki submit "$CLIENT/alice-register.json"
pki observe northstar-alice-register-01 --wait 60
intent "$CLIENT/role-templates.json" security.role-template.list '{}'
pki read "$CLIENT/role-templates.json"
```

Principal registration is not statically high-risk, although grant conditions can
still require approval. Choose a template/version from the actual listing and
inspect it; do not assume a display name denotes administrator rights. For one
explicit read-only grant:

```sh
intent "$CLIENT/alice-realm-read.json" security.grant.create \
  '{"grantId":"alice-realm-read-01","principalId":"alice","effect":"ALLOW","action":"REALM_READ","resourceType":"REALM","relationship":"ANY","dataView":"METADATA_REDACTED"}' \
  '' northstar-alice-realm-read-01
pki submit "$CLIENT/alice-realm-read.json"
```

Approve and observe that grant. It gives realm metadata read, not issuance,
approval or certificate-content access. Use the
[per-operation permissions](../reference/operation-permissions.md) to create only
the required scoped grants, or assign an inspected role template with
`security.role-assignment.create` (`assignmentId`, `principalId`, `templateId`,
integer `templateVersion`, optional `profileId`/`expiresAt`). Role/grant creation
is high-risk. Adding an approver also requires deployment approval-policy
eligibility; a permission alone does not change that list or threshold.

Follow the executable [TLS login enrollment procedure](access-control.md#give-a-registered-operator-a-tls-login)
to complete this step. Alice generates her login private key and CSR locally. The deployment owner
checks the CSR/public key, obtains a clientAuth certificate from the configured
administrative login CA, and adds a unique certificate commitment mapping to the
existing `alice` principal. For the installer's trusted proxy this belongs in
`authentication.forwardedClientMappings`, for example:

```json
{"mappingId":"alice-login-01","principalId":"alice","certificateSha256":"SHA-256-of-the-exact-login-certificate-DER"}
```

This is a configuration fragment, not an API request or a usable literal digest.
Preserve all existing mappings, proxy identity and trust settings. The deployment
owner validates configuration and controls the restart; Alice's client never
reads or edits server files. The configured administrative-client trust store
must trust Alice's certificate chain. For a CA already trusted by the installer,
no new global trust installation is needed. Deliver Alice's certificate/chain;
she exports PKCS#12 locally with her original key and a new hidden password.
See [client certificate mappings](../reference/pki-server-admin-https.md#tls-and-authentication-modes)
and [configuration](../reference/configuration-reference.md) for other supported
mapping forms. Certificate mapping establishes identity only; grants establish
authority. Use her own certificate and fresh identity-bound checkpoint for login.

## 7. Import a CSR and issue a server certificate

The server/application owner generates and protects the subject key locally.
This example uses RSA-3072 and a DNS SAN matching the service:

```sh
openssl req -new -newkey rsa:3072 -noenc -sha256 \
  -keyout "$CLIENT/api.key" -out "$CLIENT/api.csr.pem" \
  -subj '/CN=api.northstar.example' -addext 'subjectAltName=DNS:api.northstar.example'
chmod 600 "$CLIENT/api.key"
openssl req -in "$CLIENT/api.csr.pem" -outform DER -out "$CLIENT/api.csr.der"
CSR_DOCUMENT=$(python3 -c 'import base64,pathlib,sys; print(base64.b64encode(pathlib.Path(sys.argv[1]).read_bytes()).decode())' "$CLIENT/api.csr.der")
intent "$CLIENT/csr-import.json" request.import \
  "$(jsonargs formatId x509 encoded "$CSR_DOCUMENT")" '' northstar-api-csr-import-01
pki submit "$CLIENT/csr-import.json"
pki observe northstar-api-csr-import-01 --wait 60
```

Keep the subject key on its owning machine; it is not the CA key or login key.
Capture the returned certification **requestId**, distinct from the local durable
ID `northstar-api-csr-import-01`:

```sh
read -r -p 'Imported CSR requestId: ' CSR_ID
intent "$CLIENT/csr-verify.json" request.verify "$(jsonargs requestId "$CSR_ID")"
pki read "$CLIENT/csr-verify.json"
```

Check the proof-of-possession verification result. Then issue once:

```sh
intent "$CLIENT/api-issue.json" credential.issue \
  "$(jsonargs issuerCaId "$ISSUING_CA" requestId "$CSR_ID" profileId server-tls)" \
  "$ISSUING_CA" northstar-api-issue-01
pki submit "$CLIENT/api-issue.json"
pki observe northstar-api-issue-01 --wait 60
```

If the resolved profile or grants require approval, use the linked approval flow;
if signing is pending, keep observing the same request. Do not treat a signing
ID or an approved decision as a certificate. Capture the terminal credential ID:

```sh
read -r -p 'Issued credentialId: ' CREDENTIAL_ID
intent "$CLIENT/api-inspect.json" credential.inspect \
  "$(jsonargs credentialId "$CREDENTIAL_ID")" "$ISSUING_CA"
pki read "$CLIENT/api-inspect.json"
```

## 8. Enroll publication and confirm possession

The shipped profile has OWNER_ONLY confirmation disclosure. Before asking for a
challenge, associate this credential with its intended existing principal:

```sh
intent "$CLIENT/api-enroll.json" certificate.publication.enroll \
  "$(jsonargs credentialId "$CREDENTIAL_ID" ownerPrincipalId "$ADMIN")" \
  "$ISSUING_CA" northstar-api-enroll-01
pki submit "$CLIENT/api-enroll.json"
pki observe northstar-api-enroll-01 --wait 60
intent "$CLIENT/api-challenge.json" credential.confirmation.challenge.issue \
  "$(jsonargs credentialId "$CREDENTIAL_ID")" "$ISSUING_CA" northstar-api-challenge-01
pki action "$CLIENT/api-challenge.json" > "$CLIENT/api-challenge-result.json"
```

Here `ADMIN` is the publication owner selected for this example; use the actual
certificate owner in your deployment. Before proof, inspect the credential and
current authority-scoped `credential.confirmation.pending.list` review. Require
the exact credential to be pending; the review row does not expose lifecycle CAS
coordinates. Use the CAS coordinates returned by this credential's challenge,
without copying them from another response. The pending query's arguments
are `limit` (for example 100), `cutoffInclusive` (canonical UTC instant), optional
`profileId` and `afterExclusive`. Follow pagination and check the challenge expiry.
The issue response supplies the exact lifecycle/challenge CAS coordinates and
presentation. Never substitute commitments from another credential or expired
challenge. Reconcile an uncertain action before issuing another challenge.

For the **RSA** subject key generated above, the `zeroecho.signature-pop.v1`
suite uses SHA-256/RSA-PSS, MGF1-SHA256, salt length 32. PKCS#1 v1.5 is not this
proof suite. Decode the returned presentation bytes, sign them exactly, and build
the proof from the same response:

```sh
python3 - "$CLIENT/api-challenge-result.json" "$CLIENT/api-presentation.bin" <<'PY'
import base64, json, pathlib, sys
reply = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert reply['exit'] == 0 and reply['result']['status'] == 'SUCCEEDED'
challenge = reply['result']['result']
assert challenge['proofSuiteId'] == 'zeroecho.signature-pop.v1'
encoded = challenge['presentation']
with open(sys.argv[2], 'xb') as output:
    output.write(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
PY
openssl dgst -sha256 -sign "$CLIENT/api.key" \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -sigopt rsa_mgf1_md:sha256 -out "$CLIENT/api-proof.sig" "$CLIENT/api-presentation.bin"
python3 - "$CLIENT/api-challenge-result.json" "$CLIENT/api-proof.sig" \
  "$ISSUING_CA" "$CLIENT/api-proof.json" <<'PY'
import base64, json, os, pathlib, sys
challenge = json.loads(pathlib.Path(sys.argv[1]).read_text())['result']['result']
arguments = {key: challenge[key] for key in (
    'credentialId', 'expectedLifecycleRevision', 'expectedLifecycleRecordCommitment',
    'expectedChallengeRecordCommitment')}
arguments['response'] = base64.urlsafe_b64encode(pathlib.Path(sys.argv[2]).read_bytes()).decode().rstrip('=')
document = dict(version=1, requestId='northstar-api-proof-01', authorityId=sys.argv[3],
                operation='credential.confirmation.proof.complete', arguments=arguments)
with os.fdopen(os.open(sys.argv[4], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
    json.dump(document, output)
PY
pki action "$CLIENT/api-proof.json"
```

Inspect the action result and require `confirmationResult: CONFIRMED`.
`SUCCEEDED` with `REJECTED` means the operation ran but possession was **not**
confirmed. Keep the rejected result; reconcile current lifecycle/challenge state
before any corrected proof. These commands apply to the exact RSA suite, not to
ECDSA, EdDSA, PQC or dual-key proof encodings.

## 9. Download the certificate and chain

With content/download grants and disclosure allowing the request:

```sh
pki certificate "$CREDENTIAL_ID" --representation original --output "$CLIENT/api.der"
pki certificate "$CREDENTIAL_ID" --representation pem --output "$CLIENT/api.pem"
```

For the chain, use `issuer.path.list` for the actual issuerId returned by the
issuing authority, then inspect the selected path. Capture its `pathId`:

```sh
read -r -p 'Selected issuer pathId: ' PATH_ID
pki chain "$PATH_ID" --output "$CLIENT/api-chain.pem"
openssl verify -CAfile "$CLIENT/root-ca.pem" -untrusted "$CLIENT/api-chain.pem" "$CLIENT/api.pem"
```

Outputs must not exist. Certificate PEM downloads compare with original DER;
`chain` additionally verifies ordered signatures/constraints using the local Java
helper. Distribute `api.pem`, its appropriate issuer chain and the original
`api.key` to the service through your secret-delivery procedure. Never distribute
the CA signing key. A trusted chain does not prove hostname/purpose correctness;
check the SAN and serverAuth purpose for the actual service.

## 10. Revoke and generate a CRL

Use the exact certificate ID and a truthful reason. Revocation is irreversible:

```sh
intent "$CLIENT/api-revoke.json" credential.revoke \
  "$(jsonargs credentialId "$CREDENTIAL_ID" reason KEY_COMPROMISE justification 'Application key exposed; service withdrawn')" \
  "$ISSUING_CA" northstar-api-revoke-01
pki submit "$CLIENT/api-revoke.json"
pki observe northstar-api-revoke-01 --wait 60
intent "$CLIENT/api-revocation.json" revocation.inspect \
  "$(jsonargs credentialId "$CREDENTIAL_ID")" "$ISSUING_CA"
pki read "$CLIENT/api-revocation.json"
intent "$CLIENT/crl-generate.json" status.generate \
  "$(jsonargs issuerCaId "$ISSUING_CA" type CRL formatId x509)" \
  "$ISSUING_CA" northstar-crl-generate-01
pki submit "$CLIENT/crl-generate.json"
pki observe northstar-crl-generate-01 --wait 60
read -r -p 'Generated statusObjectId: ' STATUS_ID
pki crl "$STATUS_ID" --representation pem --output "$CLIENT/issuing.crl.pem"
```

Require `PERMANENTLY_REVOKED` from revocation inspection. Generating/downloading
a CRL does not publish it: configure the [publication target and aliases](publication.md)
and a public listener if relying parties need anonymous retrieval. Preserve the
previous publication until the new one has succeeded. OCSP is a separate
configured service: install/activate a responder bound to the actual issuer,
key, credential, chain and policy, then test fresh signed responses. The default
persistent installer does not provision that listener. See
[OCSP administration](revocation-and-status.md) and the
[exact native/SDK contracts](../reference/pki-server-ocsp.md); SDK evidence is not
standard AltSignature OCSP.

## 11. Back up and operate the service

As deployment owner, use the original installation path:

```sh
./deploy/rootless-pki.sh status --directory "$HOME/.local/share/northstar-pki"
./deploy/rootless-pki.sh stop --directory "$HOME/.local/share/northstar-pki"
```

After a clean stop, take a private consistent backup of the whole installation
and retain its separately protected keyring secret and safety/control authority.
Do not replace a live store with a copied directory. Start the retained instance:

```sh
./deploy/rootless-pki.sh start --directory "$HOME/.local/share/northstar-pki"
```

For logical streaming backup/restore use the [backup and recovery procedure](backup-restore.md):
verify, stage, perform the owner-controlled cold reopen, require ACTIVATED and
acknowledge separately. STAGED is not a restored live system. Observe retained
request IDs after interrupted operations; never delete a checkpoint to retry.
Read the [production guide](../deployment/pki-production.md) before compatible
updates, grant migrations or changing transport trust.
