# The administration console

The web console is a single-page application served by the nginx edge. You reach
it in a browser that presents your administrator client certificate; there is no
password or anonymous path (see [Deployment](../deployment/index.md) for how the
edge terminates and forwards your identity). Once loaded, the console is a
task-oriented front end over the server's [operation model](index.md#the-operation-model):
every table, form, and button ultimately invokes one named operation.

## Layout

The left navigation is organised into fixed groups, each holding one or more
areas. An area is either an **entity screen** (a table of records with actions) or
falls back to an **operation browser** for actions that are not tied to a
realm-wide list.

| Group | Areas |
|---|---|
| **Overview** | Dashboard, Realm, Requests |
| **Issuance** | Certificate Authorities, Issuer Generations & Paths, Certificate Profiles, Certificate requests (CSRs), Certificates |
| **Lifecycle** | Lifecycle, Credential Confirmation, Revocation, Status & CRLs, Publication |
| **Trust & Access** | Principals, Roles & Grants, Approvals, Break-glass, Disclosure & Capabilities, Audit |
| **Operations** | ACME, OCSP, Repository Aliases, Algorithm Bindings & Config, Operations Explorer |
| **Public** | Public Repository |

The **Dashboard**, **Realm**, **Requests** and **Public Repository** screens are
always visible. Every other area is governed by the operations it contains and is
hidden when you can invoke none of them (see
[Discoverability](#the-console-hides-what-you-cannot-do)).

## Entity tables

Most administrative areas render as an entity screen: an auto-loaded, paginated,
sortable, and filterable table of records. Areas that manage several entity types
(for example **Roles & Grants**, which holds grants, role assignments, and role
templates; or **ACME**, which holds directories and accounts) show one tab per
entity.

The areas backed by a realm-wide list, and the entity each lists, are:

| Area | Entity table(s) | List operation |
|---|---|---|
| Certificate Authorities | Authorities | `ca.list` |
| Principals | Principals | `security.principal.list` |
| Roles & Grants | Grants, Role assignments, Role templates | `security.grant.list`, `security.role-assignment.list`, `security.role-template.list` |
| Approvals | Approvals | `security.approval.list` |
| Break-glass | Break-glass grants | `security.break-glass.list` |
| Publication | Publications | `publication.list` |
| ACME | Directories, Accounts | `acme.directory.list`, `acme.account.list` |
| OCSP | Responders | `ocsp.responder.list` |
| Repository Aliases | Repository aliases | `repository.alias.list` |
| Algorithm Bindings & Config | Algorithm bindings | `algorithm.binding.list` |
| Audit | Audit trail | `security.audit.search` |

A few areas list against a key you supply in the table's filter bar before the
table loads — **Status & CRLs** (per issuer), **Revocation**, **Certificate
Profiles** (per profile), and **Credential Confirmation**.

### Per-row actions

Each row offers the actions that apply to that record: an **inspect** action plus
every mutation in the area that takes the row's identifier. The console pre-fills
the identifier from the row, so you only complete the remaining fields. For
example, an authority row offers *Inspect authority*, *Transition authority
state*, *Roll over CA certificate*, and *Rotate CA key*, each pre-filled with that
authority's `caId`.

### Create flows

Where an area supports creating a new record, a **Create** action opens the
corresponding operation form. Creation conventions differ by entity — some mint
the new identifier as an argument you supply, while an authority's identifier is
assigned by the server — so the console declares the create operations explicitly.
For instance, the Certificate Authorities area offers *Create root authority*
(`ca.create`), *Create intermediate CA* (`ca.intermediate.create`), and *Issue
intermediate certificate* (`ca.intermediate.issue`).

## Operation forms

Selecting any action opens a typed form generated from the operation's parameter
contract. Fields are validated in the browser (required fields, whole numbers,
well-formed JSON, and so on) before the request is sent, but the server remains
the validating authority and independently rejects anything invalid.

Field controls follow the argument type: text and identifier boxes, integer and
timestamp inputs, checkboxes, single- and multi-select choice controls for closed
enumerations (for example a revocation reason or a CA state), string-set and
enum-set inputs, and base64 inputs for encoded documents such as a CSR or a
profile.

Read operations and direct approval decisions show their outcomes inline. Supported
business mutations transfer to the durable request detail, where these lifecycle
outcomes remain visible:

=== "Succeeded"

    The result payload is rendered inline. Operations with no payload simply
    confirm completion.

=== "Failed"

    The failure classification is shown, along with any *recovery required* or
    *reconciliation required* indicators.

=== "Approval required"

    Submitting a supported business operation automatically retains its exact
    target and creates the required [approval](access-control.md#approvals).
    The request detail shows the pending human decision; the user does not create
    a second approval request or re-enter the operation afterward.

=== "Pending"

    The server continues the retained request independently of the browser.
    Its request detail reports progress, the signing-operation id when available,
    and the final result. Refreshing the page reads status without executing again.

The complete [operation coverage and recovery contract](administrative-requests.md)
classifies every catalog mutation, including dedicated interactive transports.

### Submit once and follow the request

Choose **Submit request** on a supported business form. The server retains its exact
arguments and authority scope, decides whether approval is required, and creates
the linked approval automatically. The dialog closes and opens **Requests** detail.
There is no separate approval-creation form and no need to enter the CA again.

When the state is `WAITING_APPROVAL`, an eligible human explicitly approves with a
justification, either on the request detail or under **Approvals**. The server then
executes the retained operation independently of the browser. Closing the browser,
changing pages or approving elsewhere does not require another submission. Return
to **Requests** to inspect progress, the signing-operation receipt and final result.
Refresh and polling only read the retained request; they never repeat its command.
If a submission response is lost, the console keeps its request ID and inspects
that ID instead of automatically resubmitting.

The CA and certificate areas also show **In progress — not issued** requests.
These are pending intents, not issued CA or certificate records. Their bounded
pages have explicit pagination; completed and failed requests remain in the general
worklist. Successful issuance refreshes the actual entity table.

The selected credential format supplies the subject field's label, example and
syntax hint. Correct any field-level syntax error before submitting; the server
still checks the complete format and profile rules. Values are never silently
rewritten. Execution timeout, when supplied, is the execution budget after approval,
not a limit on human review time.

Legacy hash-only approvals have no retained executable operation. They are labelled
**Legacy approval-only** and do not represent queued CA creation. Low-level API
clients retain their explicit approval/execute contract; guided business forms use
the durable request service and show unsupported operations without replay fallbacks.

### Type-to-search pickers for references

Fields that point at an *existing* record render as a type-to-search picker rather
than a free-text box. The picker is backed by that entity's list operation and
shows a helpful secondary label. The following reference types resolve to a
picker: authority, publication, principal, grant, role template, role assignment,
approval, break-glass grant, ACME directory, ACME account, OCSP responder, and
algorithm binding.

Scoped selectors first ask for an authority or issuer generation, then load the
authorized records belonging to that context. Certificate pickers use the
mandatory inventory and do not require the optional advanced search index.

## Certificates and downloads

Open **Certificates** and choose an authority to load its bounded certificate
inventory. **View certificates** on a CA row selects that authority automatically;
no identifier copying is needed. Optional **Advanced search** remains a separate
index-dependent view. A CA's own certificate is available directly from its CA
row even when it was issued by a parent authority and belongs to that parent's
inventory.

Choose **Download CA certificate** or **Download certificate** on a table row to
read the currently authorized representations. The server resolves the current CA
certificate and supplies the format-specific choices. A completed issuance or CA
request also offers these download links beside its result. PEM is offered only
when that credential provider exports it; other formats keep their own binary
representation. Download links use native authenticated attachments, preserving
binary bytes. Metadata visibility alone does not grant download access, and the
server rechecks permissions when the file is requested.

**Public Repository** checks whether this console endpoint has an explicitly
published public API binding. When unavailable, it sends no public repository
requests and links to the authenticated CA and certificate views instead. Opening
this page never enables anonymous distribution or changes disclosure policy.
Certificate downloads in demo mode do not fall through to the real server.

## The console hides what you cannot do

On load, the console asks the server which operations you may invoke
(`GET /admin/v1/operations`) and uses the answer to drive the interface. An area
whose operations you cannot invoke is removed from the navigation entirely, and
within an area only the row actions and create flows you are permitted to run are
offered. This is a usability aid, not the security boundary: the server
authorises every request independently and fails closed regardless of what the
console shows.

The **Operations Explorer** lists the full catalogue of operations available to
you and lets you run any of them directly by filling its form — useful for actions
that are not surfaced as a row action, such as looking up a credential or request
by its identifier.

## Demo and review mode

The console has a self-contained demo mode for evaluation and review without a
live server or a client certificate. It is enabled either at build time or at
runtime by adding `?demo=1` to the URL (and disabled with `?demo=0`). In demo
mode the console runs against in-memory sample data.

Demo mode adds a **persona switcher**. Selecting a persona re-evaluates
discoverability exactly as the server would for a principal with that role, so a
reviewer can walk the console as different kinds of user and see how the
navigation and available actions change:

| Persona | What they see |
|---|---|
| **Administrator** | Full realm administration — every operation. |
| **Operator** | Day-to-day issuance, lifecycle, revocation, status, and publication (no high-risk or server-control operations). |
| **Issuer** | Submit requests and issue/inspect credentials. |
| **Auditor** | Read-only visibility across the realm, including the audit trail. |
| **Ordinary user** | A non-privileged user: submit and inspect their own requests only. |

!!! warning "Demo mode is not the product's security model"
    The personas illustrate how discoverability filters the interface. Live
    authorisation is always enforced by the server against your real roles and
    grants, described under [Access control](access-control.md).

## Next steps

Continue with [Certificate authorities](authorities.md) to establish trust, or
jump to the area you need from the [guide index](index.md#where-to-go-next).

### Stored certificates and downloads

The certificate table and credential selectors use the mandatory `credential.list`
inventory. They do not require the optional H2 search index; advanced
`credential.search` remains a separate capability. Inventory is bounded and scoped
to the selected issuing authority.

A CA row resolves its current certificate on the server. Certificate rows and
completed issuance results expose format-provided download representations. X.509
provides original DER and PEM; an opaque format can provide only its original
bytes. These actions download public certificate material, never private keys.
The browser receives a binary attachment with a server-generated filename.

Metadata permission alone does not permit downloading. Both
`CERTIFICATE_READ_CONTENT` and `CERTIFICATE_DOWNLOAD` with `CONTENT_FULL` are
required on the exact credential scope. Intermediate CA certificates retain their
canonical issuing-parent scope: reading the child authority alone does not grant
content access to the parent's issued certificate. A CA-current lookup also checks
read access to the requested child authority before resolving its certificate.

The public repository is independent of authenticated downloads. Rootless installs
leave its listener disabled; the console shows that state and makes no public
listing requests. Publishing it requires an explicitly configured public listener
with TLS, trusted-proxy authentication and `consoleBasePath: "/public/v1"`, together
with a matching nginx `PKI_PUBLIC_UPSTREAM`. The separate `authorityListExposed`
policy controls whether the console offers public listing. Enabling that routing
binding does not change any certificate's disclosure policy.


### Private CRL and status downloads

Status & CRLs rows, inspection results and completed `status.generate` requests offer
native download links. Representations come from the configured format provider:
X.509 full and delta CRLs offer DER and PEM; other formats offer their native
original bytes. Downloading does not publish the object anonymously.

Fresh installations give the initial administrator pair explicit status content
access. Existing installations require a deliberate migration:

```sh
./deploy/rootless-pki.sh update --status-access
```

This flag adds only `CRL_DOWNLOAD` with `CONTENT_FULL` on status objects to the
validated original administrator pair. It is independent of `--certificate-access`
and `--root-admin`. A retained update must be resumed with the same explicit flags;
configuration, keys, policies and existing grants are preserved. Revoked or changed
initial permissions cause refusal rather than restoration.

The authenticated metadata route is `GET /admin/v1/status-artifacts/{id}` and its
server-owned attachment links select `original` or a provider-supported representation
at `/content?representation=...`. Metadata access alone gives no content links.
Authorization uses the exact stored status-object identifier and its stored logical
CA authority; historical issuer/profile scope is never guessed from today's issuer.
Downloads prevalidate immutable content length/hash, send an exact length and SHA-256
Content-Digest, stream with bounded memory, and honor the configured maximum execution
deadline and cancellation. Native objects are limited to 256 MiB and encoded output
to 368 MiB. No public listener or disclosure rule is enabled by this migration.
