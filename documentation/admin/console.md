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
| **Overview** | Dashboard, Realm |
| **Issuance** | Certificate Authorities, Issuer Generations & Paths, Certificate Profiles, Requests (CSRs), Issuance |
| **Lifecycle** | Lifecycle, Credential Confirmation, Revocation, Status & CRLs, Publication |
| **Trust & Access** | Principals, Roles & Grants, Approvals, Break-glass, Disclosure & Capabilities, Audit |
| **Operations** | ACME, OCSP, Repository Aliases, Algorithm Bindings & Config, Operations Explorer |
| **Public** | Public Repository |

The **Dashboard** and **Realm** overview screens and the **Public Repository** are
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

When you submit, the form shows the operation's outcome directly:

=== "Succeeded"

    The result payload is rendered inline. Operations with no payload simply
    confirm completion.

=== "Failed"

    The failure classification is shown, along with any *recovery required* or
    *reconciliation required* indicators.

=== "Approval required"

    The form reports that the operation is high-risk or grant-conditioned, shows
    the *operation commitment*, and offers to create a durable
    [approval](access-control.md#approvals) bound to these exact arguments.

=== "Pending"

    A signing hand-off did not return within the wait budget. The console reports
    the signing-operation id so the work can be resumed later.

### Type-to-search pickers for references

Fields that point at an *existing* record render as a type-to-search picker rather
than a free-text box. The picker is backed by that entity's list operation and
shows a helpful secondary label. The following reference types resolve to a
picker: authority, publication, principal, grant, role template, role assignment,
approval, break-glass grant, ACME directory, ACME account, OCSP responder, and
algorithm binding.

Fields that name an entity without a realm-wide list — for example a credential,
request, profile, issuer generation, status object, or chain path — accept the
identifier directly. You obtain these identifiers by inspecting the parent record
(for example the request or credential returned by an earlier step) or from the
area's key-filtered table.

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
