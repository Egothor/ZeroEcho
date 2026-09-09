# Protocols and automated enrolment

ZeroEcho supports automated certificate enrolment over ACME. This page covers the
administrative side of ACME: registering and governing the ACME **directories**
that expose enrolment endpoints, and administering the **accounts** that enrol
against them. The enrolment exchange that a client performs against a directory is
described for end users in [ACME enrolment](../user/acme-enrollment.md).

ACME is managed under the **ACME** area, which shows Directories and Accounts as
tabs.

## ACME directories

An ACME directory is a named enrolment endpoint bound to one authority and profile,
with an enforced policy over the names, algorithms, and challenge types it will
accept. The **ACME** area lists directories (`acme.directory.list`).

### Registering a directory

**Register ACME directory** (`acme.directory.register`) is high-risk and requires
an [approval](access-control.md#approvals). It binds a directory to an authority
and profile and sets its enrolment policy:

| Field | Meaning |
|---|---|
| `alias` | The directory's stable alias. |
| `authorityId` | The issuing authority — also the operation's target authority. |
| `profileId` | The profile enrolled certificates are issued under. |
| `dnsNamespaces` | The DNS namespaces the directory will issue within. |
| `maximumValidityMillis` | The maximum validity of issued certificates. |
| `publicKeyAlgorithms` | The accepted subject public-key algorithms. |
| `x509BindingPolicies` | The applicable X.509 binding policies. |
| `challengeTypes` | The accepted challenge types — `HTTP_01`, `DNS_01`. |
| `challengeProviderIds` | The challenge-provider identifiers to use. |
| `eabProviderId`, `eabRequired` | *(Optional)* External Account Binding provider, and whether EAB is mandatory. |

!!! note "Enabling automated enrolment"
    Registering a directory binds it to a specific, activated
    [profile](profiles-and-issuance.md) on an `ACTIVE`
    [authority](authorities.md). Ensure both exist and are in service before you
    register, and require EAB where you need to control which accounts may enrol.

### Activating and deactivating

A directory must be activated before clients can enrol against it:

- **Activate ACME directory** (`acme.directory.activate`) — high-risk; put a
  directory into service.
- **Deactivate ACME directory** (`acme.directory.deactivate`) — withdraw a
  directory from service.
- **Inspect ACME directory** (`acme.directory.inspect`) — show a directory's
  configuration.

=== "Enable enrolment"

    Register the directory, have the registration approved, then *Activate ACME
    directory*. Clients can now discover and enrol against it.

=== "Suspend enrolment"

    *Deactivate ACME directory* to stop new enrolment without removing the
    directory's configuration or its accounts.

## ACME accounts

Each enrolling client holds an ACME account against a directory. The **Accounts**
tab lists accounts (`acme.account.list`).

- **Inspect ACME account** (`acme.account.inspect`) — show one account by
  `accountId`, including its contact and state.
- **Deactivate ACME account** (`acme.account.deactivate`) — deactivate an account
  so it can no longer enrol.

Accounts are created by clients during enrolment rather than by an administrator;
your administrative role is to inspect them and to deactivate any that should no
longer be able to enrol.

## Related tasks

- The profile and authority a directory issues from: [Profiles and issuance](profiles-and-issuance.md) and [Certificate authorities](authorities.md).
- The client-side enrolment flow: [ACME enrolment](../user/acme-enrollment.md).
