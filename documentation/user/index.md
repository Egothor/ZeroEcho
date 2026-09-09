# User Guide

This guide is for people and systems that *use* a ZeroEcho PKI realm rather than
administer it: certificate **requesters**, **relying parties** who need to obtain
and trust issued certificates, and **automation accounts** that enrol
certificates without a human in the loop.

You do **not** need to be a realm administrator to follow this guide. You need an
identity the realm recognises, and the guide explains what that identity lets you
see and do.

## What you can do

Depending on the permissions attached to your identity, you can typically:

- **Submit certification requests.** Prepare a certificate signing request (CSR)
  with a tool such as `openssl`, submit it to the realm, and have its proof of
  possession verified. See [Requesting certificates](requesting-certificates.md).
- **Track your requests.** Look up a request by its identifier and follow it from
  submission through to issuance.
- **Obtain and inspect your credentials.** Find an issued certificate by its
  identifier, inspect its details, and download the certificate together with its
  issuing chain from the public repository. See
  [Managing certificates](managing-certificates.md).
- **Check validity and revocation status.** Read a credential's status, and where
  your permissions allow it, request that a credential be revoked.
- **Enrol automatically.** Point a standard ACME client (such as `certbot` or
  `acme.sh`) at a ZeroEcho ACME directory to obtain and renew certificates without
  manual steps. See [ACME enrolment](acme-enrollment.md).
- **Work from the command line.** Use the `zeroecho pki` utility in its remote
  mode to submit and inspect requests and credentials over mutual TLS, with
  machine-readable output for scripting. See [Command line](command-line.md).

## Your identity decides what you see

ZeroEcho is deliberately **identity-driven**. Everything you can view or invoke is
decided by the server, from the identity you present, not by anything the client
chooses to show or hide.

!!! info "The server is the authority on your permissions"
    When you open the web console, it asks the server which operations your
    identity may perform and shows only those. Two people opening the same console
    can therefore see two different sets of actions. If an action you expect is
    missing, it is because your identity has not been granted it — contact a realm
    administrator rather than trying to work around the console.

This means the exact list above is a *superset*. Your realm administrator grants a
subset of it to your identity. A read-only relying party might only be able to
inspect and download certificates; an automation account might only be able to
submit requests through ACME.

## How the rest of this guide is organised

| Page | What it covers |
|---|---|
| [Accessing the platform](accessing.md) | Presenting a client certificate over mutual TLS, and the certificate-free demo mode for evaluation. |
| [Requesting certificates](requesting-certificates.md) | Preparing a CSR, submitting it, proof of possession, and what happens next. |
| [Managing certificates](managing-certificates.md) | Finding, inspecting, and downloading credentials; checking status; requesting revocation. |
| [ACME enrolment](acme-enrollment.md) | Automatic issuance and renewal with `certbot`, `acme.sh`, and other ACME clients. |
| [Command line](command-line.md) | Using `zeroecho pki` in remote mode for scripting and automation. |

!!! tip "New to certificate concepts?"
    If terms like *CSR*, *chain*, *CRL*, or *OCSP* are unfamiliar, the
    [glossary](../reference/glossary.md) defines them, and the
    [concepts overview](../overview/concepts.md) explains how they fit together in
    ZeroEcho.
