# Managing your certificates

Once a credential has been issued for your request, you can find it, inspect it,
download it together with its issuing chain, check whether it is still valid, and —
where your permissions allow — request its revocation.

Two distinct surfaces are involved, and it helps to know which is which:

- **The administrative API / web console** (mutual TLS) lets you *inspect* a
  credential's metadata and, where permitted, *act* on it. The operations are
  `credential.inspect`, `revocation.inspect`, and `credential.revoke`.
- **The public repository** (read-only, cacheable HTTP) serves the *published*
  bytes: certificates, chains, CRLs, and status objects, under the `/public/v1/…`
  path space.

## Find and inspect your credential

Every issued credential has an identifier. You will have seen it when the
credential was issued from your request; you can also find it from the request.
Use the identifier to inspect the credential's details.

=== "Command line"

    ```bash
    zeroecho pki credential.inspect \
      --url https://pki.example.com:8443 \
      --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
      --credential-id <credential-id> \
      --output json
    ```

=== "Web console"

    Open **Issuance**, choose **Inspect credential**, and enter the credential
    identifier. The console shows the subject, validity window, issuing authority,
    and related details.

`credential.inspect` returns *metadata*. To obtain the certificate bytes
themselves, download them from the public repository (below).

## Download certificates and chains

The public repository serves published material over plain, cacheable HTTPS `GET`
requests. The paths are stable and predictable, so they are easy to script or
embed in tooling. All live under `/public/v1/`.

| What you want | Endpoint |
|---|---|
| A specific certificate | `GET /public/v1/certificates/{credentialId}` |
| An authority's current issuing chain | `GET /public/v1/authorities/{authorityId}/chain` |
| A specific chain path | `GET /public/v1/authorities/{authorityId}/issuers/{issuerId}/paths/{pathId}` |
| An issuer (CA) certificate | `GET /public/v1/authorities/{authorityId}/issuers/{issuerId}/certificate` |
| An authority's current CRL | `GET /public/v1/authorities/{authorityId}/crl` |
| An authority's current delta CRL | `GET /public/v1/authorities/{authorityId}/delta-crl` |
| A status object (CRL/delta by id) | `GET /public/v1/status/{statusObjectId}` |
| List of authorities *(if exposed)* | `GET /public/v1/authorities` |
| One authority's summary | `GET /public/v1/authorities/{authorityId}` |

Downloading your certificate and verifying it against its chain:

```bash
# Download your leaf certificate (DER).
curl -sSf https://pki.example.com/public/v1/certificates/<credential-id> \
  -o leaf.crt

# Download the issuing authority's current chain descriptor (JSON). It lists the
# ordered certificate URLs that make up the chain.
curl -sSf https://pki.example.com/public/v1/authorities/<authority-id>/chain

# Fetch each certificate the chain descriptor points at (each is a
# /public/v1/certificates/{id} URL), concatenate them into chain.pem, then verify.
openssl verify -CAfile chain.pem leaf.crt
```

!!! note "The chain descriptor points at certificate URLs"
    `/public/v1/authorities/{authorityId}/chain` returns a small JSON document
    whose `certificates` array holds `/public/v1/certificates/{id}` links in
    issuing order. Fetch those to assemble the full chain.

!!! tip "Caching and conditional requests"
    Immutable objects (like a specific certificate) are served with long-lived
    cache headers and an `ETag`; alias objects (like "current chain" or "current
    CRL") are cacheable for a shorter window. You can send `If-None-Match` with a
    stored `ETag` to get a cheap `304 Not Modified` when nothing has changed.

### What is (and is not) public

The public repository is read-only and deliberately discloses only what the realm
has chosen to publish. If an object has not been published, or its disclosure
policy does not permit anonymous access, the repository returns *unavailable*
rather than revealing that the object exists. Where a realm issues a time-bounded
**disclosure capability** for a restricted object, present it as an
`Authorization: Bearer …` header on the same `GET`.

## Understand validity and revocation status

A certificate can be valid, expired (past its `notAfter`), or revoked before
expiry. Two independent things establish this:

1. **The validity window** printed in the certificate itself:

    ```bash
    openssl x509 -in leaf.crt -noout -dates -subject -issuer
    ```

2. **The revocation status** published by the realm. As a relying party you check
   this against the published **CRL** (or delta CRL), or against **OCSP** if the
   realm runs a responder:

    ```bash
    # Download the current CRL and look for your certificate's serial.
    curl -sSf https://pki.example.com/public/v1/authorities/<authority-id>/crl \
      -o current.crl
    openssl crl -in current.crl -inform DER -noout -text
    ```

If you hold administrative read access to the credential, you can also read its
revocation state directly:

=== "Command line"

    ```bash
    zeroecho pki revocation.inspect \
      --url https://pki.example.com:8443 \
      --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
      --credential-id <credential-id> \
      --output json
    ```

=== "Web console"

    Open **Revocation** and choose **Inspect revocation** for the credential to see
    whether it is revoked, and if so, when and why.

## Request revocation (where permitted)

If a private key is lost or exposed, or a certificate is no longer needed, it
should be revoked. Revocation is permitted only for identities the realm has
granted it for the credential in question.

=== "Command line"

    ```bash
    zeroecho pki credential.revoke \
      --url https://pki.example.com:8443 \
      --client-keystore me.p12 --client-keystore-password-env PKI_P12_PASSWORD \
      --credential-id <credential-id> \
      --reason KEY_COMPROMISE \
      --justification "Key exposed on decommissioned host" \
      --output json
    ```

=== "Web console"

    Open **Revocation**, choose **Revoke credential**, select the reason, and add a
    justification if prompted.

!!! warning "Revocation is permanent"
    A revoked certificate cannot be un-revoked. Once revocation is published in a
    CRL (or reflected by OCSP), relying parties will reject the certificate. If you
    still need a certificate for the same subject afterwards,
    [submit a new request](requesting-certificates.md).

!!! info "If revocation is refused"
    If the console does not offer revocation, or the command is denied, your
    identity has not been granted revocation for that credential. A realm
    administrator can revoke it on your behalf, or grant you the permission.

## Next steps

- Need a fresh certificate? [Requesting certificates](requesting-certificates.md).
- Automating issuance and renewal? [ACME enrolment](acme-enrollment.md).
- Scripting these steps? [Command line](command-line.md).
