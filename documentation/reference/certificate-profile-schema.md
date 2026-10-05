# Certificate profile schema

A certificate profile document is a strict JSON object that constrains a class
of certificates. The codec enforces schema version 5. Documents must not exceed
**256 KB**.

## Top-level structure

All fields listed below are **required** unless the Req column says Optional.

| Field | Type | Req | Constraint | Description |
|---|---|---|---|---|
| `schemaVersion` | integer | Yes | must equal `5` | Document schema version. |
| `certificateType` | string | Yes | see [Certificate types](#certificate-types) | The kind of certificate this profile governs. |
| `profileId` | string | Yes | ≤ 128 UTF-8 bytes | Stable identifier for this profile. |
| `profileVersion` | integer | Yes | positive | Monotonically increasing version counter. |
| `formatId` | string | Yes | ≤ 128 UTF-8 bytes | Format binding identifier used when importing CSRs. |
| `displayName` | string | Yes | ≤ 256 UTF-8 bytes | Human-readable profile name. |
| `maxValidity` | string | Yes | ISO-8601 duration | Maximum certificate validity period (e.g. `PT8760H` for one year). |
| `approvalRequirement` | string | Yes | see [Approval requirement](#approval-requirement) | Whether issuance requires administrative approval. |
| `algorithmBindings` | object | Yes | see [Algorithm bindings](#algorithm-bindings) | Key algorithm and key-usage constraints. |
| `subject` | array | Yes | see [Subject rules](#subject-rules) | Ordered list of subject RDN rules. |
| `subjectAlternativeNames` | array | END_ENTITY only | see [SAN rules](#san-rules) | Allowed subject alternative name types. |
| `leafCertificate` | object | END_ENTITY only | see [Leaf certificate](#leaf-certificate) | Key-usage and extension rules for end-entity certificates. |
| `confirmationPolicy` | object | END_ENTITY only | see [Confirmation policy](#confirmation-policy) | Request-confirmation policy for end-entity issuance. |
| `caCertificate` | object | CA types only | see [CA certificate](#ca-certificate) | Key-usage and path-length constraint for CA certificates. |
| `hybridMode` | object | Optional | see [Hybrid mode](#hybrid-mode) | Selects supported AltSignature root issuance or marks an independently administered Twin hierarchy. Omit for ordinary single-signature profiles. |

## Certificate types

| Value | Description |
|---|---|
| `END_ENTITY` | Leaf certificate (not a CA). Requires `subjectAlternativeNames`, `leafCertificate`, and `confirmationPolicy`. |
| `ROOT_CA` | Self-signed root CA. Requires `caCertificate`. |
| `INTERMEDIATE_CA` | Intermediate (subordinate) CA. Requires `caCertificate`. |
| `CROSS_CA` | Cross-certified CA certificate. Requires `caCertificate`. |

## Approval requirement

Declared in `approvalRequirement`. Controls whether the server gates issuance on
an administrative approval before signing.

| Value | Meaning |
|---|---|
| `NONE` | Issuance proceeds immediately without any approval. |
| `SINGLE` | Issuance requires exactly one attributable administrative approval. |
| `THRESHOLD` | Issuance requires a multi-party (M-of-N) approval threshold. The exact threshold and eligible approvers are deployment concerns, not embedded in the profile. |

## Algorithm bindings

The `algorithmBindings` object controls which public-key algorithms and key
usages a CSR may carry.

```json
"algorithmBindings": {
  "allowedKeyAlgorithms": ["ECDSA", "Ed25519"],
  "allowedKeyUsages": ["DIGITAL_SIGNATURE"]
}
```

### `allowedKeyAlgorithms`

Array of one or more strings. Accepted values:

| Value | Algorithm |
|---|---|
| `RSA` | RSA (any supported key size) |
| `ECDSA` | Elliptic-curve DSA |
| `Ed25519` | Edwards-curve 25519 |
| `Ed448` | Edwards-curve 448 |
| `SPHINCS+` | SPHINCS+ (stateless hash-based signature) |
| `ML-DSA` | Module-Lattice Digital Signature Algorithm (FIPS 204) |
| `SLH-DSA` | Stateless Hash-Based Digital Signature Algorithm (FIPS 205) |

### `allowedKeyUsages`

Array of key-usage identifiers. The valid set depends on `certificateType`.

**For `END_ENTITY`** (from `LeafKeyUsage`):

| Value | X.509 bit |
|---|---|
| `DIGITAL_SIGNATURE` | digitalSignature |
| `CONTENT_COMMITMENT` | nonRepudiation / contentCommitment |
| `KEY_ENCIPHERMENT` | keyEncipherment |
| `DATA_ENCIPHERMENT` | dataEncipherment |
| `KEY_AGREEMENT` | keyAgreement |
| `ENCIPHER_ONLY` | encipherOnly |
| `DECIPHER_ONLY` | decipherOnly |

**For CA types** (from `CaKeyUsage`):

| Value | X.509 bit |
|---|---|
| `KEY_CERT_SIGN` | keyCertSign |
| `CRL_SIGN` | cRLSign |

## Subject rules

`subject` is an ordered array of RDN rule objects. Each rule specifies how many
times an RDN component of a given OID may appear and how its value is sourced.

| Field | Type | Req | Description |
|---|---|---|---|
| `oid` | string | Yes | The RDN attribute OID (e.g. `2.5.4.3` for Common Name). |
| `source` | string | Yes | `REQUESTER` — value comes from the CSR; `PROFILE_FIXED` — value is taken from the profile. |
| `minimumOccurrences` | integer | Yes | Minimum number of times this RDN must appear (0 = optional). |
| `maximumOccurrences` | integer | Yes | Maximum number of times this RDN may appear. |
| `maximumUtf8Bytes` | integer | Yes | Maximum byte length of the RDN value in UTF-8. |
| `fixedValue` | string | Only when `source=PROFILE_FIXED` | The exact value to embed; must not be present when source is `REQUESTER`. |

## SAN rules

`subjectAlternativeNames` (END_ENTITY only) is an array of SAN type rule objects.
Each entry permits one SAN type and its constraints.

### Common fields

| Field | Type | Req | Description |
|---|---|---|---|
| `sanType` | string | Yes | One of `DNS_NAME`, `IP_ADDRESS`, `URI`, `RFC822_NAME`. |
| `minimumOccurrences` | integer | Yes | Minimum required count (0 = optional). |
| `maximumOccurrences` | integer | Yes | Maximum permitted count. |

### `DNS_NAME` extra fields

| Field | Type | Description |
|---|---|---|
| `wildcardAllowed` | boolean | Whether wildcard DNS names (e.g. `*.example.com`) are accepted. |

### `IP_ADDRESS` extra fields

| Field | Type | Description |
|---|---|---|
| `ipv4Allowed` | boolean | Whether IPv4 addresses are accepted. |
| `ipv6Allowed` | boolean | Whether IPv6 addresses are accepted. |

### `URI` extra fields

| Field | Type | Description |
|---|---|---|
| `allowedSchemes` | array of string | The URI schemes the SAN value may use (e.g. `["https", "ldap"]`). |

`RFC822_NAME` has no additional fields beyond the common ones.

## Leaf certificate

`leafCertificate` applies only to `END_ENTITY` profiles. It describes what
extensions and key-usage assertions the issued certificate will carry.

```json
"leafCertificate": {
  "keyUsages": ["DIGITAL_SIGNATURE"],
  "extendedKeyUsages": ["1.3.6.1.5.5.7.3.2"],
  "subjectKeyIdentifierIncluded": true,
  "authorityKeyIdentifierIncluded": true
}
```

| Field | Type | Description |
|---|---|---|
| `keyUsages` | array | One or more `LeafKeyUsage` values (see [allowedKeyUsages](#allowedkeyusages)). Must be a subset of `algorithmBindings.allowedKeyUsages`. |
| `extendedKeyUsages` | array of string | Optional OID strings for Extended Key Usage extension values. |
| `subjectKeyIdentifierIncluded` | boolean | Whether to include the Subject Key Identifier extension. |
| `authorityKeyIdentifierIncluded` | boolean | Whether to include the Authority Key Identifier extension. |

## Confirmation policy

`confirmationPolicy` (END_ENTITY only) controls how the server confirms that the
requesting entity controls the subject information before issuing.

| Field | Type | Description |
|---|---|---|
| `type` | string | Confirmation strategy. |

Confirmation types and their additional fields are defined by the installed
confirmation-policy providers. Contact your deployment documentation for the
supported types.

## CA certificate

`caCertificate` applies only to `ROOT_CA`, `INTERMEDIATE_CA`, and `CROSS_CA`
profiles.

| Field | Type | Req | Description |
|---|---|---|---|
| `keyUsages` | array | Yes | One or more `CaKeyUsage` values (`KEY_CERT_SIGN`, `CRL_SIGN`). |
| `pathLengthConstraint` | integer | No | X.509 path-length constraint. Omit or set to `-1` for no constraint. `0` means no further CAs below this one. |

## Hybrid mode

`hybridMode` is optional. It controls how the certificate hierarchy participates
in a post-quantum migration strategy. Two modes are currently implemented:
`ALT_SIGNATURE` and `TWIN_CERTIFICATE`. `Composite` is reserved and rejected by
the validator.

### `ALT_SIGNATURE` mode

Embeds three X.509 2019 Amendment 2 extensions into the certificate
TBS structure:

| Extension | OID | Content |
|---|---|---|
| SubjectAltPublicKeyInfo | 2.5.29.72 | Alternative public key in SubjectPublicKeyInfo DER form |
| AltSignatureAlgorithm | 2.5.29.73 | Alternative signature algorithm identifier |
| AltSignatureValue | 2.5.29.74 | Alternative signature bits |

All three extensions are non-critical, so classical verifiers that do not
recognise them skip them and still validate the primary signature correctly.

| Field | Type | Description |
|---|---|---|
| `type` | string | Must be `ALT_SIGNATURE`. |
| `altSignatureAlgorithmId` | string | Canonical ZeroEcho algorithm identity string for the alternative signature. The signing provider must support this algorithm and have the corresponding private key loaded. |
| `altKeyRef` | string | Key reference for the alternative private key in the signing provider's keyring (e.g. `zeroecho-lib:root-alt.prv`). |

```json
"hybridMode": {
  "type": "ALT_SIGNATURE",
  "altSignatureAlgorithmId": "zealg:2:9:signature8:zeroecho9:ml-dsa-6516:zeroecho.builtin6:bm9uZQ",
  "altKeyRef": "zeroecho-lib:root-alt.prv"
}
```

The canonical algorithm identity string can be obtained from
`BootstrapAlgorithmIdentities.ML_DSA_65_SIGNATURE.canonicalForm()` (and
equivalent constants for other ML-DSA and SLH-DSA parameter sets).

The alternative algorithm must have an installed standard X.509 binding with
absent or DER-NULL parameters and be supported by the selected provider's
alternative-signing capability. Structured DER parameters, including RSA-PSS
parameters, are currently unsupported for the alternative signature. No
fixed-length signature or placeholder is required. ML-DSA-65 is the built-in
profile's tested default.

`ALT_SIGNATURE` is accepted only for `ROOT_CA` profiles. An intermediate or
end-entity profile requesting it is rejected during validation. Such descendants
may use ordinary or Twin profiles beneath an AltSignature root; their certificates
then carry only their configured primary signature.

Historical unsupported profiles remain readable and included in backup/restore.
New imports, activation and issuance validate current lifecycle support; loading
an archived profile does not authorize its use for issuance.

| Lifecycle | AltSignature | Twin |
|---|---|---|
| Root creation | Both signatures and all three extensions | One signature per independent hierarchy |
| Root rollover / primary-key rotation | Preserves alternative public key and algorithm | Preserves Twin profile marker |
| Intermediate / leaf issuance | AltSignature profile rejected; ordinary descendants permitted | Standard single-signature issuance in each hierarchy |
| CRL / delta CRL | Primary signature only | Primary signature of the selected hierarchy |
| OCSP operation | Existing operation availability is unchanged; no hybrid OCSP support added | Same |
| Verification | Primary verification plus explicit alternative issuer-key verification | Independently verify each hierarchy |

Root rollover and primary-key rotation preserve the historical hybrid mode.
An active profile change cannot implicitly migrate between None, Twin and
AltSignature. Alternative-key or alternative-algorithm rotation is unsupported.
The configured alternative key must match the public key in the current root
certificate. A creation-time key-reference override is not persisted as a new
configuration default: configure the matching key before later rollover.

Previously issued AltSignature roots using the invalid placeholder transform
remain readable, but fail alternative-signature verification and rollover.
No automatic certificate repair or history rewriting is performed.

Intermediate lifecycle operations preserve the subject's actual DER ordering.
Legacy BC display-order metadata is checked against retained committed DER
during recovery. A failed or expired legacy operation with no retained DER
cannot supply that evidence and retains the existing strict recovery behavior.

The built-in `hybrid-root-ca` profile uses this mode with ML-DSA-65 as the
alternative algorithm and `zeroecho-lib:root-alt.prv` as the key reference.
Operators who activate this profile must provision an ML-DSA key under that
reference in the signing provider's keyring.

### `TWIN_CERTIFICATE` mode

A semantic marker indicating that this profile belongs to a twin-certificate
deployment. Each certificate produced from such a profile is a standard,
single-algorithm X.509 certificate — no extra extensions are added. The
relationship between the classical and PQC hierarchies is a deployment-level
configuration, not a per-certificate property.

The two hierarchies have independent issuance transactions, serials, renewal,
revocation and publication. No atomic certificate-pair transaction or wire-level
cross-reference is provided; administrators coordinate their deployment.

| Field | Type | Description |
|---|---|---|
| `type` | string | Must be `TWIN_CERTIFICATE`. No other fields are present. |

```json
"hybridMode": {
  "type": "TWIN_CERTIFICATE"
}
```

Built-in profiles using this mode:

| Profile ID | Type | Primary algorithm | Validity |
|---|---|---|---|
| `pqc-root-ca` | `ROOT_CA` | Any registered PQC or classical algorithm | 10 years |
| `pqc-intermediate-ca` | `INTERMEDIATE_CA` | Any registered PQC or classical algorithm | 5 years |

These profiles accept ML-DSA and SLH-DSA primary keys in addition to classical
ECDSA, Ed25519, and RSA. Operators can use Egothor OIDs (IANA PEN 31424, arc
`1.3.6.1.4.1.31424`) for non-standardised PQC algorithms such as SPHINCS+; those
OIDs are recognised within the ZeroEcho ecosystem.

## Complete example: end-entity TLS profile

```json
{
  "schemaVersion": 5,
  "certificateType": "END_ENTITY",
  "profileId": "tls-server-v1",
  "profileVersion": 1,
  "formatId": "PKCS10-DER",
  "displayName": "TLS Server Certificate",
  "maxValidity": "PT8760H",
  "approvalRequirement": "NONE",
  "algorithmBindings": {
    "allowedKeyAlgorithms": ["ECDSA", "Ed25519"],
    "allowedKeyUsages": ["DIGITAL_SIGNATURE"]
  },
  "subject": [
    {
      "oid": "2.5.4.3",
      "source": "REQUESTER",
      "minimumOccurrences": 1,
      "maximumOccurrences": 1,
      "maximumUtf8Bytes": 64
    },
    {
      "oid": "2.5.4.10",
      "source": "PROFILE_FIXED",
      "minimumOccurrences": 1,
      "maximumOccurrences": 1,
      "maximumUtf8Bytes": 64,
      "fixedValue": "Example Organisation"
    }
  ],
  "subjectAlternativeNames": [
    {
      "sanType": "DNS_NAME",
      "minimumOccurrences": 1,
      "maximumOccurrences": 16,
      "wildcardAllowed": false
    },
    {
      "sanType": "IP_ADDRESS",
      "minimumOccurrences": 0,
      "maximumOccurrences": 4,
      "ipv4Allowed": true,
      "ipv6Allowed": true
    }
  ],
  "leafCertificate": {
    "keyUsages": ["DIGITAL_SIGNATURE"],
    "extendedKeyUsages": ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"],
    "subjectKeyIdentifierIncluded": true,
    "authorityKeyIdentifierIncluded": true
  },
  "confirmationPolicy": {
    "type": "NONE"
  }
}
```

## Complete example: intermediate CA profile

```json
{
  "schemaVersion": 5,
  "certificateType": "INTERMEDIATE_CA",
  "profileId": "intermediate-ca-v1",
  "profileVersion": 1,
  "formatId": "PKCS10-DER",
  "displayName": "Intermediate CA",
  "maxValidity": "PT87600H",
  "approvalRequirement": "THRESHOLD",
  "algorithmBindings": {
    "allowedKeyAlgorithms": ["ECDSA"],
    "allowedKeyUsages": ["KEY_CERT_SIGN", "CRL_SIGN"]
  },
  "subject": [
    {
      "oid": "2.5.4.3",
      "source": "REQUESTER",
      "minimumOccurrences": 1,
      "maximumOccurrences": 1,
      "maximumUtf8Bytes": 64
    }
  ],
  "caCertificate": {
    "keyUsages": ["KEY_CERT_SIGN", "CRL_SIGN"],
    "pathLengthConstraint": 0
  }
}
```
