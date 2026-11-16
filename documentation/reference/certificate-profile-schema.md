# Certificate profile schema

Owner: PKI maintainers. Reviewed: 2026-11-16. Review on profile/codec changes.
Source-reviewed examples remain unverified as written pending procedure rehearsal.

A certificate profile document is a strict JSON object that constrains a class
of certificates. The codec enforces schema version 5. Documents must not exceed
**262144 bytes**. Unknown/duplicate fields, wrong types, unsupported versions,
trailing data, a UTF-8 BOM and null optionals are rejected. Depth is bounded at
16, arrays at 128 elements and ordinary strings at 4096 UTF-8 bytes; individual
fields may have smaller bounds. These are JSON profiles consumed by
`CertificateProfileDocumentCodec`, not arbitrary CSR-format documents.

## Top-level structure

All fields listed below are **required** unless the Req column says Optional.

| Field | Type | Req | Constraint | Description |
|---|---|---|---|---|
| `schemaVersion` | integer | Yes | must equal `5` | Document schema version. |
| `certificateType` | string | Yes | see [Certificate types](#certificate-types) | The kind of certificate this profile governs. |
| `profileId` | string | Yes | ≤ 128 UTF-8 bytes | Stable identifier for this profile. |
| `profileVersion` | integer | Yes | positive | Monotonically increasing version counter. |
| `formatId` | string | Yes | ≤ 128 UTF-8 bytes | Installed certificate format; the recipes use `x509`. |
| `displayName` | string | Yes | ≤ 256 UTF-8 bytes | Human-readable profile name. |
| `maxValidity` | string | Yes | ISO-8601 duration | Maximum certificate validity period (e.g. `PT8760H` for one year). |
| `approvalRequirement` | string | Yes | see [Approval requirement](#approval-requirement) | Whether issuance requires administrative approval. |
| `algorithmBindings` | object | Yes | see [Algorithm bindings](#algorithm-bindings) | Standard-only or explicitly pinned representation bindings. |
| `subject` | object | Yes | see [Subject rules](#subject-rules) | Empty-subject policy and ordered subject RDN rules. |
| `subjectAlternativeNames` | object | END_ENTITY only | see [SAN rules](#san-rules) | Total limits, identity/criticality policy and allowed SAN type rules. |
| `leafCertificate` | object | END_ENTITY only | see [Leaf certificate](#leaf-certificate) | Key-usage and extension rules for end-entity certificates. |
| `confirmationPolicy` | object | END_ENTITY only | see [Confirmation policy](#confirmation-policy) | Request-confirmation policy for end-entity issuance. |
| `caCertificate` | object | CA types only | see [CA certificate](#ca-certificate) | Key-usage and path-length constraint for CA certificates. |
| `hybridMode` | object | Optional | see [Hybrid mode](#hybrid-mode) | Selects supported AltSignature issuance/lifecycle or marks an independently administered Twin hierarchy. Omit for ordinary single-signature profiles. |

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
| `NONE` | No profile-imposed issuance approval; other authorization/high-risk policy still applies. |
| `SINGLE` | Issuance requires exactly one attributable administrative approval. |
| `THRESHOLD` | Issuance requires a multi-party (M-of-N) approval threshold. The exact threshold and eligible approvers are deployment concerns, not embedded in the profile. |

## Algorithm bindings

The `algorithmBindings` object selects X.509 representation policy; subject-key
families and key usages belong to leaf/CA policy below. It has required `mode`
and optional `subjectPublicKey`, `csrSignature`, `certificateSignature`,
`crlSignature` references. Each reference is exactly `{ "bindingId": "...",
"semanticCommitment": "..." }` from the installed binding registry; do not
invent an OID, commitment or algorithm identity.

```json
"algorithmBindings": {
  "mode": "STANDARD_ONLY"
}
```

`STANDARD_ONLY` permits no explicit references and no private-OID fallback.
`EXPLICIT` requires at least one exact reference. Discover bindings through
`algorithm.binding.list` (required integer `limit`) and inspect their identity,
semantic commitment and role. Representation selection alone does not choose
an issuer's key or outgoing signature algorithm.

### `allowedKeyAlgorithms`

`leafCertificate.allowedKeyAlgorithms` and
`caCertificate.allowedSubjectKeyAlgorithms` are arrays of supported family tokens.
Accepted syntax includes the following; codec acceptance does not prove a signer,
client or qualified scenario supports every family/parameter set.

| Value | Algorithm |
|---|---|
| `RSA` | RSA (any supported key size) |
| `ECDSA` | Elliptic-curve DSA |
| `Ed25519` | Edwards-curve 25519 |
| `Ed448` | Edwards-curve 448 |
| `SPHINCS+` | SPHINCS+ (stateless hash-based signature) |
| `ML-DSA` | Module-Lattice Digital Signature Algorithm (FIPS 204) |
| `SLH-DSA` | Stateless Hash-Based Digital Signature Algorithm (FIPS 205) |
| `LMS`, `XMSS` | Stateful families; not supplied by the four approved certificate scenarios. |

### `allowedKeyUsages`

Key-usage identifiers live in `leafCertificate.keyUsage` (singular) or
`caCertificate.keyUsages` (plural), not `algorithmBindings.allowedKeyUsages`.
The valid set depends on `certificateType`.

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

`subject` is exactly an object with required boolean `allowEmpty` and array
`rules`. Each ordered rule specifies how many times an RDN component of a given
OID may appear and how its value is sourced. An empty permitted subject requires
at least one SAN in an end-entity profile.

| Field | Type | Req | Description |
|---|---|---|---|
| `oid` | string | Yes | The RDN attribute OID (e.g. `2.5.4.3` for Common Name). |
| `source` | string | Yes | `REQUESTER` — value comes from the CSR; `PROFILE_FIXED` — value is taken from the profile. |
| `minimumOccurrences` | integer | Yes | Minimum number of times this RDN must appear (0 = optional). |
| `maximumOccurrences` | integer | Yes | Maximum number of times this RDN may appear. |
| `maximumUtf8Bytes` | integer | Yes | Maximum byte length of the RDN value in UTF-8. |
| `fixedValue` | string | Only when `source=PROFILE_FIXED` | The exact value to embed; must not be present when source is `REQUESTER`. |

## SAN rules

`subjectAlternativeNames` (END_ENTITY only) is an object with all six required
fields: integer `minimumTotal`, integer `maximumTotal`, boolean
`serviceIdentityRequired`, boolean `emailIdentityRequired`, boolean
`criticalWhenSubjectNonEmpty`, and array `rules`. Every rule permits one SAN
type and its occurrence constraints. Minimum/maximum bounds and policy invariants
are checked by the typed policy constructors.

### Common fields

| Field | Type | Req | Description |
|---|---|---|---|
| `type` | string | Yes | One of `DNS_NAME`, `IP_ADDRESS`, `URI`, `RFC822_NAME`. |
| `minimumOccurrences` | integer | Yes | Minimum required count (0 = optional). |
| `maximumOccurrences` | integer | Yes | Maximum permitted count. |

### `DNS_NAME` extra fields

| Field | Type | Description |
|---|---|---|
| `wildcardAllowed` | boolean, required | Whether wildcard DNS names (e.g. `*.northstar.example`) are accepted. |

### `IP_ADDRESS` extra fields

| Field | Type | Description |
|---|---|---|
| `ipv4Allowed` | boolean, required | Whether IPv4 addresses are accepted. |
| `ipv6Allowed` | boolean, required | Whether IPv6 addresses are accepted. |

### `URI` extra fields

| Field | Type | Description |
|---|---|---|
| `allowedSchemes` | array of string, required | Lowercase ASCII URI schemes, each at most 32 bytes (e.g. `["https", "spiffe"]`). |

`RFC822_NAME` has no additional fields beyond the common ones. Type-specific
fields are mandatory for their type and forbidden on other types.

## Leaf certificate

`leafCertificate` applies only to `END_ENTITY` profiles. It describes what
extensions and key-usage assertions the issued certificate will carry.

```json
"leafCertificate": {
  "basicConstraintsCritical": true,
  "keyUsageCritical": true,
  "keyUsage": ["DIGITAL_SIGNATURE"],
  "extendedKeyUsageCritical": false,
  "extendedKeyUsage": ["1.3.6.1.5.5.7.3.2"],
  "allowedKeyAlgorithms": ["ECDSA", "Ed25519", "RSA"]
}
```

| Field | Type | Description |
|---|---|---|
| `basicConstraintsCritical` | boolean | Required criticality flag for non-CA basic constraints. |
| `keyUsageCritical` | boolean | Required key-usage criticality flag. |
| `keyUsage` | array | Required `LeafKeyUsage` values (see [usage values](#allowedkeyusages)). |
| `extendedKeyUsageCritical` | boolean | Required EKU criticality flag. |
| `extendedKeyUsage` | array of string | Required array of canonical EKU OID strings. |
| `allowedKeyAlgorithms` | array of string | Required permitted subject-key families. |

## Confirmation policy

`confirmationPolicy` is required for END_ENTITY and forbidden for CA types. It
defines the disclosure and holder-confirmation policy, distinct from CSR PoP and
administrative approval. All five fields are required:

| Field | Type | Description |
|---|---|---|
| `disclosurePolicy` | string | Supported `ConfirmationDisclosurePolicy` value, such as `OWNER_ONLY`; select the actual configured policy. |
| `confirmationWindow` | string | Positive supported ISO-8601 confirmation duration. |
| `proofSuiteId` | string | Installed proof suite ID, at most 128 UTF-8 bytes. |
| `proofSuiteCommitment` | string | Exact 64-character configuration commitment of that proof suite. |
| `policyCommitment` | string | Exact 64-character derived commitment of the whole confirmation policy. |

The codec reconstructs the typed policy and checks its derived commitment.
Do not use a fabricated `type=NONE` object or guess hashes. The complete example
below retains the shipped OWNER_ONLY/PT24H proof-policy values; changing that
policy requires generating the matching canonical commitment with the supported
SDK/configuration workflow and validating before registration.

## CA certificate

`caCertificate` applies only to `ROOT_CA`, `INTERMEDIATE_CA`, and `CROSS_CA`
profiles.

| Field | Type | Req | Description |
|---|---|---|---|
| `basicConstraintsCritical` | boolean | Yes | CA basic-constraints criticality. |
| `keyUsageCritical` | boolean | Yes | Key-usage criticality. |
| `keyUsages` | array | Yes | One or more `CaKeyUsage` values (`KEY_CERT_SIGN`, `CRL_SIGN`). |
| `pathLengthConstraint` | integer | Yes | `-1` means no path-length constraint; `0` means no further subordinate CAs. |
| `allowedSubjectKeyAlgorithms` | array of string | Yes | Permitted subject-key families; does not replace explicit outgoing algorithm/key selection. |

## Hybrid mode

`hybridMode` is optional. It controls how the certificate hierarchy participates
in a post-quantum migration strategy. Two modes are currently implemented:
`ALT_SIGNATURE` and `TWIN_CERTIFICATE`. `Composite` is reserved and rejected by
the validator.

### `ALT_SIGNATURE` mode

Uses the X.509 alternative-signature extensions with the implemented Cor. 3
transcript rules. Verify the actual primary and alternative issuer relationships:

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
| `subjectKeySource` | string | `MANAGED` (default) for CA subject keys, `REQUEST` for ordinary hybrid end-entity subject keys. |
| `altKeyRef` | string | Required managed alternative subject-key reference for MANAGED; absent for REQUEST. Applicant private keys remain client-owned. |

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

`ALT_SIGNATURE` supports root/intermediate CA and end-entity issuance. CA profiles
use managed subject keys. Ordinary end-entity profiles use `subjectKeySource:
"REQUEST"` and omit `altKeyRef`; issuance requires the approved SDK dual-subject
PoP workflow. The narrow dedicated managed OCSP responder profile instead permits
MANAGED end-entity keys with exactly digitalSignature and id-kp-OCSPSigning, through
controlled `ocsp.responder.issue-certificate`. Selecting a profile alone grants
neither key generation nor permission to sign.

Historical unsupported profiles remain readable and included in backup/restore.
New imports, activation and issuance validate current lifecycle support; loading
an archived profile does not authorize its use for issuance.

| Lifecycle | AltSignature | Twin |
|---|---|---|
| Root creation | Both signatures and all three extensions | One signature per independent hierarchy |
| CA rollover / key rotation | Explicit primary, alternative or both-role rotation; omitted roles preserved | Preserves Twin profile marker |
| Intermediate / leaf issuance | Both issuer signatures; leaf subject keys require both fresh SDK proofs | Standard single-signature issuance in each hierarchy |
| CRL / delta CRL | Both signatures with qualified SDK/BC-compatible transcript profile and generation/base continuity | Primary signature of the selected hierarchy |
| OCSP | Native single-signature RFC 6960 plus optional **separate** SDK F4/F5 evidence, not standard AltSignature OCSP | Ordinary native profile |
| Verification | Primary verification plus explicit alternative issuer-key verification | Independently verify each hierarchy |

Lifecycle operations preserve the accepted immutable issuer/key/profile binding;
an active profile edit cannot implicitly migrate existing credentials. Hybrid
renew/reissue proves both unchanged subject keys; replacement proves the requested
tuple. A changed-key/algorithm root candidate requires separately approved
activation after distribution acknowledgement; same-tuple rollover keeps ordinary
selection behavior. See [CA lifecycle](../admin/authorities.md#certificate-rollover-and-key-rotation)
and [activities](../admin/operator-activities.md).

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

That bundled default is not the approved ML-DSA-87 scenario selection. The
[classical/PQC/hybrid recipes](../deployment/pki-exercise.md#approved-algorithm-scenarios)
register explicit per-run profiles and managed keys for P-384/SHA-384 plus
ML-DSA-87. A primary-only verifier does not establish alternative-signature
assurance or universal PQC browser/TLS compatibility.

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
  "profileId": "northstar-server-tls",
  "profileVersion": 1,
  "formatId": "x509",
  "displayName": "Northstar Example Server TLS",
  "maxValidity": "PT8760H",
  "approvalRequirement": "NONE",
  "algorithmBindings": {"mode": "STANDARD_ONLY"},
  "subject": {
    "allowEmpty": true,
    "rules": [
      {"oid": "2.5.4.3", "source": "REQUESTER", "minimumOccurrences": 0,
       "maximumOccurrences": 1, "maximumUtf8Bytes": 253}
    ]
  },
  "subjectAlternativeNames": {
    "minimumTotal": 1,
    "maximumTotal": 64,
    "serviceIdentityRequired": true,
    "emailIdentityRequired": false,
    "criticalWhenSubjectNonEmpty": false,
    "rules": [
      {"type": "DNS_NAME", "minimumOccurrences": 0, "maximumOccurrences": 64,
       "wildcardAllowed": false},
      {"type": "IP_ADDRESS", "minimumOccurrences": 0, "maximumOccurrences": 16,
       "ipv4Allowed": true, "ipv6Allowed": true}
    ]
  },
  "leafCertificate": {
    "basicConstraintsCritical": true,
    "keyUsageCritical": true,
    "keyUsage": ["DIGITAL_SIGNATURE"],
    "extendedKeyUsageCritical": false,
    "extendedKeyUsage": ["1.3.6.1.5.5.7.3.1"],
    "allowedKeyAlgorithms": ["ECDSA", "Ed25519", "RSA"]
  },
  "confirmationPolicy": {
    "disclosurePolicy": "OWNER_ONLY",
    "confirmationWindow": "PT24H",
    "proofSuiteId": "zeroecho.signature-pop.v1",
    "proofSuiteCommitment": "5ab6ec453561975d8978076cb31227cd68bc1f66da417bfb500002704be5ef11",
    "policyCommitment": "4933b3d9a9dd31b972d5835884ed8ef9218f8d331928e6ac0feb802d28ab9a30"
  }
}
```

## Complete example: intermediate CA profile

```json
{
  "schemaVersion": 5,
  "certificateType": "INTERMEDIATE_CA",
  "profileId": "northstar-intermediate-ca",
  "profileVersion": 1,
  "formatId": "x509",
  "displayName": "Northstar Example Intermediate CA",
  "maxValidity": "PT43800H",
  "approvalRequirement": "NONE",
  "algorithmBindings": {"mode": "STANDARD_ONLY"},
  "subject": {
    "allowEmpty": false,
    "rules": [
      {"oid": "2.5.4.3", "source": "REQUESTER", "minimumOccurrences": 1,
       "maximumOccurrences": 1, "maximumUtf8Bytes": 253}
    ]
  },
  "caCertificate": {
    "basicConstraintsCritical": true,
    "pathLengthConstraint": 0,
    "keyUsageCritical": true,
    "keyUsages": ["KEY_CERT_SIGN", "CRL_SIGN"],
    "allowedSubjectKeyAlgorithms": ["ECDSA", "Ed25519", "ML-DSA", "RSA", "SLH-DSA"]
  }
}
```

These examples preserve the shipped schema/policy shapes with fictitious
Northstar labels; they do not claim successful registration in a new instance.
Validate with `profile.validate` before registering. Use the TUI's profile form
or base64-encode the complete JSON as `document` in the automation intent, as
specified by the live schema. Registration returns the actual profile reference;
carry its version/hash forward. Never substitute a profile label for exact
subject-key, issuer-algorithm or alternative-signature verification.
