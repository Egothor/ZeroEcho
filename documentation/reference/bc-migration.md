# BouncyCastle 1.86 migration notes

ZeroEcho upgraded its bundled BouncyCastle provider from 1.84 to 1.86. This
page documents the breaking changes introduced by that upgrade and the action
required from operators and developers.

Review the SPHINCS+ compatibility rules below before loading old specifications
or keys. Unsupported parameter sets are not silently substituted.

## Removed parameter sets

### Classic McEliece — `mceliece348864` removed

The `mceliece348864` parameter set has been removed in BC 1.86. Any code or
configuration that requests this variant will fail at runtime.

**Action required:** Replace `mceliece348864` with `mceliece460896` or a higher
security level. ZeroEcho's advertised sets are `mceliece460896`, `mceliece460896f`,
`mceliece6688128`, `mceliece6688128f`, `mceliece6960119`, `mceliece6960119f`,
`mceliece8192128`, and `mceliece8192128f`.

### FrodoKEM — `frodo640` removed

The `frodo640` parameter set has been removed in BC 1.86. Any code or
configuration that requests this variant will fail at runtime.

**Action required:** Choose `FrodoKEM-976-AES`, `FrodoKEM-976-SHAKE`,
`FrodoKEM-1344-AES`, or `FrodoKEM-1344-SHAKE` when generating new keys.
The 640 variants are absent from the catalogue. Existing enum constants remain
for source compatibility; BC 1.86 rejects attempts to generate those variants.
This is a parameter change requiring new key material, not a key conversion.

## SPHINCS+ JCA interface removed

BC 1.86 removes the SPHINCS+ JCA algorithm name registration. ZeroEcho retains
the canonical identifier `"SPHINCS+"` as a compatibility binding to pure SLH-DSA
(FIPS 205), using provider `BC`. This does not make legacy SPHINCS+ keys or
signatures interchangeable with SLH-DSA.

**Impact on ZeroEcho callers:**

- Defaults and advertised descriptors use `Mode.SIMPLE` with SHA-2 or SHAKE.
  Explicit `ROBUST` and `HARAKA` requests fail with `IllegalArgumentException`
  before provider invocation, even when an explicit parameter override is present.
- Explicit overrides may select any of the twelve pure SLH-DSA parameter
  constants. Unknown and prehash constants fail with `IllegalArgumentException`.
  The override still intentionally takes precedence over hash/strength/variant.
- Public/private persisted specs with a missing provider, and constructors with
  a null provider, select `BC`. Current `BC` payloads round-trip unchanged.
  Explicit `BCPQC` specs fail with `IllegalArgumentException` during construction
  or unmarshalling. Generation with `BCPQC` is also rejected explicitly.
- Import accepts only valid SLH-DSA X.509/PKCS#8 encodings. Legacy SPHINCS+ OIDs
  fail with `GeneralSecurityException` at import, including in provider-less
  payloads. Key bytes and OIDs are never rewritten. Relabelling an old payload
  with `BC` does not migrate its key.

If you were using SPHINCS+ with the HARAKA variant, migrate to
`"SLH-DSA"` with a SHA-2 or SHAKE parameter set via `SlhDsaKeyGenSpec`.
The same applies to ROBUST and legacy SPHINCS+ keys: generate new SLH-DSA keys
and retain a separate compatible legacy verifier if old signatures must remain
verifiable. Previously generated SLH-DSA keys remain usable; the former silently
ignored ROBUST flag must not be interpreted as proof that those keys used ROBUST.

## Catalogue and template contracts

Descriptor IDs and labels must be nonblank; IDs are unique within an algorithm.
Lists are immutable and ordered. Templates expose `constraints()` with value kind,
required flags, defaults, ordered choices and inclusive integer bounds/steps.
`factory().apply(arguments)` validates and snapshots the map, applies defaults,
and rejects unknown, missing, explicit-null, wrongly typed and out-of-range values
with `IllegalArgumentException` before calling the supplied factory. Error messages
do not include supplied values. Schema validation is linear in the number of
parameters and supplied arguments on average and retains only a map of that size.

Existing `TemplateParameter` and `Template` record shapes and constructors remain
available. The old five-argument template constructor cannot infer required fields,
defaults or domain bounds from prose; its `LEGACY` constraints preserve omission
semantics and enforce declared Java types. Built-in templates use explicit schemas.
Third-party providers remain responsible for stable immutable catalogue results;
registry startup validates a snapshot without replacing provider identities.

`ElGamal-2048` now supplies the executable `ElgamalParamSpec.ffdhe2048()`.
Consumers that cast its former, unregistered `ElgamalKeyGenSpec` must adjust.
The unusable `elgamal-custom` template is removed. Size-based spec classes and SDK
methods remain source-compatible, but generator lookup still rejects them with
`IllegalArgumentException`; slow random domain-parameter generation remains disabled.
DH standard groups now use their supplied parameters directly, including 4096,
6144 and 8192 bits.

## X-Wing input boundaries

Raw public keys contain 1216 bytes (ML-KEM-768 followed by X25519); private seeds
contain 32 bytes; ciphertexts contain 1120 bytes. Wrong lengths fail before BC
processing. Key-spec null arguments retain `NullPointerException`; other invalid
lengths and foreign context key types use `IllegalArgumentException`. Null or
wrong-length ciphertexts also use `IllegalArgumentException`. Fixed-length
persisted Base64 fields are bounded before decoding. Correctly sized modified
ML-KEM ciphertexts may yield a different secret through implicit rejection;
they are not guaranteed to throw. A committed independent draft vector verifies
decapsulation in addition to registry round-trips.

## Deliberate public BouncyCastle dependency

`ElgamalParamSpec.parameters()` publicly returns BC's `ElGamalParameterSpec`.
To preserve this supported signature, `lib` retains its Gradle `api` dependency
on BC 1.86 and re-exports `org.bouncycastle.provider` through JPMS. Classpath and
named-module consumers can compile against that return type. BC `pkix` and
`util` modules are not re-exported by JPMS. Other application modules must still
obey the source confinement gate; a transitive compile dependency is not permission
to introduce new provider-specific production APIs outside `lib`.

## Provider changes for PQ algorithms

The JCA provider name for ML-KEM (Kyber), CMCE (Classic McEliece), and
FrodoKEM changed from `BCPQC` to `BC` in BC 1.86. This change is handled
entirely inside the ZeroEcho library. No user-visible change is required.

Callers that constructed JCA objects directly by passing the provider name
`"BCPQC"` — for example `KeyPairGenerator.getInstance("…", "BCPQC")` — must
update the provider argument to `"BC"`. Callers who go through the ZeroEcho
key builder API are unaffected.

## ML-KEM specification class rename

The BouncyCastle internal class for ML-KEM (Kyber) parameter specifications
changed from `KyberParameterSpec` to `MLKEMParameterSpec`. This change is
absorbed inside the ZeroEcho library.

The ZeroEcho key builder API uses `KyberKeyGenSpec` (named for the
algorithm's pre-standardisation name) and the canonical identifier `"ML-KEM"`.
Neither the spec class name nor the canonical identifier has changed from the
caller's perspective.

## See also

- [Working with cryptography](../developer/cryptography.md) — canonical
  algorithm identifiers and key builder API.
- [Supported algorithm families table](../developer/cryptography.md#supported-algorithm-families) — current algorithm inventory.
