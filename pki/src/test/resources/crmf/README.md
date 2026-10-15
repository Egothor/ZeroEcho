# CRMF test requests

These public DER requests were generated for ZeroEcho by BouncyCastle 1.86's
`CertificateRequestMessageBuilder`, independently of the production CRMF parser.
They let the PKI module test real proof verification and issuance without importing
BouncyCastle. The requests use request ID 7 and an RSA-2048 test key.

| File | Subject | DNS SAN | Proof signature |
|---|---|---|---|
| `rsa2048-sha256.der` | `CN=leaf.example.test` | `leaf.example.test` | SHA256withRSA |
| `rsa2048-nosan.der` | `CN=Applicant` | absent | SHA256withRSA |
| `rsa2048-sha384.der` | `CN=Applicant` | absent | SHA384withRSA |

The generator is
`lib/src/test/java/zeroecho/pkix/cmp/CrmfRequestTest.java`, method
`emitsDeterministicPublicRequestFixtureForIndependentCoreTests`. It uses the
repository's Java 25 toolchain, `SunRsaSign` RSA generation and `SUN` SHA1PRNG seeded
with `{19, 42, 73, 11, 9, 31, 5}`. This reproducible key is solely test material;
no private-key fixture is stored.

From the repository root, regenerate build artifacts with:

```bash
./gradlew :lib:test --tests '*CrmfRequestTest.emitsDeterministicPublicRequestFixtureForIndependentCoreTests' --rerun-tasks
```

The generated requests are under `lib/build/generated/crmf-test-fixtures/`.
Generation does not replace these committed fixtures. Compare the generated DER
before deliberately updating a fixture. They are ZeroEcho-generated test assets
covered by the project's [source license](../../../../../LICENSE-source.txt).
