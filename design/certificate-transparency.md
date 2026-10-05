# Certificate Transparency — Design Specification

**Status:** Draft  
**Revision:** 1.0  
**Date:** 2026-09-30

---

## 1. Background and Mode Selection

### What is Certificate Transparency?

Certificate Transparency (CT) is a public auditing infrastructure for TLS certificates. Every time a certificate is issued, a cryptographic fingerprint of it (or of a pre-certificate) is submitted to a publicly accessible append-only log. Anyone — auditors, browser vendors, domain owners — can query these logs to verify that no certificate was issued without their knowledge.

CT comes in two variants that serve different purposes:

| Aspect | Private/Enterprise PKI | Public CA (browser-trusted) |
|---|---|---|
| Browser enforcement | Not required | Mandatory since 2018 |
| External log submission | Not needed | Required (≥ 2 logs) |
| Compliance / audit need | Internal journal | SCT embedding + external logs |
| ZeroEcho mode | **Mode A: CT Journal** | **Mode B: CT Log Client** |

### Decision gate

```
Is this CA expected to issue publicly trusted TLS certificates
(i.e., trusted by Chrome, Firefox, Safari, Edge without manual config)?
│
├─ YES → Mode B (CT Log Client) is required.
│        Mode A journal is still recommended alongside it.
│
└─ NO  → Mode A (CT Journal) suffices for internal audit and
         compliance requirements.
```

An operator may run both modes simultaneously — for example, a root CA that issues both internal private certs and publicly trusted intermediates.

---

## 2. Mode A: Internal CT Audit Journal

### 2.1 Purpose

The internal CT journal provides an **append-only, Merkle-chained log of every certificate ever issued by this ZeroEcho instance**. It enables:

- Auditor verification that no certificate was silently issued outside the normal workflow.
- Integrity verification: any tampering with the log is detectable without external dependencies.
- Offline forensics: find any certificate by fingerprint or serial number.

This is distinct from the existing `AuditSink` trail, which records administrative operations (who changed what configuration, who approved a request). The CT journal records only the cryptographic identity of each issued credential.

### 2.2 Data model

Each journal entry is a **Merkle leaf** with this structure:

```
CtJournalEntry {
    sequenceNumber : long          // monotonically increasing, 1-based
    timestamp      : Instant       // signing completion time
    certFingerprint: byte[32]      // SHA-256 of DER-encoded certificate
    serialNumber   : BigInteger    // certificate serial
    authorityId    : String        // issuing CA identifier
    previousHash   : byte[32]      // hash of previous entry (zeros for entry #1)
    leafHash       : byte[32]      // SHA-256(sequenceNumber || timestamp || certFingerprint)
    entryHash      : byte[32]      // SHA-256(previousHash || leafHash)
}
```

The `entryHash` at position `n` includes all earlier hashes transitively, making the chain tamper-evident. A verifier re-computes `leafHash` and `entryHash` for each entry and checks that `entry[n].previousHash == entry[n-1].entryHash`.

### 2.3 Storage

The CT journal is stored within the PKI store volume under a dedicated subdirectory: `$store_root/ct-journal/`. Each entry is written as a fixed-size binary record (256 bytes, zero-padded) to a flat sequential file `entries.bin`. A separate index file `index.bin` maps certificate fingerprints to sequence numbers for O(log n) lookups.

**Integration with the existing store**: The CT journal is **not** a `MetadataStore` entry — it requires append-only, positionally addressable I/O that the generic metadata store does not provide. It uses a dedicated `CtJournalStore` seam.

### 2.4 Write path

After a successful `credential.issue` operation, the issuer pipeline calls `CtJournalStore.append(CtJournalEntry)` as a **post-commit hook**, outside the main metadata transaction. The sequence is:

```
1. Credential record committed to MetadataStore (durable)
2. Signing WAL finalized
3. CtJournalStore.append(...) — separate fsync to ct-journal/entries.bin
4. AuditSink.record(CREDENTIAL_ISSUED) — existing audit event
```

If step 3 fails (e.g., disk full), the credential is already durably issued. The system retries journal append on next startup via a reconciliation scan that compares issued credentials in the metadata store against journal sequence numbers.

### 2.5 New SPI interface

```java
// zeroecho.pki.spi.ct.CtJournalStore
public interface CtJournalStore extends AutoCloseable {

    void append(CtJournalEntry entry) throws CtJournalException;

    CtJournalEntry lookup(byte[] certSha256) throws CtJournalException;

    long latestSequenceNumber();

    CtJournalVerificationResult verify(long fromSequence, long toSequence);

    @Override
    void close();
}
```

```java
// zeroecho.pki.spi.ct.CtJournalEntry  (record)
public record CtJournalEntry(
        long sequenceNumber,
        Instant timestamp,
        byte[] certFingerprint,
        java.math.BigInteger serialNumber,
        String authorityId,
        byte[] previousHash,
        byte[] leafHash,
        byte[] entryHash) { ... }
```

```java
// zeroecho.pki.spi.ct.CtJournalVerificationResult  (record)
public record CtJournalVerificationResult(
        long checkedFrom,
        long checkedTo,
        boolean intact,
        java.util.List<Long> brokenAtSequences) { ... }
```

### 2.6 Admin API operations

| Operation ID | Description |
|---|---|
| `ct.journal.status` | Return journal head sequence number, last entry timestamp, integrity-verified-at timestamp |
| `ct.journal.inspect` | Query entries by sequence range or certificate fingerprint |
| `ct.journal.verify` | Trigger integrity verification for a sequence range; returns `CtJournalVerificationResult` |
| `ct.journal.reconcile` | Find and re-append any issued credentials missing from the journal |

### 2.7 CLI

```
zeroecho pki ct journal status
zeroecho pki ct journal verify [--from N] [--to N]
zeroecho pki ct journal lookup --fingerprint <hex>
zeroecho pki ct journal reconcile
```

### 2.8 Configuration

```properties
# pki.properties
ct.journal.enabled=true
ct.journal.path=                    # defaults to $store_root/ct-journal
ct.journal.verify-on-startup=false  # full integrity check at startup (slow for large journals)
```

---

## 3. Mode B: CT Log Client

### 3.1 Purpose

When ZeroEcho acts as a publicly trusted CA (or issues certificates that must be trusted by browsers without manual configuration), every issued TLS certificate must carry **Signed Certificate Timestamps (SCTs)** from at least two CT logs recognized by the relevant browser programs (Chrome CT Policy, Apple CT Policy).

SCTs are obtained by submitting a **pre-certificate** to each CT log *before* the final certificate is signed. The CT log returns an SCT; the SCTs are embedded in the final certificate as an X.509 extension.

### 3.2 Pre-certificate flow (RFC 9162)

```
Request approved
       │
       ▼
┌──────────────────────────────────┐
│  1. Build TBSCertificate         │  (normal issuance path)
└──────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  2. Build pre-certificate        │
│  = TBSCertificate + poison ext   │  OID 1.3.6.1.4.1.11129.2.4.3
│    signed with issuer CA key     │
└──────────────────────────────────┘
       │
       ▼  (parallel)
┌──────────────────────────────────┐
│  3. Submit pre-cert to each      │
│     configured CT log            │
│     POST {log}/ct/v1/add-pre-chain│
│     → receive SCT per log        │
└──────────────────────────────────┘
       │  (require ≥ min-scts)
       ▼
┌──────────────────────────────────┐
│  4. Verify each SCT signature    │
│     against known CT log pubkey  │
└──────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  5. Embed SCTs in TBSCertificate │
│     as OID 1.3.6.1.4.1.11129.2.4.2│
│     (SCT List extension)         │
└──────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  6. Sign final certificate       │
│     (existing signing path)      │
└──────────────────────────────────┘
       │
       ▼
  Credential committed + CT Journal append (Mode A if enabled)
```

### 3.3 Pre-certificate construction

Pre-certificate construction modifies the TBSCertificate in a way that requires re-signing with the issuing CA. Since BouncyCastle is confined to `lib`, the `Pkix` facade must be extended:

```java
// Additions to zeroecho.pkix.Pkix in lib module

/**
 * Builds a pre-certificate from a TBSCertificate by adding the CT poison
 * extension (OID 1.3.6.1.4.1.11129.2.4.3) and signing it with the given signer.
 *
 * The returned bytes are the DER-encoded pre-certificate, ready for submission
 * to a CT log's add-pre-chain endpoint.
 *
 * @param tbsCertificate DER-encoded TBSCertificate (without poison extension)
 * @param issuerChainDer DER-encoded issuer certificate chain (issuer first)
 * @param signer configured signer for the issuing CA key
 * @return DER-encoded pre-certificate and its chain
 */
public static PreCertificateResult buildPreCertificate(
        byte[] tbsCertificate,
        List<byte[]> issuerChainDer,
        ContentSigner signer);

/**
 * Parses a Signed Certificate Timestamp from the JSON response body returned
 * by a CT log's add-pre-chain or add-chain endpoint.
 *
 * @param jsonResponseBody response body bytes
 * @return parsed SCT
 */
public static SignedCertificateTimestamp parseSct(byte[] jsonResponseBody);

/**
 * Verifies an SCT's digital signature against a known CT log public key.
 *
 * @param sct SCT to verify
 * @param ctLogPublicKey EC or RSA public key of the CT log
 * @param preCertDer DER-encoded pre-certificate that was submitted
 * @return true if the signature is valid
 */
public static boolean verifySct(
        SignedCertificateTimestamp sct,
        PublicKey ctLogPublicKey,
        byte[] preCertDer);

/**
 * Embeds a list of SCTs into a TBSCertificate as the SCT list extension
 * (OID 1.3.6.1.4.1.11129.2.4.2).
 *
 * @param tbsCertificate original DER-encoded TBSCertificate
 * @param scts verified SCTs to embed
 * @return modified DER-encoded TBSCertificate with SCT list extension added
 */
public static byte[] embedScts(
        byte[] tbsCertificate,
        List<SignedCertificateTimestamp> scts);
```

Supporting value types in `lib`:

```java
// zeroecho.pkix.ct.SignedCertificateTimestamp  (record)
public record SignedCertificateTimestamp(
        int version,             // 0 = v1, 1 = v2
        byte[] logId,            // 32-byte log ID (SHA-256 of log public key)
        Instant timestamp,
        byte[] extensions,       // raw extensions bytes
        String signatureAlgorithm, // e.g. "SHA256withECDSA"
        byte[] signature) { ... }

// zeroecho.pkix.ct.PreCertificateResult  (record)
public record PreCertificateResult(
        byte[] preCertDer,
        List<byte[]> chainDer) { ... }
```

### 3.4 CT log client SPI

CT log submission is modelled as a specialized `Publisher` variant rather than reusing the general `Publisher` SPI directly. The general publisher contract (`PublicationAttempt` with pre-computed SHA-256 commitments) is not well-suited to the synchronous round-trip required for SCT collection.

A dedicated SPI in `pki-server`:

```java
// zeroecho.pki.server.ct.CtLogClient
public interface CtLogClient extends AutoCloseable {

    /**
     * Returns the stable CT log identifier (SHA-256 of the log's public key, hex).
     */
    String logId();

    /**
     * Submits a pre-certificate and its issuer chain to the CT log.
     * Blocks until an SCT is received or the deadline elapses.
     *
     * @param preCert DER-encoded pre-certificate
     * @param chain   DER-encoded issuer chain (issuer first)
     * @param deadline submission deadline
     * @return received SCT
     * @throws CtSubmissionException if submission fails or times out
     */
    SignedCertificateTimestamp submit(
            byte[] preCert,
            List<byte[]> chain,
            Instant deadline) throws CtSubmissionException;

    @Override
    void close();
}
```

The default implementation (`HttpCtLogClient`) uses `java.net.http.HttpClient` with virtual threads. Each CT log endpoint is configured with its URL and DER-encoded public key.

### 3.5 Failure handling

CT log submission is **blocking** in Mode B: a public CA cannot issue a certificate without at least `ct.min-scts` valid SCTs. The failure modes are:

| Scenario | Behaviour |
|---|---|
| Log returns HTTP 5xx | Retry up to `ct.retry-count` times with exponential backoff |
| Deadline elapsed | Fail the issuance request with `CT_SUBMISSION_TIMEOUT` |
| SCT signature invalid | Discard SCT; count toward failed logs |
| Fewer than `min-scts` succeeded | Fail the issuance; no certificate committed |
| SCT embedding fails | Abort; no certificate committed |

Issuance failure due to CT submission does **not** consume a serial number or write to the metadata store. The request remains in `PENDING_CT` state and may be retried by the operator.

### 3.6 Integration into the issuance pipeline

A new `CtIssuanceInterceptor` participates in the credential issuance workflow between request approval and final signing:

```
CredentialIssuerBackend.issue(...)
    → CtIssuanceInterceptor.beforeSigning(request, tbsCert)
        → PreCertificateBuilder.build(tbsCert, chain, signerForCA)
        → CtLogSubmitter.submitAll(preCert, chain, configuredLogs, minScts, deadline)
        → SctVerifier.verifyAll(scts, logPublicKeys, preCert)
        → Pkix.embedScts(tbsCert, verifiedScts)
        → returns modified tbsCert
    → SigningProvider.dispatch(signRequest)   ← signs the SCT-bearing tbsCert
    → CtJournalStore.append(...)             ← Mode A journal (if enabled)
```

The `CtIssuanceInterceptor` is activated by the presence of `ct.log-client.enabled=true` in authority configuration. It is a no-op for authorities without CT configured.

### 3.7 CT log registry

Operators manage CT logs through the admin API. Log entries are stored in the PKI store's metadata under key prefix `ct.log.*`.

```java
// zeroecho.pki.api.ct.CtLogDescriptor  (record)
public record CtLogDescriptor(
        String logId,          // hex SHA-256 of log public key
        String baseUrl,        // e.g. "https://ct.googleapis.com/logs/argon2025/"
        byte[] publicKeyDer,   // DER-encoded EC or RSA public key
        boolean enabled,
        String description) { ... }
```

### 3.8 Admin API operations

| Operation ID | Description |
|---|---|
| `ct.log.list` | List all configured CT log endpoints |
| `ct.log.register` | Add a CT log endpoint (requires `logId`, `baseUrl`, `publicKeyDer`) |
| `ct.log.update` | Enable/disable or update a CT log endpoint |
| `ct.log.remove` | Remove a CT log endpoint (requires no pending submissions) |
| `ct.log.test` | Submit a test pre-certificate to verify connectivity |

### 3.9 Configuration

```properties
# Per-authority or global; per-authority overrides win

# Mode B: CT log client
ct.log-client.enabled=false
ct.min-scts=2
ct.submission-timeout-seconds=30
ct.retry-count=3
ct.retry-backoff-ms=500

# List of log IDs to use (must be registered via ct.log.register)
ct.log-ids=<logId1>,<logId2>,...

# Mode A: CT journal
ct.journal.enabled=true
ct.journal.path=
ct.journal.verify-on-startup=false
```

---

## 4. Module Placement

| Component | Module | Package |
|---|---|---|
| `CtJournalEntry`, `CtJournalVerificationResult` | `pki` | `zeroecho.pki.spi.ct` |
| `CtJournalStore` SPI | `pki` | `zeroecho.pki.spi.ct` |
| `FsCtJournalStore` (fs implementation) | `pki` | `zeroecho.pki.impl.fs.ct` |
| `CtJournalException` | `pki` | `zeroecho.pki.spi.ct` |
| `SignedCertificateTimestamp`, `PreCertificateResult` | `lib` | `zeroecho.pkix.ct` |
| `Pkix` additions (`buildPreCertificate`, `parseSct`, `verifySct`, `embedScts`) | `lib` | `zeroecho.pkix` |
| `CtLogDescriptor` | `pki` | `zeroecho.pki.api.ct` |
| `CtLogClient` SPI, `CtSubmissionException` | `pki-server` | `zeroecho.pki.server.ct` |
| `HttpCtLogClient` | `pki-server` | `zeroecho.pki.server.ct` |
| `CtIssuanceInterceptor`, `CtLogSubmitter` | `pki-server` | `zeroecho.pki.server.ct` |
| `SctVerifier` | `pki-server` | `zeroecho.pki.server.ct` |
| `PreCertificateBuilder` | `pki-server` | `zeroecho.pki.server.ct` |
| Admin API handlers for `ct.*` operations | `pki-server` | `zeroecho.pki.server.http.ct` |

The `pki` module must not depend on `pki-server`; the CT journal SPI and types belong in `pki`. The log client components are in `pki-server` because they require HTTP networking (Mode B is server-only; the CLI `pki` tool can inspect the journal but does not submit to external logs).

### module-info.java changes

`pki/src/main/java/module-info.java` — add:
```java
exports zeroecho.pki.spi.ct;
exports zeroecho.pki.api.ct;
```

`lib/src/main/java/module-info.java` — add:
```java
exports zeroecho.pkix.ct;
```

---

## 5. Security Considerations

### 5.1 SCT verification is mandatory

An SCT received from a CT log must be cryptographically verified against the log's own public key before being embedded in the final certificate. Embedding an unverified SCT would pass a malformed timestamp to relying parties. The `SctVerifier.verifyAll()` method must reject any SCT whose ECDSA or RSA signature does not verify, and must also reject SCTs with timestamps more than 10 minutes in the future.

### 5.2 Pre-certificate signing key

The pre-certificate is signed with the **same CA key** as the final certificate. The CA's private key never leaves the configured `SigningProvider`. `PreCertificateBuilder` calls `SigningProvider.dispatch()` for pre-certificate signing, the same as for the final certificate. This means two signing operations are consumed per certificate in Mode B.

### 5.3 Pre-certificate vs. final certificate identity

The pre-certificate and the final certificate must have **identical TBSCertificate content**, except:
- Pre-certificate: adds poison extension (critical, OID 1.3.6.1.4.1.11129.2.4.3, empty value)
- Final certificate: replaces poison extension with SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2)

Any other difference — subject, validity, SANs, serial — is a protocol violation. `CtIssuanceInterceptor` asserts structural equality before calling `Pkix.embedScts`.

### 5.4 CT log public key trust

CT log public keys are supplied by the operator out-of-band (e.g., from Google's known log list or the CA/B Forum list) and registered via `ct.log.register`. They must not be fetched automatically from the CT log itself, as this would allow a malicious log to supply a self-signed key and produce unverifiable SCTs.

### 5.5 Journal integrity

The CT journal's `entryHash` chain uses SHA-256. Verification is an O(n) scan. For very large journals (millions of entries), the `ct.journal.verify` admin operation accepts a `--from` / `--to` range to allow incremental verification. A startup integrity check covering the full journal is off by default (`ct.journal.verify-on-startup=false`) because it may take minutes.

---

## 6. Implementation Plan

### Phase 1 — CT Journal (Mode A) [M]
1. Add `zeroecho.pkix.ct.SignedCertificateTimestamp` and `PreCertificateResult` records to `lib`. **[S]**
2. Add `CtJournalEntry`, `CtJournalStore`, `CtJournalVerificationResult`, `CtJournalException` to `pki/spi/ct`. **[S]**
3. Implement `FsCtJournalStore` (sequential binary file + in-memory index). **[M]**
4. Wire `CtJournalStore.append()` as a post-commit hook in the issuance pipeline. **[S]**
5. Add reconciliation scan (startup + admin trigger). **[S]**
6. Add admin API operations `ct.journal.*` and CLI commands. **[S]**
7. Tests: journal append, verification, fingerprint lookup, reconciliation after simulated gap. **[M]**

*Phase 1 total: Medium. No external dependencies. Can be shipped independently.*

### Phase 2 — Pkix CT facade (lib) [M]
1. Implement `Pkix.buildPreCertificate()` — add poison extension, re-sign with BC internally. **[M]**
2. Implement `Pkix.parseSct()` — parse JSON response per RFC 9162 §A.1. **[S]**
3. Implement `Pkix.verifySct()` — verify ECDSA/RSA signature per RFC 9162 §4.8. **[M]**
4. Implement `Pkix.embedScts()` — encode SCT list extension per RFC 9162 §A.3. **[S]**
5. Unit tests with known CT log test vectors. **[M]**

*Phase 2 depends on: nothing outside lib. Can run in parallel with Phase 1.*

### Phase 3 — CT Log Client (Mode B) [L]
1. Implement `HttpCtLogClient` using `java.net.http.HttpClient` with virtual threads. **[M]**
2. Implement `CtLogSubmitter` (parallel submission, min-scts gating, retry with backoff). **[M]**
3. Implement `SctVerifier` using Phase 2 `Pkix.verifySct()`. **[S]**
4. Implement `PreCertificateBuilder` (calls `SigningProvider.dispatch()` for pre-cert signing). **[M]**
5. Implement `CtIssuanceInterceptor` and wire into `CredentialIssuerBackend`. **[M]**
6. Implement `CtLogDescriptor` storage in PKI metadata store. **[S]**
7. Add admin API operations `ct.log.*`. **[S]**
8. Integration tests: `SoftHSM2` or mock CT log server; verify SCT embedding in issued cert. **[L]**

*Phase 3 depends on: Phase 2 complete. Architect review recommended before starting (per owner note).*

### Phase 4 — Documentation and conformance **[S]**
1. Add CT section to `docs/pki-conformance-matrix.md`.
2. Add CT configuration reference to `docs/admin/`.
3. Add CT journal and Mode B to `docs/reference/`.

---

## 7. Open Questions (for architect review)

1. **Pre-certificate signing lanes**: Pre-cert signing consumes a signing lane, potentially halving issuance throughput in Mode B. Should pre-cert signing use a separate, lower-priority lane configuration?

2. **CT log list source of truth**: Should ZeroEcho support automatic import from the official CT log list JSON (at a Google/Apple URL) on operator request, or only manual registration? Automatic import reduces operator burden but introduces an external URL dependency that must be secured.

3. **`PENDING_CT` issuance state**: The request state machine needs a new `PENDING_CT` state to represent "approved, awaiting CT submission". This state must be durable — if the server restarts after approval but before CT submission, the request must resume from CT submission, not require re-approval.

4. **SCT storage**: SCTs received during issuance should be stored durably alongside the issued certificate record, both for audit purposes and to allow re-embedding without re-submission if the certificate is later re-packaged. This requires a small addition to the credential record schema.
