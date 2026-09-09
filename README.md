# ZeroEcho

<img src=ZeroEcho-logo.png width=20% align="right" />

*No Signal Is Ever Truly Silent: A Modular Toolkit for Covert, Resilient, and Future-Proof Communication*

**ZeroEcho** is a modular cryptographic toolkit designed to support secure, scriptable, and resilient data workflows — even in low-connectivity, offline, or constrained environments. Built with flexibility in mind, it enables developers, researchers, and advanced users to construct encryption pipelines using modern cryptographic algorithms and robust deployment models.

Whether you're working on secure file storage, encrypted communication, or privacy-focused data exchange, ZeroEcho offers a toolkit to build reliable, modern cryptographic workflows — with a focus on portability, future-proofing, and offline survivability.

**Key Features**

- Post-Quantum Cryptography (PQC)
    - Supports NIST-standardized algorithms like ML-KEM (Kyber)
    - Includes signature schemes such as SPHINCS+ for long-term integrity protection
    - Modular structure allows easy integration of additional post-quantum providers
    - Designed to protect against future quantum-based attacks

- Classic Cryptography
    - Full support for proven algorithms such as RSA, ECDSA, and Ed25519
    - Works seamlessly alongside PQC for hybrid deployments
    - Flexible signing and verification APIs for modern workflows
  
- Multi-Recipient Encryption and KEM
    - Encrypt a single payload for multiple recipients, each with their own key
    - No shared secrets or central authority required
    - Optional decoy data streams to enhance confidentiality and recipient privacy

- Offline and Indirect Deployment Workflows
    - Generate encrypted payloads entirely offline, suitable for air-gapped environments
    - Transfer via physical media (USB, SD card, etc.) with no online exposure
    - Optional script generation to automate upload or staging to public endpoints  
      (cloud drives, pastebins, file hosts, etc.)
    - Enables asynchronous or indirect delivery models where sender and receiver never
      need to be online at the same time

- Steganographic Embedding (Incubator)
    - Optionally embed ciphertext into common media formats: images, audio, video
    - Enables discreet transport of encrypted data over everyday channels
    - Currently in transition: may evolve into a standalone pluggable project

- CLI Tools & Keystore Management

## PKI administration CLI

The application distribution provides one synchronous PKI administration entry
point. Direct commands and JSON plans use the same typed backend operation
executor and one lifecycle-owned `PkiSession`:

```text
zeroecho pki --help
zeroecho pki configuration.validate --config pki-config.json
zeroecho pki run administration-plan.json --config pki-config.json --output json
```

The administration surface covers every administratively meaningful capability
implemented by the current backend: configuration validation; persisted profile
validation/import/inspection/activation; CA creation, inspection, listing, and
lifecycle transitions; strict CSR import and proof verification; credential
issuance and inspection; revocation inspection and bounded history/snapshot
presentation; signed status/CRL generation and inspection; and explicit
publication registration, processing, retry, reconciliation, inspection, and
listing. It also exposes immutable X.509 algorithm-binding listing, inspection,
and commitment validation. Presentation limits bound terminal output only; backend revocation and
publication cursors remain streaming and do not acquire an aggregate population
limit.

Plans are versioned JSON documents with ordered, uniquely named operations.
References use exact whole values from earlier successful steps. Plans support
only `FAIL_FAST` and `CONTINUE_INDEPENDENT`; they have no scripts, expressions,
loops, implicit retries, or rollback across already committed operations. Binary
artifacts and secrets are never emitted in terminal JSON.

Version-four session configuration enables capabilities explicitly. A signing
section selects one signature-workflow provider, one X.509 framework, a durable
signing algorithm and a finite signing deadline. It also configures the shared
bounded execution runtime with `laneCount`, `queueCapacity`,
`gracefulDrainSeconds`, and `forcedCancellationSeconds`; defaults are 16 lanes,
64 ready steps, 30 seconds of graceful drain, and 10 seconds of forced
cancellation. Providers that use a local
software keyring additionally select an environment variable supplying the
process-local unlock capability; remote providers need no local unlock. The lane
and queue values bound transient provider steps, not durable workflow lifetime;
pending durable operations retain no scheduler slot. The filesystem due-work
index separately bounds active signing workflows at 100,000; content-free
`EXPIRED` and `RETIRED` records remain in the bounded horizon-retention index.
Publisher entries select configured destinations independently, so publication
can be administered without enabling signing. Values of unlock variables,
private keys, and publisher credentials are never operation arguments or output.
Read-only version-one configurations remain valid and allocate neither signing
nor publisher capabilities.

X.509 algorithm identity is independent of its role-specific OID representation.
Published standard bindings remain sealed. ZeroEcho private assignments are
frozen below the Egothor PEN branch `1.3.6.1.4.1.31424.1.1`; explicitly enabled
deployer providers may contribute immutable bindings only below configuration-
authorized roots, including deployment-local arcs below
`1.3.6.1.4.1.31424.1.2`. Profiles default to standard-only mode and pin both a
binding ID and its semantic commitment when private mode is deliberately chosen.
Private-OID certificates and CRLs require matching binding and cryptographic
support at every relying party; generic PKI software may reject them.

```text
zeroecho pki algorithm.binding.list --limit 100 --config pki-config.json
zeroecho pki algorithm.binding.inspect --binding-id zeroecho.private.sphincs-plus-default.certificate-signature.v1 --config pki-config.json
zeroecho pki algorithm.binding.validate --config pki-config.json
```

The CLI and a future server share the same transport-neutral `PkiSession` and
typed operations; batch execution opens that service graph once. Backup and
import/export commands remain unavailable because the current backend has no
production service implementation for them.


## Development Status

ZeroEcho is stable and actively maintained.  
Some subcomponents (such as steganography and script export) are provided with basic functionality while being moved out of the incubator stage. It is under evaluation whether they will remain integrated in the core library or become separate pluggable projects.  

The core cryptographic engine, context model, and CLI tools are production-ready, with a strong focus on **security, robustness, and maintainability**.

## Documentation

- [API is documented via Javadoc](https://www.egothor.org/javadoc/zeroecho/lib/) and complemented by [CLI usage examples](https://www.egothor.org/javadoc/zeroecho/app/).
- Public and protected Java APIs are checked with strict doclint. If you encounter
  **discrepancies in examples or descriptions**, we welcome focused corrections.


## Ideal Use Cases

- Building secure backup and archive workflows  
- Sending encrypted messages across public platforms  
- Creating educational or research-grade cryptographic tools  
- Learning applied cryptography and encryption systems design  
- Exploring secure data transport in offline or limited-access environments

No deep programming experience is required to get started. Most features are available through intuitive CLI utilities and well-documented examples.

---

**🧭 Responsible Use Notice:** ZeroEcho is intended for lawful and ethical use only.
It is designed to support privacy, secure communication, academic research, and freedom of expression. The author does **not condone or support** the use of this software for any illegal or malicious activities, including but not limited to data theft, unauthorized surveillance evasion, or digital espionage.

Users are responsible for complying with all applicable laws and regulations in their jurisdiction. This is a tool for empowerment, not exploitation.
