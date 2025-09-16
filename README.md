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


## Development Status

ZeroEcho is stable and actively maintained.  
Some subcomponents (such as steganography and script export) are provided with basic functionality while being moved out of the incubator stage. It is under evaluation whether they will remain integrated in the core library or become separate pluggable projects.  

The core cryptographic engine, context model, and CLI tools are production-ready, with a strong focus on **security, robustness, and maintainability**.

## Documentation

- [API is documented via Javadoc](https://www.egothor.org/javadoc/zeroecho/lib/) and complemented by [CLI usage examples](https://www.egothor.org/javadoc/zeroecho/app/).
- Some Javadoc sections are still being updated after recent structural changes.  
  If you encounter **discrepancies in examples or descriptions**, we welcome feedback and contributions to ensure clarity and correctness.


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
