# Falcon-512 Merkle Tree Demonstration

## Overview

This project demonstrates the integration of the Falcon-512 post-quantum cryptographic signature scheme with a Merkle Tree structure. The program:

- Generates 5 Falcon-512 key pairs
- Constructs a Merkle Tree using the SHA-256 hashes of the public keys as leaves
- Signs the Merkle root using one of the Falcon key pairs
- Generates an authenticated path for a selected leaf node

The implementation uses the official Falcon library for cryptographic operations and OpenSSL for SHA-256 hashing.

---

## Features

- Generates 5 Falcon-512 key pairs (`logn = 9`) using the Falcon library.
- Builds a Merkle Tree with the SHA-256 hashes of the public keys as leaves.
- Signs the Merkle root using the private key of key pair 4.
- Outputs:
  - Public key hashes
  - Merkle root
  - Signature (first 32 bytes shown for readability)
  - Authenticated path for key 0
- Uses non-deterministic randomness for secure key generation and signing (configurable).

---

## Dependencies

- **Falcon Library**: Download the official Falcon implementation from [falcon-sign.info](https://falcon-sign.info). Required files include:
  - `falcon.h`
  - `falcon.c`
  - Additional support files: `inner.h`, `fpr.h`, `codec.c`, etc.
- **OpenSSL**: For SHA-256 hashing.
  - Ubuntu: `sudo apt-get install libssl-dev`
  - macOS: `brew install openssl`
- **C Compiler**: `gcc` or any compatible compiler.

---

## Files

- `falconmtl.c`: Main program implementing the Falcon-512 Merkle Tree demonstration.
- `falcon.h`: Header file for the Falcon library.
- `falcon.c`: Source file for the Falcon library.
- Other Falcon support files: `inner.h`, `fpr.h`, `codec.c`, etc.

---

## Compilation

Ensure all Falcon library files are in the same directory as `falconmtl.c`.

```bash
gcc -o falconmtl falconmtl.c falcon.c -I. -L. -lssl -lcrypto -lm
