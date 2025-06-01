# 🛡️ Falcon+MTL DNSSEC Demo

A proof-of-concept implementation showcasing the integration of the **Falcon post-quantum signature scheme** with a **Merkle Tree Ladder (MTL)** for efficient Key Signing Key (KSK) management in DNS Security Extensions (DNSSEC). This project demonstrates post-quantum secure generation, signing, and verification of DNS resource records (RRs) using **Falcon-256** and scalable KSK verification using Merkle trees.

---

## 📖 Overview

This demonstration includes four main components:

- `falconmtlKSK`: Generates a Merkle tree of KSKs and selects a specific KSK.
- `falconZSK`: Generates a Zone Signing Key (ZSK) and signs an A/AAAA/TXT RRset.
- `dnskey_sign`: Signs the DNSKEY RRset using the selected KSK.
- `resolver`: Verifies the Merkle tree, A/AAAA/TXT RRset signature, and DNSKEY RRset signature.

---

## ✨ Features

- 🔐 **Post-Quantum Security**: Uses [Falcon-256](https://falcon-sign.info/), a NIST-standard lattice-based signature scheme.
- 🌲 **Merkle Tree Ladder**: Efficient KSK verification using Merkle tree-based authentication paths.
- 📜 **DNSSEC Compliance**: Supports standard DNSSEC mechanisms for A/AAAA/TXT and DNSKEY RRsets.
- 🐞 **Debugging Support**: Verbose debug output for canonicalization, hashing, and signature verification.

---

## ⚙️ Prerequisites

Install the following dependencies:

- **GCC** (GNU Compiler Collection)
- **OpenSSL** (`libcrypto`)
  
Install on Ubuntu:
```bash
sudo apt-get install libssl-dev
```
# Falcon MTL DNSSEC - Installation and Usage Guide

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/indiainternetfoundation/pqc-dnssec/tree/side
cd falcon-mtl-dnssec
```

### 2. Ensure `libfalcon.a` and `falcon.h` Are Available
Place both in the project root, or update `-I` and `-L` paths during compilation accordingly.

### 3. Compile the Programs

```bash
gcc -o falconmtlKSK falconmtlKSK.c -I. -L. -lcrypto ./libfalcon.a
gcc -o falconZSK falconZSK.c -I. -L. -lcrypto ./libfalcon.a
gcc -o dnskey_sign dnskey_sign.c -I. -L. -lcrypto ./libfalcon.a
gcc -o resolver resolver.c -I. -L. -lcrypto ./libfalcon.a
```

### 4. Verify Executables
Ensure the binaries `falconmtlKSK`, `falconZSK`, `dnskey_sign`, and `resolver` exist in the current directory.

## 🧪 Usage

### 📄 RRset Configuration
Create a file named `rrset.conf` with your DNS RRset, for example:

```text
3600 IN A 192.0.2.1
3600 IN AAAA 2001:db8::1
3600 IN TXT "example text"
```

### ▶️ Run the Demo

```bash
# Clean up previous generated files
rm -f *.bin *.out

# Generate a Merkle tree with 8 KSKs and select key 0
./falconmtlKSK -n 8 -k 0

# Sign A/AAAA/TXT RRset for www.example.com
./falconZSK -o www.example.com. -t 3600 -f rrset.conf

# Sign DNSKEY RRset for example.com
./dnskey_sign -r example.com. -t 3600

# Verify everything
./resolver -o www.example.com. -f rrset.conf
```

## 📌 Command Options

### `falconmtlKSK`
- `-n <number>`: Number of KSKs (power of 2, e.g., 8).
- `-k <index>`: Index of selected KSK (0 to n-1).

**Outputs:** `ksk0_pubkey.bin`, `merkle_data.bin`, `timestamp.bin`

### `falconZSK`
- `-o <owner>`: Owner domain, e.g., `www.example.com.`
- `-t <ttl>`: Time to Live (e.g., 3600)
- `-f <file>`: RRset configuration file (e.g., `rrset.conf`)

**Outputs:** `zsk_pubkey.bin`, `zsk_privkey.bin`, `zsk_rrsig.out`

### `dnskey_sign`
- `-r <zone>`: Zone domain, e.g., `example.com.`
- `-t <ttl>`: TTL

**Output:** `dnskey_rrsig.out`

### `resolver`
- `-o <owner>`: Owner domain, e.g., `www.example.com.`
- `-f <file>`: RRset configuration file

**Verifies:** Merkle tree, A/AAAA/TXT RRset signature, and DNSKEY RRset signature.

## 📋 Example Output

```text
DNSSEC Resolver Verification for Falcon-256
==========================================

KSK Key Tag: [value]
ZSK Key Tag: [value]

Initial KSK: [hash]
Level 0 auth path: [hash]
Level 0 computed hash: [hash]
...
Expected Merkle root: [hash]

Merkle tree verification successful

Canonicalized RRset:
www.example.com 3600 IN A 192.0.2.1
www.example.com 3600 IN AAAA 2001:db8::1
www.example.com 3600 IN TXT "example text"

RRSIG rr_hash: [hash]
RRSIG signer_name: www.example.com

Loaded signature from zsk_rrsig.out: [Base64]

A/AAAA/TXT RRset signature verified successfully
A/AAAA/TXT RRset integrity check passed
DNSKEY RRset signature verified successfully
```

## 📂 File Descriptions

| File | Description |
|------|-------------|
| `falconmtlKSK.c` | Generates a Merkle tree of KSKs and selects one for signing. |
| `falconZSK.c` | Generates a ZSK and signs the A/AAAA/TXT RRset. |
| `dnskey_sign.c` | Signs the DNSKEY RRset using the selected KSK. |
| `resolver.c` | Verifies the Merkle tree and all RRset signatures. |
| `rrset.conf` | Sample DNS RRset configuration. |

## 🔧 Generated Files

| File | Description |
|------|-------------|
| `ksk0_pubkey.bin` | Selected KSK public key |
| `merkle_data.bin` | Merkle root and authentication paths |
| `timestamp.bin` | Signature timestamp |
| `zsk_pubkey.bin` | ZSK public key |
| `zsk_privkey.bin` | ZSK private key |
| `zsk_rrsig.out` | Signature over A/AAAA/TXT RRset |
| `dnskey_rrsig.out` | Signature over DNSKEY RRset |
