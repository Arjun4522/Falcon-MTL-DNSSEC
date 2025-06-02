#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

#define N 24           // 192-bit hash (SHA-256 truncated)
#define H 6            // Merkle tree height => 2^H = 64 leaves
#define LEAVES (1 << H)
#define W 16           // Winternitz parameter
#define P (8 * N / W + 4)  // Properly calculated P value (12 + 4)

// Simple pseudo-random data generator
void generate_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = rand() % 256;
}

// SHA-192 wrapper (first 24 bytes of SHA-256)
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N);
}

// LM-OTS key structure
typedef struct {
    uint8_t sk[P][N];   // LM-OTS+ private key
    uint8_t pk[P][N];   // LM-OTS+ public key
} WOTS_Keypair;

// Generate public key from private key (2^W - 1 hash steps)
void wots_gen_pk(const uint8_t sk[P][N], uint8_t pk[P][N]) {
    for (int i = 0; i < P; i++) {
        memcpy(pk[i], sk[i], N);
        for (int j = 0; j < 65535; j++) {
            uint8_t temp[N];
            hash_sha192(pk[i], N, temp);
            memcpy(pk[i], temp, N);
        }
    }
}

// Hash public key to derive Merkle leaf
void wots_pk_to_leaf(const uint8_t pk[P][N], uint8_t *leaf) {
    uint8_t buf[P * N];
    for (int i = 0; i < P; i++)
        memcpy(buf + i * N, pk[i], N);
    hash_sha192(buf, P * N, leaf);
}

// Build Merkle tree and authentication path
void build_merkle_tree(uint8_t leaves[LEAVES][N], uint8_t root[N], uint8_t auth_path[H][N], int target_leaf) {
    uint8_t tree[2 * LEAVES - 1][N];

    // Initialize leaves
    for (int i = 0; i < LEAVES; i++)
        memcpy(tree[LEAVES - 1 + i], leaves[i], N);

    // Build internal nodes
    for (int i = LEAVES - 2; i >= 0; i--) {
        uint8_t concat[2 * N];
        memcpy(concat, tree[2 * i + 1], N);
        memcpy(concat + N, tree[2 * i + 2], N);
        hash_sha192(concat, 2 * N, tree[i]);
    }

    memcpy(root, tree[0], N);  // Root = LMS public key

    // Build authentication path
    int idx = LEAVES - 1 + target_leaf;
    for (int level = 0; level < H; level++) {
        int sibling = (idx % 2 == 0) ? idx - 1 : idx + 1;
        memcpy(auth_path[level], tree[sibling], N);
        idx = (idx - 1) / 2;
    }
}

// Print hex data
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    srand(42);  // Seed RNG

    printf("================ LMS Signer Simulation for DNSSEC ================\n\n");

    WOTS_Keypair keypairs[LEAVES];
    uint8_t leaves[LEAVES][N];

    printf("[+] Step 1: Generating %d LM-OTS Keypairs (P=%d)\n", LEAVES, P);
       for (int i = 0; i < LEAVES; i++) {
        printf("\n--- Keypair %d ---\n", i);

        // Generate private key
        printf("Private Key (sk):\n");
        for (int j = 0; j < P; j++) {
            generate_random_bytes(keypairs[i].sk[j], N);
            printf("  sk[%2d]: ", j);
            for (int k = 0; k < 3; k++) printf("%02x", keypairs[i].sk[j][k]); // Show first 3 bytes
            printf("...\n");
        }

        // Generate public key
        wots_gen_pk(keypairs[i].sk, keypairs[i].pk);
        printf("\nPublic Key (pk):\n");
        for (int j = 0; j < P; j++) {
            printf("  pk[%2d]: ", j);
            for (int k = 0; k < 3; k++) printf("%02x", keypairs[i].pk[j][k]); // Show first 3 bytes
            printf("...\n");
        }
        // Create leaf
        wots_pk_to_leaf(keypairs[i].pk, leaves[i]);
        printf("\nLeaf Hash: ");
        for (int k = 0; k < 3; k++) printf("%02x", leaves[i][k]);
        printf("...\n");
    }

    printf("\n[+] Step 2: Building Merkle Tree\n");
    uint8_t merkle_root[N];
    uint8_t auth_path[H][N];
    int target = 0;
    build_merkle_tree(leaves, merkle_root, auth_path, target);
    print_hex("Merkle Root", merkle_root, N);

    printf("\n[+] Step 3: Preparing Message (LM-OTS PK + ZSK)\n");
    const char *sample_zsk = "DNSKEY 256 3 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    // Build message: LM-OTS PK || ZSK
    uint8_t message[P * N + 128];
    size_t msg_len = 0;
    for (int i = 0; i < P; i++) {
        memcpy(message + msg_len, keypairs[target].pk[i], N);
        msg_len += N;
    }
    size_t zsk_len = strlen(sample_zsk);
    memcpy(message + msg_len, sample_zsk, zsk_len);
    msg_len += zsk_len;

    // Hash message
    uint8_t msg_digest[N];
    hash_sha192(message, msg_len, msg_digest);
    print_hex("Message Digest", msg_digest, N);

        printf("\n[+] Step 4: Generating LM-OTS Signature\n");
    uint8_t signature[P][N];

    // Show message digest chunks
    printf("\nMessage Digest Chunks:\n");
    uint16_t chunks[P];
    for (int i = 0; i < 12; i++) {
        chunks[i] = (msg_digest[2*i] << 8) | msg_digest[2*i+1];
        printf("  chunk[%2d] = %04x\n", i, chunks[i]);
    }

    // Calculate checksum
    uint32_t checksum = 0;
    for (int i = 0; i < 12; i++)
        checksum += (65535 - chunks[i]);
    printf("\nChecksum: %08x\n", checksum);

    // Split checksum into chunks
    printf("Checksum Chunks:\n");
    for (int i = 12; i < P; i++) {
        chunks[i] = checksum & 0xFFFF;
        printf("  chunk[%2d] = %04x\n", i, chunks[i]);
        checksum >>= 16;
    }

    // Generate signature
    printf("\nSignature Elements:\n");
    for (int i = 0; i < P; i++) {
        memcpy(signature[i], keypairs[target].sk[i], N);
        printf("  sig[%2d] (iterations=%5d): ", i, chunks[i]);

        for (int j = 0; j < chunks[i]; j++) {
            uint8_t temp[N];
            hash_sha192(signature[i], N, temp);
            memcpy(signature[i], temp, N);
        }

        // Show first 3 bytes of signature element
        for (int k = 0; k < 3; k++) printf("%02x", signature[i][k]);
        printf("...\n");
    }

    printf("\n[+] Step 5: Saving Signature Components\n");
    FILE *f = fopen("lms_signature.bin", "wb");
    if (!f) {
        perror("[-] Failed to open file");
        return 1;
    }

    // Write signature components
    for (int i = 0; i < P; i++)
        fwrite(signature[i], 1, N, f);

    // Write authentication path
    for (int i = 0; i < H; i++)
        fwrite(auth_path[i], 1, N, f);

    // Write Merkle root
    fwrite(merkle_root, 1, N, f);


//  Write LM-OTS public key used in signing (so verifier has full context)
for (int i = 0; i < P; i++)
    fwrite(keypairs[target].pk[i], 1, N, f);
fclose(f);

    printf("[+] Signature saved to lms_signature.bin\n");

    printf("\n================ LMS Signature Complete ================\n");
    return 0;
}