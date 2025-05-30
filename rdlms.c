#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>

#define N 24           // 192-bit hash (SHA-256 truncated)
#define P 18           // WOTS+ chain count (based on N and W)
#define H 6            // Merkle tree height => 2^H = 64 leaves
#define W 16           // Winternitz parameter => base-65536 encoding
#define LEAVES (1 << H)

// Simple pseudo-random data generator for demonstration
void generate_random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = rand() % 256;
}

// SHA-192 wrapper (first 24 bytes of SHA-256)
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N);  // truncate to 192 bits
}

// WOTS+ key structure
typedef struct {
    uint8_t sk[P][N];   // WOTS+ private key
    uint8_t pk[P][N];   // WOTS+ public key
} WOTS_Keypair;

// Generate WOTS+ public key from private key (65535 hash steps per chain)
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

// Hash all public key elements to derive Merkle leaf
void wots_pk_to_leaf(const uint8_t pk[P][N], uint8_t *leaf) {
    uint8_t buf[P * N];
    for (int i = 0; i < P; i++)
        memcpy(buf + i * N, pk[i], N);
    hash_sha192(buf, P * N, leaf);
}

// Build Merkle tree and authentication path
void build_merkle_tree(uint8_t leaves[LEAVES][N], uint8_t root[N], uint8_t auth_path[H][N], int target_leaf) {
    uint8_t tree[2 * LEAVES - 1][N];

    printf("\n[+] Building Merkle Tree...\n");

    // Bottom leaves
    for (int i = 0; i < LEAVES; i++) {
        memcpy(tree[LEAVES - 1 + i], leaves[i], N);
        printf("Leaf %2d: ", i);
        for (int j = 0; j < N; j++) printf("%02x", leaves[i][j]);
        printf("\n");
    }

    // Internal nodes
    for (int i = LEAVES - 2; i >= 0; i--) {
        uint8_t concat[2 * N];
        memcpy(concat, tree[2 * i + 1], N);
        memcpy(concat + N, tree[2 * i + 2], N);
        hash_sha192(concat, 2 * N, tree[i]);
    }

    memcpy(root, tree[0], N); // LMS public key

    // Build auth path
    int idx = LEAVES - 1 + target_leaf;
    for (int level = 0; level < H; level++) {
        int sibling = (idx % 2 == 0) ? idx - 1 : idx + 1;
        memcpy(auth_path[level], tree[sibling], N);
        idx = (idx - 1) / 2;
    }
}

// Print a buffer in hex
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    srand(42); // Seed RNG

    printf("================ WOTS+ with LMS Signature Demo ================\n\n");

    WOTS_Keypair keypairs[LEAVES];
    uint8_t leaves[LEAVES][N];

    printf("[+] Step 1: Generating 64 WOTS+ Keypairs and Corresponding Leaves...\n");
    for (int i = 0; i < LEAVES; i++) {
        for (int j = 0; j < P; j++) {
            generate_random_bytes(keypairs[i].sk[j], N);
        }
        wots_gen_pk(keypairs[i].sk, keypairs[i].pk);
        wots_pk_to_leaf(keypairs[i].pk, leaves[i]);
    }

    printf("\n[+] Step 2: Building Merkle Tree with Leaves\n");
    uint8_t merkle_root[N];
    uint8_t auth_path[H][N];
    int target = 0;
    build_merkle_tree(leaves, merkle_root, auth_path, target);

    print_hex("\n[+] Merkle Root (LMS Public Key)", merkle_root, N);

    printf("\n[+] Step 3: Preparing Message (WOTS Leaf PK + Sample ZSK)\n");

    // Sample ZSK DNSKEY text
    const char *sample_zsk = "DNSKEY 256 3 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

    // Combine WOTS PK and ZSK to sign
    uint8_t message[P * N + 128];
    size_t msg_len = 0;

    for (int i = 0; i < P; i++) {
        memcpy(message + msg_len, keypairs[target].pk[i], N);
        msg_len += N;
    }

    size_t zsk_len = strlen(sample_zsk);
    memcpy(message + msg_len, sample_zsk, zsk_len);
    msg_len += zsk_len;

    // Hash the message
    uint8_t message_digest[N];
    hash_sha192(message, msg_len, message_digest);
    print_hex("[+] Message Hash (SHA-192)", message_digest, N);

    printf("\n[+] Step 4: LMS Signature Components\n");

    // Output WOTS+ Signature
    printf("\nWOTS+ Signature (using sk[%d]):\n", target);
    for (int i = 0; i < P; i++) {
        printf("sig[%02d]: ", i);
        for (int j = 0; j < N; j++)
            printf("%02x", keypairs[target].sk[i][j]);
        printf("\n");
    }

    // Output Authentication Path
    printf("\nAuthentication Path from Leaf to Root:\n");
    for (int i = 0; i < H; i++) {
        char label[32];
        snprintf(label, sizeof(label), "Level %d", i);
        print_hex(label, auth_path[i], N);
    }

    print_hex("\nLMS Public Key (Merkle Root)", merkle_root, N);

    FILE *f = fopen("lms_signature.bin", "wb");
    if (!f) {
        perror("[-] Failed to open output file");
        return 1;
    }

    printf("\n[+] Saving Signature to lms_signature.bin...\n");

    // Save message digest
    fwrite(message_digest, 1, N, f);

    // Save WOTS+ signature (sk parts used as sig)
    for (int i = 0; i < P; i++) {
        fwrite(keypairs[target].sk[i], 1, N, f);
    }

    // Save authentication path
    for (int i = 0; i < H; i++) {
        fwrite(auth_path[i], 1, N, f);
    }

    // Save Merkle root (public key)
    fwrite(merkle_root, 1, N, f);

    fclose(f);
    printf("[+] Signature saved successfully.\n");


    printf("\n================ Signature Construction Complete ================\n");
    return 0;
}
