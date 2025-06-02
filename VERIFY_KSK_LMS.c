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

// SHA-192 wrapper (first 24 bytes of SHA-256)
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N);
}

// Print hex data for debugging
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main() {
    // ZSK must match the signer
    const char *zsk = "DNSKEY 256 3 8 ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    size_t zsk_len = strlen(zsk);

    // Allocate arrays for signature components
    uint8_t signature[P][N];
    uint8_t auth_path[H][N];
    uint8_t merkle_root[N];
    uint8_t lm_ots_pk[P][N];

    // Read signature file
    FILE *f = fopen("lms_signature.bin", "rb");
    if (!f) {
        perror("Failed to open signature file");
        return 1;
    }
    for (int i = 0; i < P; i++)
        fread(signature[i], 1, N, f);
    for (int i = 0; i < H; i++)
        fread(auth_path[i], 1, N, f);
    fread(merkle_root, 1, N, f);
    for (int i = 0; i < P; i++)
        fread(lm_ots_pk[i], 1, N, f);
    fclose(f);

    printf("================ LMS Verifier Simulation ================\n\n");

    // Step 1: Reconstruct the message (LM-OTS PK || ZSK)
    printf("[+] Step 1: Reconstructing Message\n");
    size_t msg_len = P * N + zsk_len;
    uint8_t *message = malloc(msg_len);
    if (!message) {
        perror("Failed to allocate message buffer");
        return 1;
    }
    size_t offset = 0;
    for (int i = 0; i < P; i++) {
        memcpy(message + offset, lm_ots_pk[i], N);
        offset += N;
    }
    memcpy(message + offset, zsk, zsk_len);

    // Compute message digest
    uint8_t msg_digest[N];
    hash_sha192(message, msg_len, msg_digest);
    print_hex("Message Digest", msg_digest, N);

    // Step 2: Compute chunks and checksum
    printf("\n[+] Step 2: Computing Chunks and Checksum\n");
    uint16_t chunks[P];
    for (int i = 0; i < 12; i++) {
        chunks[i] = (msg_digest[2 * i] << 8) | msg_digest[2 * i + 1];
        printf("  chunk[%2d] = %04x\n", i, chunks[i]);
    }
    uint32_t checksum = 0;
    for (int i = 0; i < 12; i++) {
        checksum += (65535 - chunks[i]);
    }
    printf("Checksum: %08x\n", checksum);
    for (int i = 12; i < P; i++) {
        chunks[i] = checksum & 0xFFFF;
        printf("  chunk[%2d] = %04x\n", i, chunks[i]);
        checksum >>= 16;
    }

    // Step 3: Verify LM-OTS signature
    printf("\n[+] Step 3: Verifying LM-OTS Signature\n");
    for (int i = 0; i < P; i++) {
        uint8_t temp[N];
        memcpy(temp, signature[i], N);
        int iterations = 65535 - chunks[i];
        printf("  Verifying chain %2d (iterations=%5d): ", i, iterations);
        for (int j = 0; j < iterations; j++) {
            uint8_t temp2[N];
            hash_sha192(temp, N, temp2);
            memcpy(temp, temp2, N);
        }
        if (memcmp(temp, lm_ots_pk[i], N) != 0) {
            printf("FAILED\n");
            printf("  Expected: ");
            for (int k = 0; k < 3; k++) printf("%02x", lm_ots_pk[i][k]);
            printf("...\n");
            printf("  Got:      ");
            for (int k = 0; k < 3; k++) printf("%02x", temp[k]);
            printf("...\n");
            free(message);
            return 1;
        }
        printf("OK\n");
    }
    printf("LM-OTS Signature Verified\n");

    // Step 4: Verify Merkle tree path
    printf("\n[+] Step 4: Verifying Merkle Tree Path\n");
    // Compute leaf from LM-OTS public key
    uint8_t leaf[N];
    uint8_t buf[P * N];
    for (int i = 0; i < P; i++)
        memcpy(buf + i * N, lm_ots_pk[i], N);
    hash_sha192(buf, P * N, leaf);
    print_hex("Computed Leaf", leaf, N);

    // Recompute Merkle root using authentication path (leaf index 0)
    uint8_t current[N];
    memcpy(current, leaf, N);
    for (int level = 0; level < H; level++) {
        uint8_t concat[2 * N];
        memcpy(concat, current, N);          // Left child
        memcpy(concat + N, auth_path[level], N); // Right sibling
        hash_sha192(concat, 2 * N, current);
    }
    print_hex("Computed Root", current, N);
    print_hex("Provided Root", merkle_root, N);

    if (memcmp(current, merkle_root, N) == 0) {
        printf("Merkle Tree Path Verified\n");
        printf("\nSignature is VALID\n");
    } else {
        printf("Merkle Tree Verification Failed\n");
        printf("\nSignature is INVALID\n");
        free(message);
        return 1;
    }

    free(message);
    printf("\n================ LMS Verification Complete ================\n");
    return 0;
}