#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <math.h>

#define N 24           // 192-bit hash (SHA-192) for WOTS+ internals
#define P 18           // WOTS+ chain count
#define W 16           // Winternitz parameter (base-65536 encoding)
#define MAX_HEIGHT 10  // Maximum Merkle tree height (supports up to 2^10 leaves)

// WOTS+ key structure
typedef struct {
    uint8_t sk[P][N];   // WOTS+ private key (18 chains x 24 bytes)
    uint8_t pk[P][N];   // WOTS+ public key (18 chains x 24 bytes)
} WOTS_Keypair;

// SHA-192 (truncated SHA-256) for WOTS+ internals
void hash_sha192(const uint8_t *in, size_t inlen, uint8_t *out) {
    uint8_t full[32];
    SHA256(in, inlen, full);
    memcpy(out, full, N); // Truncate to 192 bits
}

// SHA-256 for Merkle tree and DS record (DNSSEC standard)
void sha256_hash(const uint8_t *input, size_t len, uint8_t output[32]) {
    SHA256(input, len, output);
}

// Hash pair for Merkle tree
void hash_pair(const uint8_t left[32], const uint8_t right[32], uint8_t output[32]) {
    uint8_t concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

// Convert to hex string
void to_hex(const uint8_t *input, size_t len, char *output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02x", input[i]);
    }
}

// Save data to binary file
void save_key(const uint8_t *key, size_t len, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s\n", filename);
        exit(1);
    }
    if (fwrite(key, 1, len, f) != len) {
        fprintf(stderr, "Failed to write %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
}

// Generate random bytes
void generate_random_bytes(uint8_t *buf, size_t len) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }
    for (size_t i = 0; i < len; i++) {
        buf[i] = rand() % 256;
    }
}

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

// Hash WOTS+ public key to Merkle leaf
void wots_pk_to_leaf(const uint8_t pk[P][N], uint8_t leaf[32]) {
    uint8_t buf[P * N];
    for (int i = 0; i < P; i++) {
        memcpy(buf + i * N, pk[i], N);
    }
    sha256_hash(buf, P * N, leaf); // Use SHA-256 for Merkle leaf
}

// Calculate DNSKEY key tag
uint16_t calculate_key_tag(const uint8_t *pubkey, size_t pubkey_len) {
    unsigned long sum = 0;
    uint8_t dnskey[2048];
    uint16_t flags = htons(257); // KSK
    uint8_t protocol = 3;
    uint8_t algorithm = 8; // Placeholder (adjust for WOTS+ in DNSSEC)
    size_t dnskey_len = 0;

    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, pubkey, pubkey_len);
    dnskey_len += pubkey_len;

    for (size_t i = 0; i < dnskey_len; i++) {
        if (i % 2 == 0) sum += (dnskey[i] << 8);
        else sum += dnskey[i];
    }
    sum += (sum >> 16) & 0xFFFF;
    return sum & 0xFFFF;
}

// Build Merkle tree and authentication path
void build_merkle_tree(uint8_t leaves[][32], int n, uint8_t root[32], uint8_t auth_path[][32], int target_leaf, int height) {
    int total_nodes = 2 * n - 1;
    uint8_t *tree = malloc(total_nodes * 32);
    if (!tree) {
        fprintf(stderr, "Failed to allocate memory for Merkle tree\n");
        exit(1);
    }

    // Copy leaves to bottom of tree
    for (int i = 0; i < n; i++) {
        memcpy(tree + (n - 1 + i) * 32, leaves[i], 32);
        char hex[65];
        to_hex(leaves[i], 32, hex);
        printf("Leaf %d: %s\n", i, hex);
    }

    // Build internal nodes
    for (int i = n - 2; i >= 0; i--) {
        hash_pair(tree + (2 * i + 1) * 32, tree + (2 * i + 2) * 32, tree + i * 32);
    }

    // Copy root
    memcpy(root, tree, 32);
    char root_hex[65];
    to_hex(root, 32, root_hex);
    printf("Merkle root: %s\n", root_hex);

    // Compute authentication path
    int idx = n - 1 + target_leaf;
    for (int level = 0; level < height; level++) {
        int sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
        memcpy(auth_path[level], tree + sibling * 32, 32);
        char path_hex[65];
        to_hex(auth_path[level], 32, path_hex);
        printf("Authentication path at level %d: %s\n", level, path_hex);
        idx = (idx - 1) / 2;
    }

    free(tree);
}

int main(int argc, char *argv[]) {
    printf("WOTS+ KSK Generation with Merkle Tree\n");
    printf("=====================================\n\n");

    // Parse arguments
    int n = 8, k = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atoi(argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            k = atoi(argv[i + 1]);
            i++;
        }
    }
    if (n < 1 || k < 0 || k >= n || (n & (n - 1)) != 0) {
        fprintf(stderr, "Invalid n=%d (must be power of 2) or k=%d\n", n, k);
        return 1;
    }

    // Compute Merkle tree height
    int height = (int)ceil(log2(n));
    if (height > MAX_HEIGHT) {
        fprintf(stderr, "Merkle tree height %d exceeds maximum %d\n", height, MAX_HEIGHT);
        return 1;
    }

    // Generate WOTS+ key pairs
    WOTS_Keypair *keypairs = malloc(n * sizeof(WOTS_Keypair));
    uint8_t (*leaves)[32] = malloc(n * 32);
    if (!keypairs || !leaves) {
        fprintf(stderr, "Failed to allocate memory for keypairs or leaves\n");
        free(keypairs);
        free(leaves);
        return 1;
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < P; j++) {
            generate_random_bytes(keypairs[i].sk[j], N);
        }
        wots_gen_pk(keypairs[i].sk, keypairs[i].pk);
        wots_pk_to_leaf(keypairs[i].pk, leaves[i]);
        uint16_t key_tag = calculate_key_tag(keypairs[i].pk[0], P * N);
        char leaf_hex[65];
        to_hex(leaves[i], 32, leaf_hex);
        printf("Key %d key tag: %u\n", i, key_tag);
        printf("Key %d public key hash: %s\n", i, leaf_hex);
    }

    // Build Merkle tree and authentication path
    uint8_t root[32];
    uint8_t (*auth_paths)[32] = malloc(height * 32);
    if (!auth_paths) {
        fprintf(stderr, "Failed to allocate memory for auth paths\n");
        free(keypairs);
        free(leaves);
        return 1;
    }
    build_merkle_tree(leaves, n, root, auth_paths, k, height);

    // Save selected KSK (public and private keys)
    char pub_filename[32], priv_filename[32];
    snprintf(pub_filename, sizeof(pub_filename), "ksk%d_pubkey_wots.bin", k);
    snprintf(priv_filename, sizeof(priv_filename), "ksk%d_privkey_wots.bin", k);
    save_key(keypairs[k].pk[0], P * N, pub_filename); // Save flattened public key
    save_key(keypairs[k].sk[0], P * N, priv_filename); // Save flattened private key
    printf("KSK keys saved to %s and %s\n", pub_filename, priv_filename);

    // Save Merkle data
    FILE *f = fopen("merkle_data_wots.bin", "wb");
    if (!f) {
        fprintf(stderr, "Failed to open merkle_data_wots.bin\n");
        free(keypairs);
        free(leaves);
        free(auth_paths);
        return 1;
    }
    fwrite(&n, sizeof(int), 1, f);
    fwrite(root, 1, 32, f);
    fwrite(auth_paths, 1, height * 32, f);
    fclose(f);
    printf("Merkle data saved to merkle_data_wots.bin\n");

    // Generate DS record
    uint8_t dnskey[2048];
    uint16_t flags = htons(257); // KSK
    uint8_t protocol = 3;
    uint8_t algorithm = 8; // Placeholder for WOTS+
    size_t dnskey_len = 0;
    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, keypairs[k].pk[0], P * N);
    dnskey_len += P * N;

    uint8_t ds_hash[32];
    sha256_hash(dnskey, dnskey_len, ds_hash);
    char ds_hex[65];
    to_hex(ds_hash, 32, ds_hex);
    printf("DS record (SHA-256): %s\n", ds_hex);

    // Save timestamp
    time_t now = time(NULL);
    f = fopen("timestamp_wots.bin", "wb");
    if (!f) {
        fprintf(stderr, "Failed to open timestamp_wots.bin\n");
        free(keypairs);
        free(leaves);
        free(auth_paths);
        return 1;
    }
    fwrite(&now, sizeof(time_t), 1, f);
    fclose(f);
    printf("Timestamp saved to timestamp_wots.bin\n");

    // Cleanup
    free(keypairs);
    free(leaves);
    free(auth_paths);

    return 0;
}