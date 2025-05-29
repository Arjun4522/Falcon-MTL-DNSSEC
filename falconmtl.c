#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "falcon.h"

// Constants for Falcon-512 (logn=9)
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)   // 897 bytes
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN) // 1281 bytes
#define FALCON512_SIGNATURE_SIZE FALCON_SIG_CT_SIZE(FALCON_LOGN)    // 666 bytes
#define FALCON512_KEYGEN_TMP_SIZE FALCON_TMPSIZE_KEYGEN(FALCON_LOGN) // 15879 bytes
#define FALCON512_SIGNDYN_TMP_SIZE FALCON_TMPSIZE_SIGNDYN(FALCON_LOGN) // 39943 bytes

// Structure for Falcon key pair
typedef struct {
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    size_t pubkey_len;
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    size_t privkey_len;
} FalconKeyPair;

// Structure for Merkle Tree
typedef struct {
    unsigned char **levels;
    int *level_sizes;
    int levels_count;
} MerkleTree;

// SHA-256 hash function
void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, len);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}

// Hash a pair of hashes
void hash_pair(const unsigned char left[32], const unsigned char right[32], unsigned char output[32]) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

// Convert hash to hex string
void hash_to_string(const unsigned char *hash, size_t len, char *output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[len * 2] = '\0';
}

// Free Merkle tree memory
void free_merkle_tree(MerkleTree *tree) {
    if (!tree) return;
    for (int i = 0; i < tree->levels_count; i++) {
        free(tree->levels[i]);
    }
    free(tree->levels);
    free(tree->level_sizes);
    tree->levels = NULL;
    tree->level_sizes = NULL;
    tree->levels_count = 0;
}

// Generate Falcon-512 key pair
int falcon512_keygen(FalconKeyPair *keypair, int index) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = (unsigned char)index; // Make seed unique per index
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng); // Prepare for output mode

    unsigned char tmp[FALCON512_KEYGEN_TMP_SIZE];
    keypair->pubkey_len = FALCON512_PUBLIC_KEY_SIZE;
    keypair->privkey_len = FALCON512_PRIVATE_KEY_SIZE;

    int ret = falcon_keygen_make(&rng, FALCON_LOGN,
                                 keypair->privkey, keypair->privkey_len,
                                 keypair->pubkey, keypair->pubkey_len,
                                 tmp, sizeof(tmp));
    if (ret != 0) {
        fprintf(stderr, "Falcon key generation failed for index %d: %d\n", index, ret);
        return 0;
    }
    return 1;
}

// Sign data with Falcon-512
int falcon512_sign(const unsigned char *data, size_t data_len,
                   const unsigned char *privkey, size_t privkey_len,
                   unsigned char *signature, size_t *sig_len) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF; // Different seed for signing
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng); // Prepare for output mode

    unsigned char tmp[FALCON512_SIGNDYN_TMP_SIZE];
    *sig_len = FALCON512_SIGNATURE_SIZE;

    int ret = falcon_sign_dyn(&rng, signature, sig_len,
                              privkey, privkey_len,
                              data, data_len,
                              1, // Constant-time signing
                              tmp, sizeof(tmp));
    if (ret != 0) {
        fprintf(stderr, "Falcon signing failed: %d\n", ret);
        return 0;
    }
    return 1;
}

// Build Merkle tree from Falcon public keys
void build_merkle_tree_falcon512(FalconKeyPair *keypairs, int num_keys, MerkleTree *tree) {
    if (num_keys == 0) {
        tree->levels = NULL;
        tree->level_sizes = NULL;
        tree->levels_count = 0;
        return;
    }

    // Calculate tree levels
    int max_levels = 0;
    int n = num_keys;
    while (n > 1) {
        n = (n + 1) / 2;
        max_levels++;
    }
    max_levels++;

    tree->levels = malloc(max_levels * sizeof(unsigned char *));
    tree->level_sizes = malloc(max_levels * sizeof(int));
    tree->levels_count = max_levels;

    // Leaf level (hash each public key)
    tree->level_sizes[0] = num_keys;
    tree->levels[0] = malloc(num_keys * 32);
    for (int i = 0; i < num_keys; i++) {
        sha256_hash(keypairs[i].pubkey, keypairs[i].pubkey_len, tree->levels[0] + (i * 32));
    }

    // Build upper levels
    for (int level = 1; level < max_levels; level++) {
        int prev_count = tree->level_sizes[level - 1];
        int curr_count = (prev_count + 1) / 2;
        tree->level_sizes[level] = curr_count;
        tree->levels[level] = malloc(curr_count * 32);

        for (int i = 0; i < curr_count; i++) {
            int left_idx = 2 * i;
            int right_idx = 2 * i + 1;
            unsigned char *left = tree->levels[level - 1] + (left_idx * 32);

            if (right_idx < prev_count) {
                unsigned char *right = tree->levels[level - 1] + (right_idx * 32);
                hash_pair(left, right, tree->levels[level] + (i * 32));
            } else {
                memcpy(tree->levels[level] + (i * 32), left, 32);
            }
        }
    }
}

// Generate Merkle proof for a leaf
void generate_merkle_proof(MerkleTree *tree, int leaf_index, unsigned char *proof[]) {
    int idx = leaf_index;
    for (int level = 0; level < tree->levels_count - 1; level++) {
        int sibling_idx = idx ^ 1;
        if (sibling_idx < tree->level_sizes[level]) {
            proof[level] = tree->levels[level] + (sibling_idx * 32);
        } else {
            proof[level] = NULL;
        }
        idx /= 2;
    }
}

// Main workflow
void generate_and_sign_merkle_root() {
    const int num_keys = 5;
    FalconKeyPair keypairs[num_keys];
    MerkleTree tree = {0};

    // Generate key pairs
    printf("Generating %d Falcon-512 key pairs...\n", num_keys);
    for (int i = 0; i < num_keys; i++) {
        if (!falcon512_keygen(&keypairs[i], i)) {
            fprintf(stderr, "Key generation failed for key %d\n", i);
            free_merkle_tree(&tree);
            return;
        }
        unsigned char pubkey_hash[32];
        char pubkey_hash_str[65];
        sha256_hash(keypairs[i].pubkey, keypairs[i].pubkey_len, pubkey_hash);
        hash_to_string(pubkey_hash, 32, pubkey_hash_str);
        printf("Key %d: PubKey (hash) = %s\n", i, pubkey_hash_str);
    }

    // Build Merkle tree
    build_merkle_tree_falcon512(keypairs, num_keys, &tree);
    if (tree.levels_count == 0) {
        fprintf(stderr, "Merkle tree construction failed\n");
        return;
    }

    // Get Merkle root
    unsigned char *merkle_root = tree.levels[tree.levels_count - 1];
    char merkle_root_str[65];
    hash_to_string(merkle_root, 32, merkle_root_str);
    printf("\nMerkle Root: %s\n", merkle_root_str);

    // Sign root with keypair[4]
    unsigned char signature[FALCON512_SIGNATURE_SIZE];
    size_t sig_len;
    if (!falcon512_sign(merkle_root, 32,
                        keypairs[4].privkey, keypairs[4].privkey_len,
                        signature, &sig_len)) {
        fprintf(stderr, "Failed to sign Merkle root\n");
        free_merkle_tree(&tree);
        return;
    }

    // Convert signature to hex (first 32 bytes for readability)
    char sig_str[65];
    hash_to_string(signature, 32, sig_str);
    printf("\nSigned Root (Key 4):\nSignature (first 32 bytes of %zu): %s...\n", sig_len, sig_str);

    // Generate authentication path for key 0
    printf("\nAuthentication Path for Key 0:\n");
    unsigned char *proof[tree.levels_count - 1];
    generate_merkle_proof(&tree, 0, proof);

    for (int i = 0; i < tree.levels_count - 1; i++) {
        if (proof[i]) {
            char proof_str[65];
            hash_to_string(proof[i], 32, proof_str);
            printf("Level %d: %s\n", i, proof_str);
        } else {
            printf("Level %d: (no sibling)\n", i);
        }
    }

    // Cleanup
    free_merkle_tree(&tree);
}

int main() {
    printf("Falcon-512 Merkle Tree Demonstration\n");
    printf("===================================\n\n");
    generate_and_sign_merkle_root();
    return 0;
}