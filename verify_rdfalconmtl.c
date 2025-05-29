#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "falcon.h"

#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)
#define FALCON512_SIGNATURE_SIZE FALCON_SIG_CT_SIZE(FALCON_LOGN)
#define MAX_LINE_LENGTH 256
#define HASH_SIZE 32
#define HEX_HASH_SIZE 64

// Forward declarations
void hash_to_string(const unsigned char *hash, size_t len, char *output);

// Structure to store parsed data
typedef struct {
    unsigned char pubkey_hashes[5][HASH_SIZE];
    unsigned char merkle_root[HASH_SIZE];
    unsigned char signature[FALCON512_SIGNATURE_SIZE];
    unsigned char auth_path[4][HASH_SIZE];
    int auth_path_valid[4];
    int auth_path_count;
} VerificationData;

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

// Convert hex string to binary
void hex_to_bin(const char *hex, unsigned char *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        sscanf(hex + (i * 2), "%02hhx", &bin[i]);
    }
}

// Convert hash to hex string
void hash_to_string(const unsigned char *hash, size_t len, char *output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[len * 2] = '\0';
}

// Parse the output file
int parse_output_file(const char *filename, VerificationData *data) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file %s\n", filename);
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    int keys_parsed = 0;
    data->auth_path_count = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        if (strstr(line, "Key ") && strstr(line, "PubKey Hash")) {
            int key_index;
            char hex_hash[HEX_HASH_SIZE + 1];
            if (sscanf(line, "Key %d PubKey Hash: %64s", &key_index, hex_hash) == 2) {
                if (key_index >= 0 && key_index < 5) {
                    hex_to_bin(hex_hash, data->pubkey_hashes[key_index], HASH_SIZE);
                    keys_parsed++;
                }
            }
        }
        else if (strstr(line, "Merkle Root: ")) {
            char hex_hash[HEX_HASH_SIZE + 1];
            if (sscanf(line, "Merkle Root: %64s", hex_hash) == 1) {
                hex_to_bin(hex_hash, data->merkle_root, HASH_SIZE);
            }
        }
        else if (strstr(line, "Signature (full): ")) {
            char hex_sig[FALCON512_SIGNATURE_SIZE * 2 + 1];
            if (sscanf(line, "Signature (full): %1332s", hex_sig) == 1) {
                hex_to_bin(hex_sig, data->signature, FALCON512_SIGNATURE_SIZE);
            }
        }
        else if (strstr(line, "Level ")) {
            int level;
            char hex_hash[HEX_HASH_SIZE + 1];
            if (sscanf(line, "Level %d: %64s", &level, hex_hash) == 2) {
                if (level >= 0 && level < 4) {
                    if (strcmp(hex_hash, "(no sibling)") != 0) {
                        hex_to_bin(hex_hash, data->auth_path[level], HASH_SIZE);
                        data->auth_path_valid[level] = 1;
                    } else {
                        data->auth_path_valid[level] = 0;
                    }
                    data->auth_path_count++;
                }
            }
        }
    }

    fclose(file);

    if (keys_parsed != 5) {
        fprintf(stderr, "Expected 5 public key hashes, found %d\n", keys_parsed);
        return 0;
    }

    printf("Parsed:\n- %d public key hashes\n- Merkle root\n- Signature\n- %d auth path levels\n",
           keys_parsed, data->auth_path_count);
    return 1;
}

// Verify the Merkle root computation
int verify_merkle_root(VerificationData *data) {
    printf("\nVerifying Merkle root...\n");
    
    unsigned char level0[5][HASH_SIZE];
    memcpy(level0, data->pubkey_hashes, sizeof(level0));

    // Level 1
    unsigned char level1[3][HASH_SIZE];
    hash_pair(level0[0], level0[1], level1[0]);
    hash_pair(level0[2], level0[3], level1[1]);
    memcpy(level1[2], level0[4], HASH_SIZE);

    // Level 2
    unsigned char level2[2][HASH_SIZE];
    hash_pair(level1[0], level1[1], level2[0]);
    memcpy(level2[1], level1[2], HASH_SIZE);

    // Root
    unsigned char computed_root[HASH_SIZE];
    hash_pair(level2[0], level2[1], computed_root);

    if (memcmp(computed_root, data->merkle_root, HASH_SIZE) != 0) {
        char computed_str[65], stored_str[65];
        hash_to_string(computed_root, HASH_SIZE, computed_str);
        hash_to_string(data->merkle_root, HASH_SIZE, stored_str);
        
        fprintf(stderr, "Merkle root mismatch!\nComputed: %s\nStored:   %s\n",
                computed_str, stored_str);
        return 0;
    }

    printf("Merkle root verified successfully\n");
    return 1;
}

// Verify the authentication path for Key 0
int verify_auth_path(VerificationData *data) {
    printf("\nVerifying auth path for Key 0...\n");
    
    if (data->auth_path_count < 3) {
        fprintf(stderr, "Insufficient auth path levels (%d/3)\n", data->auth_path_count);
        return 0;
    }

    unsigned char current_hash[HASH_SIZE];
    memcpy(current_hash, data->pubkey_hashes[0], HASH_SIZE);

    for (int level = 0; level < data->auth_path_count; level++) {
        if (data->auth_path_valid[level]) {
            unsigned char temp[HASH_SIZE];
            hash_pair(current_hash, data->auth_path[level], temp);
            memcpy(current_hash, temp, HASH_SIZE);
        }
    }

    if (memcmp(current_hash, data->merkle_root, HASH_SIZE) != 0) {
        char computed_str[65], stored_str[65];
        hash_to_string(current_hash, HASH_SIZE, computed_str);
        hash_to_string(data->merkle_root, HASH_SIZE, stored_str);
        
        fprintf(stderr, "Auth path verification failed!\nComputed: %s\nStored:   %s\n",
                computed_str, stored_str);
        return 0;
    }

    printf("Auth path verified successfully\n");
    return 1;
}

// Verify the signature (basic check)
int verify_signature(VerificationData *data) {
    printf("\nVerifying signature...\n");
    
    int all_zero = 1;
    for (int i = 0; i < FALCON512_SIGNATURE_SIZE; i++) {
        if (data->signature[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    
    if (all_zero) {
        fprintf(stderr, "Signature is all zeros (invalid)\n");
        return 0;
    }
    
    printf("Signature format appears valid\n");
    return 1;
}

int main() {
    printf("Falcon-512 Merkle Tree Verification\n");
    printf("==================================\n");

    VerificationData data = {0};

    if (!parse_output_file("merkle_falcon_outputs.txt", &data)) {
        fprintf(stderr, "\nVerification failed at parsing stage\n");
        return 1;
    }

    if (!verify_merkle_root(&data) || 
        !verify_auth_path(&data) ||
        !verify_signature(&data)) {
        fprintf(stderr, "\nVerification failed\n");
        return 1;
    }

    printf("\nAll verifications passed successfully!\n");
    return 0;
}
