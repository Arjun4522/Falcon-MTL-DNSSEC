#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include "falcon.h"

// Falcon-512 constants
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)   // 897 bytes
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN) // 1281 bytes
#define FALCON512_KEYGEN_TMP_SIZE FALCON_TMPSIZE_KEYGEN(FALCON_LOGN) // 15879 bytes

typedef struct {
    unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
    size_t pubkey_len;
    unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
    size_t privkey_len;
} FalconKeyPair;

void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, len);
    EVP_DigestFinal_ex(ctx, output, NULL);
    EVP_MD_CTX_free(ctx);
}

void hash_pair(const unsigned char left[32], const unsigned char right[32], unsigned char output[32]) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

int falcon512_keygen(FalconKeyPair *keypair, int index) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = (unsigned char)index;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

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

void save_key(const unsigned char *key, size_t key_len, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        exit(1);
    }
    if (fwrite(key, 1, key_len, f) != key_len) {
        fprintf(stderr, "Failed to write to %s\n", filename);
        fclose(f);
        exit(1);
    }
    fclose(f);
}

uint16_t calculate_key_tag(const unsigned char *pubkey, size_t pubkey_len, int is_ksk) {
    unsigned long sum = 0;
    unsigned char dnskey[2048];
    uint16_t flags = is_ksk ? 257 : 256; // KSK or ZSK
    uint8_t protocol = 3; // DNSSEC
    uint8_t algorithm = 16; // Falcon-512
    size_t dnskey_len = 0;

    flags = htons(flags);
    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, pubkey, pubkey_len);
    dnskey_len += pubkey_len;

    for (size_t i = 0; i < dnskey_len; i++) {
        if (i % 2 == 0) {
            sum += (dnskey[i] << 8);
        } else {
            sum += dnskey[i];
        }
    }
    sum += (sum >> 16) & 0xFFFF;
    return sum & 0xFFFF;
}

void build_merkle_tree_falcon512(FalconKeyPair *keypairs, int num_keys,
                                 unsigned char *root, unsigned char *auth_paths, int ksk_index) {
    unsigned char hashes[num_keys][32];
    for (int i = 0; i < num_keys; i++) {
        sha256_hash(keypairs[i].pubkey, keypairs[i].pubkey_len, hashes[i]);
    }

    int level_size = num_keys;
    unsigned char *current_level = malloc(level_size * 32);
    memcpy(current_level, hashes, level_size * 32);
    int auth_path_offset = 0;
    int pos = ksk_index;

    while (level_size > 1) {
        int new_size = (level_size + 1) / 2;
        unsigned char *next_level = malloc(new_size * 32);
        for (int i = 0; i < level_size; i += 2) {
            if (i + 1 < level_size) {
                hash_pair(current_level + i * 32, current_level + (i + 1) * 32, next_level + (i / 2) * 32);
                if (i == (pos & ~1)) {
                    memcpy(auth_paths + auth_path_offset, current_level + (i + (pos & 1 ? 0 : 1)) * 32, 32);
                    auth_path_offset += 32;
                }
            } else {
                memcpy(next_level + (i / 2) * 32, current_level + i * 32, 32);
            }
        }
        free(current_level);
        current_level = next_level;
        level_size = new_size;
        pos /= 2;
    }
    memcpy(root, current_level, 32);
    free(current_level);
}

void generate_merkle_proof(const unsigned char *auth_paths, int num_levels) {
    for (int level = 0; level < num_levels; level++) {
        unsigned char hash[32];
        memcpy(hash, auth_paths + level * 32, 32);
        printf("Authentication path at level %d: ", level);
        for (int i = 0; i < 32; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    int num_keys = 8;
    int ksk_index = 0;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            num_keys = atoi(argv[++i]);
            if (num_keys < 1 || num_keys > 256) {
                fprintf(stderr, "Invalid number of keys: %d\n", num_keys);
                return 1;
            }
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            ksk_index = atoi(argv[++i]);
            if (ksk_index < 0) {
                fprintf(stderr, "Invalid KSK index: %d\n", ksk_index);
                return 1;
            }
        } else {
            fprintf(stderr, "Usage: %s [-n <num_keys>] [-k <ksk_index>]\n", argv[0]);
            return 1;
        }
    }

    if (ksk_index >= num_keys) {
        fprintf(stderr, "KSK index %d exceeds number of keys %d\n", ksk_index, num_keys);
        return 1;
    }

    FalconKeyPair *keypairs = malloc(num_keys * sizeof(FalconKeyPair));
    for (int i = 0; i < num_keys; i++) {
        if (!falcon512_keygen(&keypairs[i], i)) {
            fprintf(stderr, "Key generation failed for index %d\n", i);
            free(keypairs);
            return 1;
        }
    }

    // Save timestamp
    time_t now = time(NULL);
    FILE *f = fopen("timestamp.bin", "wb");
    if (!f || fwrite(&now, sizeof(time_t), 1, f) != 1) {
        fprintf(stderr, "Failed to write timestamp.bin\n");
        free(keypairs);
        return 1;
    }
    fclose(f);

    // Save KSK
    char pubkey_file[32], privkey_file[32];
    snprintf(pubkey_file, sizeof(pubkey_file), "ksk%d_pubkey.bin", ksk_index);
    snprintf(privkey_file, sizeof(privkey_file), "ksk%d_privkey.bin", ksk_index);
    save_key(keypairs[ksk_index].pubkey, keypairs[ksk_index].pubkey_len, pubkey_file);
    save_key(keypairs[ksk_index].privkey, keypairs[ksk_index].privkey_len, privkey_file);
    printf("KSK keys saved to %s and %s\n", pubkey_file, privkey_file);

    // Compute key tags
    for (int i = 0; i < num_keys; i++) {
        uint16_t key_tag = calculate_key_tag(keypairs[i].pubkey, keypairs[i].pubkey_len, i == ksk_index);
        printf("Key %d key tag: %u\n", i, key_tag);
    }

    int num_levels = 0;
    for (int n = num_keys; n > 1; n = (n + 1) / 2) num_levels++;
    unsigned char *auth_paths = malloc(32 * num_levels);
    unsigned char root[32];
    build_merkle_tree_falcon512(keypairs, num_keys, root, auth_paths, ksk_index);

    for (int i = 0; i < num_keys; i++) {
        unsigned char hash[32];
        sha256_hash(keypairs[i].pubkey, keypairs[i].pubkey_len, hash);
        printf("Key %d public key hash: ", i);
        for (int j = 0; j < 32; j++) {
            printf("%02x", hash[j]);
        }
        printf("\n");
    }

    printf("Merkle root: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", root[i]);
    }
    printf("\n");

    generate_merkle_proof(auth_paths, num_levels);

    // Generate DS record
    unsigned char root_hash[32];
    sha256_hash(root, 32, root_hash);
    printf("DS record (SHA-256): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", root_hash[i]);
    }
    printf("\n");

    free(auth_paths);
    free(keypairs);
    return 0;
}