#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "falcon.h"

// Falcon-512 constants
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)   // 897 bytes
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN) // 1281 bytes

void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        exit(1);
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        fprintf(stderr, "SHA-256 hash computation failed\n");
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    EVP_MD_CTX_free(ctx);
}

void hash_pair(const unsigned char left[32], const unsigned char right[32], unsigned char output[32]) {
    unsigned char concat[64];
    memcpy(concat, left, 32);
    memcpy(concat + 32, right, 32);
    sha256_hash(concat, 64, output);
}

uint16_t calculate_key_tag(const unsigned char *pubkey, size_t pubkey_len) {
    unsigned long sum = 0;
    unsigned char dnskey[2048];
    uint16_t flags = htons(257); // KSK
    uint8_t protocol = 3;
    uint8_t algorithm = 16;
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

void to_hex(const unsigned char *input, size_t len, char *output) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02x", input[i]);
    }
}

void save_key(const unsigned char *key, size_t len, const char *filename) {
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

/*void benchmark_ksk_generation(int n) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];

    for (int i = 0; i < n; i++) {
        unsigned char pubkey[FALCON512_PUBLIC_KEY_SIZE];
        unsigned char privkey[FALCON512_PRIVATE_KEY_SIZE];
        
        shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
        shake256_flip(&rng);

        if (falcon_keygen_make(&rng, FALCON_LOGN,
                             privkey, FALCON512_PRIVATE_KEY_SIZE,
                             pubkey, FALCON512_PUBLIC_KEY_SIZE,
                             tmp, sizeof(tmp)) != 0) {
            fprintf(stderr, "KSK generation failed\n");
            exit(1);
        }

        // Store the last generated key pair
        if (i == n-1) {
            memcpy(ksk_pubkey, pubkey, FALCON512_PUBLIC_KEY_SIZE);
            memcpy(ksk_privkey, privkey, FALCON512_PRIVATE_KEY_SIZE);
        }
    }
}*/

int main(int argc, char *argv[]) {
    printf("Falcon-512 KSK Generation with Merkle Tree\n");
    printf("==========================================\n\n");

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
    if (n < 1 || k < 0 || k >= n) {
        fprintf(stderr, "Invalid n=%d or k=%d\n", n, k);
        return 1;
    }

    // Generate keys
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);

    unsigned char pubkeys[8][FALCON512_PUBLIC_KEY_SIZE];
    unsigned char privkeys[8][FALCON512_PRIVATE_KEY_SIZE];
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];

    for (int i = 0; i < n; i++) {
        if (falcon_keygen_make(&rng, FALCON_LOGN,
                               privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                               pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                               tmp, sizeof(tmp)) != 0) {
            fprintf(stderr, "Failed to generate key %d\n", i);
            return 1;
        }
    }

    // Save key k
    char pub_filename[32], priv_filename[32];
    snprintf(pub_filename, sizeof(pub_filename), "ksk%d_pubkey.bin", k);
    snprintf(priv_filename, sizeof(priv_filename), "ksk%d_privkey.bin", k);
    save_key(pubkeys[k], FALCON512_PUBLIC_KEY_SIZE, pub_filename);
    save_key(privkeys[k], FALCON512_PRIVATE_KEY_SIZE, priv_filename);
    printf("KSK keys saved to %s and %s\n", pub_filename, priv_filename);

    // Compute key tags and hashes
    unsigned char pubkey_hashes[8][32];
    for (int i = 0; i < n; i++) {
        uint16_t key_tag = calculate_key_tag(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE);
        sha256_hash(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, pubkey_hashes[i]);
        char hash_hex[65];
        to_hex(pubkey_hashes[i], 32, hash_hex);
        printf("Key %d key tag: %u\n", i, key_tag);
        printf("Key %d public key hash: %s\n", i, hash_hex);
    }

    // Build Merkle tree
    unsigned char nodes[8][32];
    memcpy(nodes, pubkey_hashes, 8 * 32);

    unsigned char level[4][32];
    for (int i = 0; i < 4; i++) {
        hash_pair(nodes[2 * i], nodes[2 * i + 1], level[i]);
    }
    unsigned char level2[2][32];
    hash_pair(level[0], level[1], level2[0]);
    hash_pair(level[2], level[3], level2[1]);
    unsigned char root[32];
    hash_pair(level2[0], level2[1], root);

    char root_hex[65];
    to_hex(root, 32, root_hex);
    printf("Merkle root: %s\n", root_hex);

    // Compute authentication path for key k
    unsigned char auth_paths[3][32];
    int index = k;
    if (index % 2 == 0) {
        memcpy(auth_paths[0], nodes[index + 1], 32);
    } else {
        memcpy(auth_paths[0], nodes[index - 1], 32);
    }
    index /= 2;
    if (index % 2 == 0) {
        memcpy(auth_paths[1], level[index + 1], 32);
    } else {
        memcpy(auth_paths[1], level[index - 1], 32);
    }
    index /= 2;
    if (index % 2 == 0) {
        memcpy(auth_paths[2], level2[index + 1], 32);
    } else {
        memcpy(auth_paths[2], level2[index - 1], 32);
    }

    for (int i = 0; i < 3; i++) {
        char path_hex[65];
        to_hex(auth_paths[i], 32, path_hex);
        printf("Authentication path at level %d: %s\n", i, path_hex);
    }

    // Save Merkle data
    FILE *f = fopen("merkle_data.bin", "wb");
    if (!f) {
        fprintf(stderr, "Failed to open merkle_data.bin\n");
        return 1;
    }
    fwrite(&n, sizeof(int), 1, f);
    fwrite(root, 1, 32, f);
    fwrite(auth_paths, 1, 3 * 32, f);
    fclose(f);

    // Generate DS record
    unsigned char dnskey[2048];
    uint16_t flags = htons(257);
    uint8_t protocol = 3;
    uint8_t algorithm = 16;
    size_t dnskey_len = 0;
    memcpy(dnskey, &flags, 2);
    dnskey_len += 2;
    dnskey[dnskey_len++] = protocol;
    dnskey[dnskey_len++] = algorithm;
    memcpy(dnskey + dnskey_len, pubkeys[k], FALCON512_PUBLIC_KEY_SIZE);
    dnskey_len += FALCON512_PUBLIC_KEY_SIZE;

    unsigned char ds_hash[32];
    sha256_hash(dnskey, dnskey_len, ds_hash);
    char ds_hex[65];
    to_hex(ds_hash, 32, ds_hex);
    printf("DS record (SHA-256): %s\n", ds_hex);

    // Save timestamp
    time_t now = time(NULL);
    f = fopen("timestamp.bin", "wb");
    if (!f) {
        fprintf(stderr, "Failed to open timestamp.bin\n");
        return 1;
    }
    fwrite(&now, sizeof(time_t), 1, f);
    fclose(f);

    return 0;
}