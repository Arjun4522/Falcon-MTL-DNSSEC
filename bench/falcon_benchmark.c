#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include "falcon.h"

// Falcon-512 constants
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN)
#define KEY_COUNT 8  // Fixed number of keys for rotation

// Timing utilities
double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

// Hash functions
void sha256_hash(const unsigned char *input, size_t len, unsigned char output[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) exit(1);
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, input, len) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
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
    uint16_t flags = htons(257);
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

// Benchmark plain Falcon with 8 keys
double benchmark_plain_falcon_8keys(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];
    
    double start_time = get_time();
    
    for (int iter = 0; iter < iterations; iter++) {
        unsigned char pubkeys[KEY_COUNT][FALCON512_PUBLIC_KEY_SIZE];
        unsigned char privkeys[KEY_COUNT][FALCON512_PRIVATE_KEY_SIZE];
        
        shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
        shake256_flip(&rng);
        
        for (int i = 0; i < KEY_COUNT; i++) {
            if (falcon_keygen_make(&rng, FALCON_LOGN,
                                 privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                                 pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                                 tmp, sizeof(tmp)) != 0) {
                fprintf(stderr, "Key generation failed at iteration %d, key %d\n", iter, i);
                exit(1);
            }
            calculate_key_tag(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE);
        }
    }
    
    double end_time = get_time();
    return end_time - start_time;
}

// Benchmark Falcon with Merkle Tree (8 keys)
double benchmark_falcon_merkle_8keys(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)];
    
    double start_time = get_time();
    
    for (int iter = 0; iter < iterations; iter++) {
        unsigned char pubkeys[KEY_COUNT][FALCON512_PUBLIC_KEY_SIZE];
        unsigned char privkeys[KEY_COUNT][FALCON512_PRIVATE_KEY_SIZE];
        unsigned char pubkey_hashes[KEY_COUNT][32];
        
        shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
        shake256_flip(&rng);
        
        for (int i = 0; i < KEY_COUNT; i++) {
            if (falcon_keygen_make(&rng, FALCON_LOGN,
                                 privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                                 pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                                 tmp, sizeof(tmp)) != 0) {
                fprintf(stderr, "Key generation failed at iteration %d, key %d\n", iter, i);
                exit(1);
            }
            sha256_hash(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, pubkey_hashes[i]);
            calculate_key_tag(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE);
        }
        
        // Build Merkle tree
        unsigned char root[32];
        unsigned char auth_paths[3][32]; // For 8 keys (log2(8)=3 levels)
        build_merkle_tree(pubkey_hashes, KEY_COUNT, root, auth_paths, 0);
    }
    
    double end_time = get_time();
    return end_time - start_time;
}

void build_merkle_tree(unsigned char pubkey_hashes[][32], int n, unsigned char *root, 
                      unsigned char auth_paths[][32], int target_key) {
    if (n != KEY_COUNT) {
        fprintf(stderr, "This implementation requires exactly %d keys\n", KEY_COUNT);
        exit(1);
    }
    
    // Level 0 (leaf level)
    unsigned char nodes[KEY_COUNT][32];
    memcpy(nodes, pubkey_hashes, KEY_COUNT * 32);
    
    // Level 1
    unsigned char level1[KEY_COUNT/2][32];
    for (int i = 0; i < KEY_COUNT/2; i++) {
        hash_pair(nodes[2*i], nodes[2*i+1], level1[i]);
    }
    
    // Level 2
    unsigned char level2[KEY_COUNT/4][32];
    hash_pair(level1[0], level1[1], level2[0]);
    hash_pair(level1[2], level1[3], level2[1]);
    
    // Root
    hash_pair(level2[0], level2[1], root);
    
    // Compute authentication path
    int index = target_key;
    if (index % 2 == 0) {
        memcpy(auth_paths[0], nodes[index+1], 32);
    } else {
        memcpy(auth_paths[0], nodes[index-1], 32);
    }
    index /= 2;
    
    if (index % 2 == 0) {
        memcpy(auth_paths[1], level1[index+1], 32);
    } else {
        memcpy(auth_paths[1], level1[index-1], 32);
    }
    index /= 2;
    
    if (index % 2 == 0) {
        memcpy(auth_paths[2], level2[index+1], 32);
    } else {
        memcpy(auth_paths[2], level2[index-1], 32);
    }
}

void analyze_memory_usage() {
    printf("\nMemory Usage Analysis (for %d keys):\n", KEY_COUNT);
    printf("==================================\n");
    
    size_t plain_memory = KEY_COUNT * (FALCON512_PUBLIC_KEY_SIZE + FALCON512_PRIVATE_KEY_SIZE);
    printf("Plain Falcon: %zu bytes (%.2f KB)\n", plain_memory, plain_memory/1024.0);
    
    size_t merkle_memory = plain_memory + 
                          (KEY_COUNT * 32) +    // Hashes
                          (3 * 32) +            // Auth paths (for 8 keys)
                          32;                   // Root
    printf("Merkle Tree: %zu bytes (%.2f KB)\n", merkle_memory, merkle_memory/1024.0);
    printf("Overhead: %zu bytes (%.2fx)\n", merkle_memory-plain_memory, 
          (double)merkle_memory/plain_memory);
}

void analyze_security() {
    printf("\nSecurity Analysis:\n");
    printf("==================\n");
    printf("Plain Falcon (%d keys):\n", KEY_COUNT);
    printf("  Each key: ~128-bit quantum-resistant\n");
    printf("  Overall: %d independent 128-bit keys\n", KEY_COUNT);
    
    printf("\nMerkle Tree (%d keys):\n", KEY_COUNT);
    printf("  Falcon security: same as plain\n");
    printf("  Tree security: SHA-256 (~128-bit classical, ~64-bit quantum)\n");
    printf("  Combined security: min(Falcon, SHA-256) = ~64-bit quantum\n");
    printf("  Authentication path size: %d hashes\n", (int)ceil(log2(KEY_COUNT)));
}

void run_benchmarks() {
    const int iterations = 100;
    printf("Falcon-512 Benchmark (%d Key Rotation Scenario)\n", KEY_COUNT);
    printf("===============================================\n");
    printf("Configuration:\n");
    printf("- Iterations: %d\n", iterations);
    printf("- Keys per iteration: %d\n", KEY_COUNT);
    printf("- Total keys generated: %d\n\n", iterations * KEY_COUNT);
    
    printf("Benchmarking plain Falcon with %d keys...\n", KEY_COUNT);
    double plain_time = benchmark_plain_falcon_8keys(iterations);
    double plain_per_key = plain_time / (iterations * KEY_COUNT) * 1000;
    
    printf("Benchmarking Falcon with Merkle Tree (%d keys)...\n", KEY_COUNT);
    double merkle_time = benchmark_falcon_merkle_8keys(iterations);
    double merkle_per_key = merkle_time / (iterations * KEY_COUNT) * 1000;
    
    printf("\nBenchmark Results:\n");
    printf("============================\n");
    printf("Plain Falcon:\n");
    printf("  Total time: %.3f seconds\n", plain_time);
    printf("  Average per key: %.3f ms\n", plain_per_key);
    printf("  Keys per second: %.1f\n", (iterations * KEY_COUNT) / plain_time);
    
    printf("\nMerkle Tree:\n");
    printf("  Total time: %.3f seconds\n", merkle_time);
    printf("  Average per key: %.3f ms\n", merkle_per_key);
    printf("  Keys per second: %.1f\n", (iterations * KEY_COUNT) / merkle_time);
    
    printf("\nComparison:\n");
    printf("  Merkle overhead per key: %.2fx\n", merkle_per_key / plain_per_key);
    printf("  Additional time per key: +%.3f ms\n", merkle_per_key - plain_per_key);
    
    analyze_memory_usage();
    analyze_security();
}

int main() {
    run_benchmarks();
    printf("\nBenchmark completed!\n");
    return 0;
}