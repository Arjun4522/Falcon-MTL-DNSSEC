#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "falcon.h"

// Falcon-512 constants
#define FALCON_LOGN 9
#define FALCON512_PUBLIC_KEY_SIZE FALCON_PUBKEY_SIZE(FALCON_LOGN)
#define FALCON512_PRIVATE_KEY_SIZE FALCON_PRIVKEY_SIZE(FALCON_LOGN)
#define KEY_COUNT 8  // Fixed number of keys for rotation

// Pre-computed constants
static const uint16_t DNS_FLAGS = 257;  // Already in host byte order for calculation
static const uint8_t DNS_PROTOCOL = 3;
static const uint8_t DNS_ALGORITHM = 16;

// Memory alignment for better cache performance
#define CACHE_LINE_SIZE 64
#define ALIGN_TO_CACHE_LINE __attribute__((aligned(CACHE_LINE_SIZE)))

// Pre-allocated global buffers to avoid repeated allocations
static unsigned char g_tmp_keygen[FALCON_TMPSIZE_KEYGEN(FALCON_LOGN)] ALIGN_TO_CACHE_LINE;
static EVP_MD_CTX *g_sha_ctx = NULL;

// Timing utilities
static inline double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec * 1e-6;
}

// Optimized hash functions using OpenSSL's direct SHA-256 API
static inline void sha256_hash_fast(const unsigned char *input, size_t len, unsigned char output[32]) {
    SHA256(input, len, output);
}

static inline void hash_pair_fast(const unsigned char left[32], const unsigned char right[32], unsigned char output[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, left, 32);
    SHA256_Update(&ctx, right, 32);
    SHA256_Final(output, &ctx);
}

// Optimized key tag calculation with reduced memory operations
static inline uint16_t calculate_key_tag_fast(const unsigned char *pubkey, size_t pubkey_len) {
    unsigned long sum = 0;
    
    // Add flags (already in correct byte order for sum)
    sum += DNS_FLAGS << 8;
    // Add protocol and algorithm
    sum += DNS_PROTOCOL << 8;
    sum += DNS_ALGORITHM;
    
    // Process public key data efficiently
    const unsigned char *ptr = pubkey;
    size_t remaining = pubkey_len;
    
    // Process in 16-bit chunks for better performance
    while (remaining >= 2) {
        sum += (ptr[0] << 8) + ptr[1];
        ptr += 2;
        remaining -= 2;
    }
    
    // Handle odd byte if any
    if (remaining) {
        sum += ptr[0] << 8;
    }
    
    // Fold carry bits
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    
    return (uint16_t)sum;
}

// Initialize global resources
void init_global_resources() {
    g_sha_ctx = EVP_MD_CTX_new();
    if (!g_sha_ctx) {
        fprintf(stderr, "Failed to create SHA context\n");
        exit(1);
    }
}

void cleanup_global_resources() {
    if (g_sha_ctx) {
        EVP_MD_CTX_free(g_sha_ctx);
        g_sha_ctx = NULL;
    }
}

// Optimized Merkle tree construction with reduced memory operations
void build_merkle_tree_fast(unsigned char pubkey_hashes[][32], int n, unsigned char *root, 
                           unsigned char auth_paths[][32], int target_key) {
    if (n != KEY_COUNT) {
        fprintf(stderr, "This implementation requires exactly %d keys\n", KEY_COUNT);
        exit(1);
    }
    
    // Use stack allocation for intermediate nodes (better cache locality)
    unsigned char level1[KEY_COUNT/2][32] ALIGN_TO_CACHE_LINE;
    unsigned char level2[KEY_COUNT/4][32] ALIGN_TO_CACHE_LINE;
    
    // Level 1 - compute in parallel-friendly order
    hash_pair_fast(pubkey_hashes[0], pubkey_hashes[1], level1[0]);
    hash_pair_fast(pubkey_hashes[2], pubkey_hashes[3], level1[1]);
    hash_pair_fast(pubkey_hashes[4], pubkey_hashes[5], level1[2]);
    hash_pair_fast(pubkey_hashes[6], pubkey_hashes[7], level1[3]);
    
    // Level 2
    hash_pair_fast(level1[0], level1[1], level2[0]);
    hash_pair_fast(level1[2], level1[3], level2[1]);
    
    // Root
    hash_pair_fast(level2[0], level2[1], root);
    
    // Optimized authentication path computation
    int index = target_key;
    
    // Level 0 sibling
    memcpy(auth_paths[0], pubkey_hashes[index ^ 1], 32);
    index >>= 1;
    
    // Level 1 sibling
    memcpy(auth_paths[1], level1[index ^ 1], 32);
    index >>= 1;
    
    // Level 2 sibling
    memcpy(auth_paths[2], level2[index ^ 1], 32);
}

// Optimized benchmark with reduced allocations and better memory layout
double benchmark_plain_falcon_8keys_fast(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    
    // Pre-allocate aligned memory for better cache performance
    static unsigned char pubkeys[KEY_COUNT][FALCON512_PUBLIC_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    static unsigned char privkeys[KEY_COUNT][FALCON512_PRIVATE_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    
    double start_time = get_time();
    
    for (int iter = 0; iter < iterations; iter++) {
        shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
        shake256_flip(&rng);
        
        // Generate keys in batch for better cache utilization
        for (int i = 0; i < KEY_COUNT; i++) {
            if (falcon_keygen_make(&rng, FALCON_LOGN,
                                 privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                                 pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                                 g_tmp_keygen, sizeof(g_tmp_keygen)) != 0) {
                fprintf(stderr, "Key generation failed at iteration %d, key %d\n", iter, i);
                exit(1);
            }
        }
        
        // Compute key tags in separate loop for better pipeline utilization
        for (int i = 0; i < KEY_COUNT; i++) {
            calculate_key_tag_fast(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE);
        }
    }
    
    double end_time = get_time();
    return end_time - start_time;
}

double benchmark_falcon_merkle_8keys_fast(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    
    // Pre-allocate aligned memory
    static unsigned char pubkeys[KEY_COUNT][FALCON512_PUBLIC_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    static unsigned char privkeys[KEY_COUNT][FALCON512_PRIVATE_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    static unsigned char pubkey_hashes[KEY_COUNT][32] ALIGN_TO_CACHE_LINE;
    
    double start_time = get_time();
    
    for (int iter = 0; iter < iterations; iter++) {
        shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
        shake256_flip(&rng);
        
        // Generate keys
        for (int i = 0; i < KEY_COUNT; i++) {
            if (falcon_keygen_make(&rng, FALCON_LOGN,
                                 privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                                 pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                                 g_tmp_keygen, sizeof(g_tmp_keygen)) != 0) {
                fprintf(stderr, "Key generation failed at iteration %d, key %d\n", iter, i);
                exit(1);
            }
        }
        
        // Hash public keys in batch
        for (int i = 0; i < KEY_COUNT; i++) {
            sha256_hash_fast(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, pubkey_hashes[i]);
        }
        
        // Compute key tags
        for (int i = 0; i < KEY_COUNT; i++) {
            calculate_key_tag_fast(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE);
        }
        
        // Build Merkle tree
        unsigned char root[32];
        unsigned char auth_paths[3][32];
        build_merkle_tree_fast(pubkey_hashes, KEY_COUNT, root, auth_paths, 0);
    }
    
    double end_time = get_time();
    return end_time - start_time;
}

double benchmark_merkle_tree_only_fast(int iterations) {
    shake256_context rng;
    unsigned char seed[48] = {0};
    seed[47] = 0xFF;
    
    // Pre-generate keys and hashes once with aligned memory
    static unsigned char pubkeys[KEY_COUNT][FALCON512_PUBLIC_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    static unsigned char privkeys[KEY_COUNT][FALCON512_PRIVATE_KEY_SIZE] ALIGN_TO_CACHE_LINE;
    static unsigned char pubkey_hashes[KEY_COUNT][32] ALIGN_TO_CACHE_LINE;
    
    shake256_init_prng_from_seed(&rng, seed, sizeof(seed));
    shake256_flip(&rng);
    
    for (int i = 0; i < KEY_COUNT; i++) {
        if (falcon_keygen_make(&rng, FALCON_LOGN,
                             privkeys[i], FALCON512_PRIVATE_KEY_SIZE,
                             pubkeys[i], FALCON512_PUBLIC_KEY_SIZE,
                             g_tmp_keygen, sizeof(g_tmp_keygen)) != 0) {
            fprintf(stderr, "Key generation failed for initial setup\n");
            exit(1);
        }
        sha256_hash_fast(pubkeys[i], FALCON512_PUBLIC_KEY_SIZE, pubkey_hashes[i]);
    }
    
    double start_time = get_time();
    
    for (int iter = 0; iter < iterations; iter++) {
        unsigned char root[32];
        unsigned char auth_paths[3][32];
        build_merkle_tree_fast(pubkey_hashes, KEY_COUNT, root, auth_paths, 0);
    }
    
    double end_time = get_time();
    return end_time - start_time;
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
    
    printf("\nOptimizations Applied:\n");
    printf("- Cache-aligned memory allocations\n");
    printf("- Direct SHA-256 API usage\n");
    printf("- Reduced memory allocations\n");
    printf("- Optimized key tag calculation\n");
    printf("- Improved loop structures\n");
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
    printf("  Authentication path size: %d hashes\n", (int)__builtin_ctz(KEY_COUNT) + 1);
}

void run_benchmarks() {
    const int iterations = 100;
    printf("Optimized Falcon-512 Benchmark (%d Key Rotation Scenario)\n", KEY_COUNT);
    printf("=========================================================\n");
    printf("Configuration:\n");
    printf("- Iterations: %d\n", iterations);
    printf("- Keys per iteration: %d\n", KEY_COUNT);
    printf("- Total keys generated: %d\n\n", iterations * KEY_COUNT);
    
    printf("Benchmarking optimized plain Falcon with %d keys...\n", KEY_COUNT);
    double plain_time = benchmark_plain_falcon_8keys_fast(iterations);
    double plain_per_key = plain_time / (iterations * KEY_COUNT) * 1000;
    
    printf("Benchmarking optimized Falcon with Merkle Tree (%d keys)...\n", KEY_COUNT);
    double merkle_time = benchmark_falcon_merkle_8keys_fast(iterations);
    double merkle_per_key = merkle_time / (iterations * KEY_COUNT) * 1000;

    printf("Benchmarking optimized Merkle Tree construction only (%d keys)...\n", KEY_COUNT);
    double merkle_only_time = benchmark_merkle_tree_only_fast(iterations);
    double merkle_only_per_iter = merkle_only_time / iterations * 1000;
    
    printf("\nOptimized Merkle Tree Construction Only:\n");
    printf("  Total time: %.3f seconds\n", merkle_only_time);
    printf("  Average per tree: %.3f ms\n", merkle_only_per_iter);
    printf("  Trees per second: %.1f\n", iterations / merkle_only_time);
    
    printf("\nOptimized Benchmark Results:\n");
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
    init_global_resources();
    run_benchmarks();
    cleanup_global_resources();
    printf("\nOptimized benchmark completed!\n");
    return 0;
}